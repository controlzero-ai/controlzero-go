package controlzero

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Three states, one client (parity with Python and Node):
//
//	state                          policy source        audit destination
//	---------------------------------------------------------------------
//	no API key + local policy      local (map/file)     local rotated log
//	API key + no local policy      REFUSED to construct (security)
//	API key + local policy         local OVERRIDES with WARN log
//	no API key + no local policy   pass-through with one-time stderr warn
//
// Resolution order for finding a policy:
//  1. WithPolicy / WithPolicyFile option
//  2. CONTROLZERO_POLICY_FILE env var
//  3. ./controlzero.yaml in cwd
//  4. CONTROLZERO_API_KEY env var (refused without local policy)
//  5. nothing => no-op pass-through with one-time stderr warning

// Module-level one-time warning state.
var (
	warnMu               sync.Mutex
	noPolicyWarned       bool
	hybridWarned         bool
	activeSourceNotified bool
)

// resetWarningState is exposed for tests via the test file in this package.
func resetWarningState() {
	warnMu.Lock()
	defer warnMu.Unlock()
	noPolicyWarned = false
	hybridWarned = false
	activeSourceNotified = false
}

// Client is the user-facing entrypoint.
type Client struct {
	apiKey         string
	hasAPIKey      bool
	hasLocalPolicy bool
	evaluator      *PolicyEvaluator
	audit          *LocalAuditLogger
	dlpScanner     *DLPScanner
	bearerSink     *BearerAuditSink
	agentName      string
	policySettings PolicySettings
	// hostedProjectID is the authenticated project_id from the parsed
	// hosted bundle (empty in local mode). gh#175 P1.1: stamped on
	// every audit row as `project_id` so dashboards see the
	// authoritative value, not whatever the caller put in Context.
	hostedProjectID string
	// isHosted reports whether the SDK booted in hosted mode
	// (signed bundle pulled from the control plane). When true, the
	// caller-supplied Context.ProjectID is ALWAYS overwritten by
	// hostedProjectID -- including the case where hostedProjectID is
	// itself empty. Without this an unscoped bundle would let a
	// caller spoof a project_id at the SDK boundary (P1 gap caught
	// in gh#175 outside-voice review).
	isHosted bool
	// policySource is the per-decision provenance enum (migration
	// 048). Captured once at construction so every audit row this
	// client emits stamps the same value. Canonical values:
	//   hosted | local | local-override | cache-fallback | tamper-quarantine
	// cache-fallback / tamper-quarantine are reserved for a future
	// SDK rollout; the backend accepts them without a new migration.
	policySource string
}

// PolicySettings returns the effective settings block (default_action,
// default_on_missing, default_on_tamper, tamper_behavior) that the
// client was constructed with. Useful for `controlzero status` style
// introspection and for tests. Returns the canonical defaults if no
// local policy was configured.
func (c *Client) PolicySettings() PolicySettings { return c.policySettings }

// AgentName returns the agent identity attached to audit events for this
// client. Resolution order: WithAgentName option > CZ_AGENT_NAME env var
// > "default-agent".
func (c *Client) AgentName() string { return c.agentName }

// Option configures a Client at construction time.
type Option func(*clientConfig)

type clientConfig struct {
	apiKey       string
	policy       map[string]any
	policyFile   string
	strictHosted bool
	logPath      string
	logFormat    string
	maxSizeMB    int
	maxBackups   int
	maxAgeDays   int
	compress     bool
	logSet       bool // tracks if user explicitly set any log option
	agentName    string
}

// WithAgentName sets the agent identity attached to audit events. Falls
// back to CZ_AGENT_NAME env var, then to "default-agent".
func WithAgentName(name string) Option {
	return func(c *clientConfig) { c.agentName = name }
}

func WithAPIKey(key string) Option {
	return func(c *clientConfig) { c.apiKey = key }
}

func WithPolicy(policy map[string]any) Option {
	return func(c *clientConfig) { c.policy = policy }
}

func WithPolicyFile(path string) Option {
	return func(c *clientConfig) { c.policyFile = path }
}

func WithStrictHosted() Option {
	return func(c *clientConfig) { c.strictHosted = true }
}

func WithLogPath(path string) Option {
	return func(c *clientConfig) { c.logPath = path; c.logSet = true }
}

func WithLogFormat(format string) Option {
	return func(c *clientConfig) { c.logFormat = format; c.logSet = true }
}

func WithLogRotation(maxSizeMB, maxBackups, maxAgeDays int, compress bool) Option {
	return func(c *clientConfig) {
		c.maxSizeMB = maxSizeMB
		c.maxBackups = maxBackups
		c.maxAgeDays = maxAgeDays
		c.compress = compress
		c.logSet = true
	}
}

// New constructs a Client with the given options. Returns an error rather
// than panicking on invalid configuration.
//
// This is the synchronous entry point. Hosted mode (WithAPIKey with no
// local policy) performs a network fetch of the signed policy bundle
// during construction. Use NewWithContext to pass your own context.
func New(opts ...Option) (*Client, error) {
	return NewWithContext(context.Background(), opts...)
}

// NewWithContext is New with a caller-supplied context. The context
// governs the hosted-mode bootstrap + bundle-pull HTTP calls.
func NewWithContext(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &clientConfig{
		logPath:    "./controlzero.log",
		logFormat:  "json",
		maxAgeDays: 30,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.policy != nil && cfg.policyFile != "" {
		return nil, fmt.Errorf("controlzero: pass either WithPolicy or WithPolicyFile, not both")
	}

	apiKey := cfg.apiKey
	if apiKey == "" {
		apiKey = os.Getenv("CONTROLZERO_API_KEY")
	}
	hasAPIKey := apiKey != ""

	agentName := cfg.agentName
	if agentName == "" {
		agentName = os.Getenv("CZ_AGENT_NAME")
	}
	if agentName == "" {
		agentName = "default-agent"
	}

	// CZ_DEBUG=1 / true / yes / on raises the controlzero logger level.
	// Translated to a process-wide env so other packages in this SDK can
	// pick it up cheaply via os.Getenv.
	switch strings.ToLower(os.Getenv("CZ_DEBUG")) {
	case "1", "true", "yes", "on":
		_ = os.Setenv("CONTROLZERO_DEBUG", "1")
	}

	// T103 precedence (2026-05-12, customer report):
	//   1. Caller-supplied WithPolicy / WithPolicyFile wins
	//      unconditionally; emits a warn when api_key is also present.
	//   2. api_key set => hosted bundle (DEFAULT).
	//   3. CONTROLZERO_LOCAL_OVERRIDE=1 with api_key => local fallback.
	//   4. No api_key => env / cwd local file.
	callerSuppliedLocal := cfg.policy != nil || cfg.policyFile != ""
	localOverride := false
	switch strings.ToLower(os.Getenv("CONTROLZERO_LOCAL_OVERRIDE")) {
	case "1", "true", "yes", "on":
		localOverride = true
	}

	var localSource any
	hasLocal := false
	isPreloadedHosted := false
	hostedProjectIDValue := ""

	if callerSuppliedLocal {
		ls, hl := resolveLocalSource(cfg)
		localSource = ls
		hasLocal = hl
		if hasAPIKey {
			notifyActiveSource("explicit-local", describeLocal(cfg))
		}
	} else if hasAPIKey && !localOverride {
		policyMap, parsed, err := loadHostedPolicy(ctx, apiKey, GetAPIURL())
		if err != nil {
			return nil, err
		}
		localSource = policyMap
		hasLocal = true
		isPreloadedHosted = true
		// gh#175 P1.1: capture the authenticated project_id from
		// the signed bundle so auditDecision can stamp it on every
		// row, defeating caller-side spoofing via Context.ProjectID.
		if parsed != nil {
			if pid, ok := parsed.Payload["project_id"].(string); ok {
				hostedProjectIDValue = pid
			}
		}
		notifyActiveSource("hosted", apiKeyPrefix(apiKey))
	} else {
		// No api_key OR local-override escape hatch.
		ls, hl := resolveLocalSource(cfg)
		localSource = ls
		hasLocal = hl
		if hasLocal {
			mode := "local"
			if localOverride && hasAPIKey {
				mode = "local-override"
			}
			notifyActiveSource(mode, describeLocal(cfg))
		}
	}

	c := &Client{
		apiKey:          apiKey,
		hasAPIKey:       hasAPIKey,
		hasLocalPolicy:  hasLocal,
		agentName:       agentName,
		hostedProjectID: hostedProjectIDValue,
		isHosted:        isPreloadedHosted,
	}

	// Hybrid detection: api_key + caller-supplied local. Skip when the
	// "local" policy came from a hosted pull.
	if hasAPIKey && callerSuppliedLocal && !isPreloadedHosted {
		if err := c.handleHybrid(cfg.strictHosted); err != nil {
			return nil, err
		}
	}

	if hasLocal {
		parsed, err := LoadPolicyFull(localSource)
		if err != nil {
			return nil, err
		}
		c.evaluator = NewPolicyEvaluatorWithSettings(parsed.Rules, parsed.Settings)
		c.policySettings = parsed.Settings

		// Initialize DLP scanner with built-in patterns. If the policy
		// contains a dlp_rules section, load those as custom rules on top.
		if policyMap, ok := localSource.(map[string]any); ok {
			customDLP := LoadDLPRulesFromPolicy(policyMap)
			if len(customDLP) > 0 {
				c.dlpScanner = NewDLPScannerWithRules(customDLP)
			} else {
				c.dlpScanner = NewDLPScanner()
			}
		} else {
			c.dlpScanner = NewDLPScanner()
		}
	} else {
		c.policySettings = DefaultPolicySettings()
	}

	if !hasAPIKey {
		c.audit = NewLocalAuditLogger(LocalAuditOptions{
			LogPath:    cfg.logPath,
			MaxSizeMB:  cfg.maxSizeMB,
			MaxBackups: cfg.maxBackups,
			MaxAgeDays: cfg.maxAgeDays,
			Compress:   cfg.compress,
			Format:     cfg.logFormat,
		})
	} else if cfg.logSet {
		// Hybrid mode: log options are ignored. Warn the user once.
		fmt.Fprintln(os.Stderr,
			"controlzero: log options are ignored when an API key is set "+
				"(audit is managed server-side).")
	}

	// Hosted + hybrid modes: ship audit to the backend via Bearer API key.
	if hasAPIKey {
		c.bearerSink = NewBearerAuditSink(BearerAuditOptions{
			APIURL: GetAPIURL(),
			APIKey: apiKey,
		})
	}

	// Migration 048 (2026-05-19): compute the per-decision provenance
	// enum once at construction. Three SDK paths today; reserved
	// values (cache-fallback / tamper-quarantine) will be wired in a
	// follow-up rollout once their signals reach the audit seam.
	switch {
	case localOverride && hasAPIKey && !callerSuppliedLocal:
		c.policySource = "local-override"
	case hasAPIKey:
		c.policySource = "hosted"
	default:
		c.policySource = "local"
	}

	// T108 (2026-05-12): emit a governance audit event when the
	// CONTROLZERO_LOCAL_OVERRIDE escape hatch bypassed the hosted
	// bundle. Posted to the remote audit sink so ops sees it in the
	// audit dashboard with reason_code=LOCAL_OVERRIDE_ACTIVE.
	// Best-effort: any failure is logged, never crashes.
	if localOverride && hasAPIKey && !callerSuppliedLocal {
		c.emitLocalOverrideAuditEvent(describeLocal(cfg))
	}

	return c, nil
}

// emitLocalOverrideAuditEvent records a single governance audit event
// for the LOCAL_OVERRIDE bypass. Required by T108: every override
// usage must be visible in the audit dashboard so ops can alert /
// correlate. Wire-shape uses the BearerAuditSink envelope with
// reason_code=LOCAL_OVERRIDE_ACTIVE.
func (c *Client) emitLocalOverrideAuditEvent(sourceHint string) {
	entry := map[string]any{
		"tool":      "_lifecycle",
		"method":    "local_override_active",
		"decision":  "audit",
		"policy_id": "<lifecycle>",
		"reason": "CONTROLZERO_LOCAL_OVERRIDE=1 is bypassing the hosted policy " +
			"bundle. Local source: " + sourceHint,
		"reason_code": "LOCAL_OVERRIDE_ACTIVE",
		"mode":        "lifecycle",
		// Migration 048: stamp the same provenance enum on the
		// lifecycle event so downstream filters / banners observe
		// symmetry with the guard decisions that follow under the
		// same override.
		"policy_source": "local-override",
	}
	if c.bearerSink != nil {
		c.bearerSink.Log(entry)
	} else if c.audit != nil {
		// No remote sink available -- still record locally so a
		// debug-bundle export captures the override fact.
		c.audit.Log(entry)
	}
}

// GuardOptions configures a single Guard call.
type GuardOptions struct {
	Args        map[string]any
	Method      string
	RaiseOnDeny bool
	Context     *EvalContext
}

// Guard evaluates a tool call against the loaded policy.
//
// Returns a PolicyDecision and an optional error. The error is non-nil only
// when RaiseOnDeny was true AND the decision is deny: in that case the
// returned error is *PolicyDeniedError.
func (c *Client) Guard(tool string, opts GuardOptions) (PolicyDecision, error) {
	method := opts.Method
	if method == "" {
		method = "*"
	}

	// gh#175 P1.1 audit trail: build the evaluation context with
	// detected client_name + authenticated project_id so the audit
	// row records what the SDK saw. Hosted bundle's project_id always
	// wins; in local mode the caller's value is honoured.
	evalContext := c.buildEvalContext(opts.Context)

	// Quarantine check: if this machine is quarantined due to tamper detection,
	// deny ALL tool calls until recovery. Emits the canonical
	// MACHINE_QUARANTINED reason_code so dashboards can count
	// "tamper-driven denies" separately from policy denies.
	if IsQuarantined(DefaultStateDir()) {
		decision := PolicyDecision{
			Effect: "deny",
			// T79: synthetic policy_id so the audit dashboard renders
			// a recognizable QUARANTINE chip + tooltip linking to the
			// recovery anchor. Mirrors Python + Node SDKs.
			PolicyID: SyntheticPolicyIDQuarantine,
			Reason: "Machine quarantined: policy tampering detected. " +
				"Run 'controlzero enroll' or 'controlzero policy-pull' to recover.",
			ReasonCode:          ReasonCodeMachineQuarantined,
			PolicyEngineVersion: PolicyEngineVersion,
		}
		c.auditDecision(tool, method, opts.Args, decision, evalContext)
		if opts.RaiseOnDeny {
			return decision, &PolicyDeniedError{Decision: decision}
		}
		return decision, nil
	}

	if c.evaluator == nil {
		return c.noopDecision(), nil
	}

	var decision PolicyDecision
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Fail closed on any evaluator panic. NEVER allow on error.
				// T79: tag with synthetic:ENGINE_UNAVAILABLE so the audit
				// dashboard can tell evaluator-crash denies apart from
				// rule-driven denies.
				decision = PolicyDecision{
					Effect:              "deny",
					PolicyID:            SyntheticPolicyIDEngineUnavail,
					Reason:              fmt.Sprintf("Evaluator panic: %v. Failing closed.", r),
					ReasonCode:          ReasonCodeNoRuleMatch,
					PolicyEngineVersion: PolicyEngineVersion,
				}
			}
		}()
		decision = c.evaluator.Evaluate(tool, method, evalContext)
	}()

	// DLP scanning: if the policy allowed the call, scan tool args for
	// sensitive data. If any DLP rule with action="block" matches, override
	// the decision to deny. Detect-only matches are logged but do not block.
	if decision.Allowed() && c.dlpScanner != nil && len(opts.Args) > 0 {
		argsText := ExtractTextFromArgs(opts.Args)
		if argsText != "" {
			dlpMatches := c.dlpScanner.Scan(argsText)
			if HasBlockingMatch(dlpMatches) {
				decision = PolicyDecision{
					Effect:              "deny",
					PolicyID:            decision.PolicyID,
					Reason:              "DLP blocking match found in tool arguments",
					ReasonCode:          ReasonCodeDLPBlocked,
					EvaluatedRules:      decision.EvaluatedRules,
					PolicyEngineVersion: PolicyEngineVersion,
				}
			}
		}
	}

	c.auditDecision(tool, method, opts.Args, decision, evalContext)

	if opts.RaiseOnDeny && decision.Denied() {
		return decision, &PolicyDeniedError{Decision: decision}
	}

	return decision, nil
}

// buildEvalContext is the gh#175 P1.1 per-call context resolver. It
// auto-fills ClientName from detectClientName when the caller didn't
// supply one, and forces ProjectID to the authenticated value from
// the parsed hosted bundle (defeats caller-side spoofing via
// opts.Context.ProjectID). In local mode (no signed bundle) the
// caller's value is honoured.
func (c *Client) buildEvalContext(caller *EvalContext) *EvalContext {
	out := &EvalContext{}
	if caller != nil {
		out.Resource = caller.Resource
		out.Tags = caller.Tags
		out.ClientName = caller.ClientName
		out.ProjectID = caller.ProjectID
	}
	if out.ClientName == "" {
		out.ClientName = detectClientName()
	}
	if c.isHosted {
		// Authoritative source wins -- ALWAYS overwrite when in
		// hosted mode, including when hostedProjectID itself is
		// empty. Without the unconditional overwrite (i.e. if we
		// only overwrote on non-empty hostedProjectID), an
		// un-scoped hosted bundle would let a caller spoof a
		// project_id via Context.ProjectID and bypass a
		// project-scoped deny rule. gh#175 outside-voice P1.
		out.ProjectID = c.hostedProjectID
	}
	return out
}

// Close flushes and closes the local audit log sink.
func (c *Client) Close() error {
	if c.bearerSink != nil {
		_ = c.bearerSink.Close()
		c.bearerSink = nil
	}
	if c.audit != nil {
		err := c.audit.Close()
		c.audit = nil
		return err
	}
	return nil
}

// ---------------- internals ----------------

func resolveLocalSource(cfg *clientConfig) (any, bool) {
	if cfg.policy != nil {
		return cfg.policy, true
	}
	if cfg.policyFile != "" {
		return cfg.policyFile, true
	}
	if envPath := os.Getenv("CONTROLZERO_POLICY_FILE"); envPath != "" {
		return envPath, true
	}
	cwd, _ := os.Getwd()
	// Auto-detect by extension per SDK_LOCAL_LAYOUT (T97). YAML is the
	// default; JSON is accepted for machine-generated workflows.
	for _, name := range []string{"controlzero.yaml", "controlzero.yml", "controlzero.json"} {
		candidate := filepath.Join(cwd, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
	}
	return nil, false
}

func (c *Client) handleHybrid(strict bool) error {
	// Caller passed BOTH WithPolicy/WithPolicyFile AND an api_key. The
	// explicit local arg wins (caller is intentional), but we surface
	// the conflict so it cannot be silent.
	msg := "controlzero: explicit local policy overrides the hosted bundle. " +
		"The dashboard policy is IGNORED for this Client. Audit still ships " +
		"remotely. Unset CONTROLZERO_API_KEY or stop passing WithPolicy/" +
		"WithPolicyFile to silence this warning."

	if strict {
		return fmt.Errorf("%w: %s", ErrHybridMode, msg)
	}

	warnMu.Lock()
	defer warnMu.Unlock()
	if !hybridWarned {
		fmt.Fprintln(os.Stderr, "WARNING: "+msg)
		hybridWarned = true
	}
	return nil
}

// notifyActiveSource emits a single stderr line naming the active policy
// source so customer support can determine instantly which policy is
// enforcing on a given machine. Required by SDK_LOCAL_LAYOUT (T103).
// Suppressed when CONTROLZERO_QUIET=1.
func notifyActiveSource(mode, sourceHint string) {
	warnMu.Lock()
	defer warnMu.Unlock()
	if activeSourceNotified {
		return
	}
	activeSourceNotified = true
	switch strings.ToLower(os.Getenv("CONTROLZERO_QUIET")) {
	case "1", "true", "yes", "on":
		return
	}
	fmt.Fprintf(os.Stderr, "controlzero: active policy source = %s (%s)\n", mode, sourceHint)
}

// apiKeyPrefix returns a sanitised label for stderr / log surfaces. Only
// the public, non-secret prefix (cz_live_ / cz_test_) is revealed. Anything
// past the prefix is customer-secret entropy and must never appear in
// terminals, support transcripts, or CI logs.
func apiKeyPrefix(k string) string {
	if strings.HasPrefix(k, "cz_live_") {
		return "cz_live_***"
	}
	if strings.HasPrefix(k, "cz_test_") {
		return "cz_test_***"
	}
	return "***"
}

// describeLocal returns a printable hint for the local policy source so
// the active-source notification can name the file or inline dict.
func describeLocal(cfg *clientConfig) string {
	if cfg.policy != nil {
		return "<inline policy>"
	}
	if cfg.policyFile != "" {
		return cfg.policyFile
	}
	if envPath := os.Getenv("CONTROLZERO_POLICY_FILE"); envPath != "" {
		return envPath
	}
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, "controlzero.yaml")
}

func (c *Client) noopDecision() PolicyDecision {
	warnMu.Lock()
	if !noPolicyWarned {
		fmt.Fprintln(os.Stderr,
			"WARNING: controlzero: no policy configured, calls are not being checked. "+
				"Use WithPolicy, WithPolicyFile, set CONTROLZERO_POLICY_FILE, "+
				"create ./controlzero.yaml, or set CONTROLZERO_API_KEY.")
		noPolicyWarned = true
	}
	warnMu.Unlock()
	return PolicyDecision{
		Effect:              "allow",
		PolicyID:            "<noop>",
		Reason:              "No policy configured (pass-through)",
		PolicyEngineVersion: PolicyEngineVersion,
	}
}

func (c *Client) auditDecision(tool, method string, args map[string]any, decision PolicyDecision, evalContext *EvalContext) {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Phase 1A (cua rig v2, issue #450): args_hash is a stable
	// SHA-256 over RFC 8785 (JCS) canonical bytes of args. Same input
	// -> identical hash across Python/Node/Go SDKs. Best-effort: on
	// canonicalisation error the field is left empty (older SDK
	// versions on the backend treat missing/empty as legacy).
	argsHashValue := ArgsHash(args)

	// Phase 1B (#451): engine version stamped on every audit row from
	// the canonical constant. Independent of whether the caller
	// populated PolicyDecision.PolicyEngineVersion -- the audit row
	// always reflects which engine bytes are loaded in this SDK.
	engineVersion := decision.PolicyEngineVersion
	if engineVersion == "" {
		engineVersion = PolicyEngineVersion
	}

	// gh#175 P1.1 audit trail: resolve the per-call selector context.
	// The Go enforcer does not yet evaluate selectors so GateMatched
	// is always "none" here, but the three columns exist so the
	// cross-SDK audit shape is invariant.
	clientNameValue := ""
	projectIDValue := ""
	if evalContext != nil {
		clientNameValue = evalContext.ClientName
		projectIDValue = evalContext.ProjectID
	}
	gateMatchedValue := decision.GateMatched
	if gateMatchedValue == "" {
		gateMatchedValue = "none"
	}

	// Migration 048 (2026-05-19): default to the client-cached
	// provenance enum. Empty fallback ('hosted') matches the column
	// DEFAULT on the backend so an in-flight upgrade never lands an
	// invalid value.
	policySourceValue := c.policySource
	if policySourceValue == "" {
		policySourceValue = "hosted"
	}

	entry := map[string]any{
		"decision":              decision.Effect,
		"tool":                  tool,
		"method":                method,
		"policy_id":             decision.PolicyID,
		"reason":                decision.Reason,
		"reason_code":           decision.ReasonCode,
		"surface":               "go-sdk",
		"args_keys":             keys,
		"args_hash":             argsHashValue,
		"policy_engine_version": engineVersion,
		"mode":                  "local",
		// Migration 048: per-decision provenance enum.
		"policy_source": policySourceValue,
		// gh#175 P1.1: see comment above.
		"client_name":  clientNameValue,
		"project_id":   projectIDValue,
		"gate_matched": gateMatchedValue,
	}

	if c.audit != nil {
		c.audit.Log(entry)
	}

	if c.bearerSink != nil {
		hosted := make(map[string]any, len(entry))
		for k, v := range entry {
			hosted[k] = v
		}
		hosted["mode"] = "hosted"
		c.bearerSink.Log(hosted)
	}
}
