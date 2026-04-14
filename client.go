package controlzero

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	warnMu          sync.Mutex
	noPolicyWarned  bool
	hybridWarned    bool
)

// resetWarningState is exposed for tests via the test file in this package.
func resetWarningState() {
	warnMu.Lock()
	defer warnMu.Unlock()
	noPolicyWarned = false
	hybridWarned = false
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
}

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

	localSource, hasLocal := resolveLocalSource(cfg)

	// Hosted mode: API key set, no local policy. Pull the signed bundle
	// from the dashboard, verify + decrypt, and use the result as the
	// local policy. Fail closed on any error.
	isPreloadedHosted := false
	if hasAPIKey && !hasLocal {
		policyMap, _, err := loadHostedPolicy(ctx, apiKey, GetAPIURL())
		if err != nil {
			return nil, err
		}
		localSource = policyMap
		hasLocal = true
		isPreloadedHosted = true
	}

	c := &Client{
		apiKey:         apiKey,
		hasAPIKey:      hasAPIKey,
		hasLocalPolicy: hasLocal,
	}

	// Hybrid detection: API key + explicitly-supplied local policy. Skip
	// when the "local" policy came from a hosted pull.
	if hasAPIKey && hasLocal && !isPreloadedHosted {
		if err := c.handleHybrid(cfg.strictHosted); err != nil {
			return nil, err
		}
	}

	if hasLocal {
		rules, err := LoadPolicy(localSource)
		if err != nil {
			return nil, err
		}
		c.evaluator = NewPolicyEvaluator(rules)

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

	return c, nil
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

	// Quarantine check: if this machine is quarantined due to tamper detection,
	// deny ALL tool calls until recovery.
	if IsQuarantined(DefaultStateDir()) {
		decision := PolicyDecision{
			Effect: "deny",
			Reason: "Machine quarantined: policy tampering detected. " +
				"Run 'controlzero enroll' or 'controlzero policy-pull' to recover.",
		}
		c.auditDecision(tool, method, opts.Args, decision)
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
				decision = PolicyDecision{
					Effect: "deny",
					Reason: fmt.Sprintf("Evaluator panic: %v. Failing closed.", r),
				}
			}
		}()
		decision = c.evaluator.Evaluate(tool, method, opts.Context)
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
					Effect:         "deny",
					PolicyID:       decision.PolicyID,
					Reason:         "DLP blocking match found in tool arguments",
					EvaluatedRules: decision.EvaluatedRules,
				}
			}
		}
	}

	c.auditDecision(tool, method, opts.Args, decision)

	if opts.RaiseOnDeny && decision.Denied() {
		return decision, &PolicyDeniedError{Decision: decision}
	}

	return decision, nil
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
	defaultFile := filepath.Join(cwd, "controlzero.yaml")
	if _, err := os.Stat(defaultFile); err == nil {
		return defaultFile, true
	}
	return nil, false
}

func (c *Client) handleHybrid(strict bool) error {
	msg := "controlzero: manual policy override detected. " +
		"An API key is set AND a local policy was provided; the local policy " +
		"will be used and the dashboard policy will be IGNORED for this client " +
		"instance. Audit will still ship to the remote dashboard. " +
		"If this is unintentional, remove the local policy or unset CONTROLZERO_API_KEY."

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
		Effect:   "allow",
		PolicyID: "<noop>",
		Reason:   "No policy configured (pass-through)",
	}
}

func (c *Client) auditDecision(tool, method string, args map[string]any, decision PolicyDecision) {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	entry := map[string]any{
		"decision":  decision.Effect,
		"tool":      tool,
		"method":    method,
		"policy_id": decision.PolicyID,
		"reason":    decision.Reason,
		"args_keys": keys,
		"mode":      "local",
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
