package controlzero

import (
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
func New(opts ...Option) (*Client, error) {
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

	// SECURITY: Hosted mode is not implemented in this slim package.
	// If a user sets CONTROLZERO_API_KEY without a local policy, they expect
	// remote dashboard policies to enforce their tool calls. Silently
	// returning "allow" for everything would be a security incident.
	// Refuse to construct, loud and immediate.
	if hasAPIKey && !hasLocal {
		return nil, ErrHostedModeNotImplemented
	}

	c := &Client{
		apiKey:         apiKey,
		hasAPIKey:      hasAPIKey,
		hasLocalPolicy: hasLocal,
	}

	if hasAPIKey && hasLocal {
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

	c.auditDecision(tool, method, opts.Args, decision)

	if opts.RaiseOnDeny && decision.Denied() {
		return decision, &PolicyDeniedError{Decision: decision}
	}

	return decision, nil
}

// Close flushes and closes the local audit log sink.
func (c *Client) Close() error {
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
	if c.audit == nil {
		return
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	c.audit.Log(map[string]any{
		"decision":  decision.Effect,
		"tool":      tool,
		"method":    method,
		"policy_id": decision.PolicyID,
		"reason":    decision.Reason,
		"args_keys": keys,
		"mode":      "local",
	})
}
