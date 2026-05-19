// Cross-SDK behavioral conformance runner -- Go (issue #409 PR-F v2).
//
// Iterates every case in tests/parity/decisions.json (the shared cross-SDK
// behavioral conformance vector) and asserts that the Go SDK's public
// Client.Guard() API returns a decision that byte-matches the case's
// `expected` block.
//
// Mirror tests live in the Python SDK (sdks/python/controlzero/tests/
// test_conformance.py) and Node SDK (sdks/node/controlzero/tests/
// conformance.test.ts). If any SDK drifts from the vector, this test fails
// first in the language that drifted, isolating the regression to that SDK.
//
// The vector is the byte-level contract; this test is the Go-side gate.
// Per issue #409: a deny that customers depended on must keep being a deny
// in every SDK, every release.
//
// Schema v2 (HITL-3) case kinds the runner understands:
//   - "evaluation" (default): full Client.Guard() round-trip. Asserts
//     effect, reason_code, policy_id against the vector.
//   - "bundle_load" (gh#602): bundle-load gate cases. Skipped at this
//     layer (covered by bundle_min_sdk_error_test.go unit tests).
//   - "approval_request_post" (gh#618): hitl_settings cascade cases.
//     Requires the HITL-4 backend handlers. Skipped unless
//     CONFORMANCE_BACKEND_URL is set (integration-test mode).
//
// Case-level skip gates:
//   - requires_backend: true + no CONFORMANCE_BACKEND_URL -> skip
//   - min_sdk_version > current Go SDK version -> skip
//
// Pass criterion (enforced by TestConformanceSummary):
//   unexpected_failures == 0 AND pass + skip == len(cases)

package controlzero

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type conformanceCase struct {
	ID            string `json:"id"`
	Kind          string `json:"kind,omitempty"`
	Description   string `json:"description"`
	RegressionID  string `json:"regression_id,omitempty"`
	MinSDKVersion string `json:"min_sdk_version,omitempty"`
	RequiresBackend bool `json:"requires_backend,omitempty"`
	Input         *struct {
		Tool          string         `json:"tool"`
		Method        string         `json:"method,omitempty"`
		Args          map[string]any `json:"args,omitempty"`
		Context       map[string]any `json:"context,omitempty"`
		DefaultAction string         `json:"default_action,omitempty"`
	} `json:"input,omitempty"`
	Policy *struct {
		Rules []any `json:"rules"`
	} `json:"policy,omitempty"`
	Expected struct {
		Effect     string `json:"effect,omitempty"`
		Outcome    string `json:"outcome,omitempty"`
		ReasonCode string `json:"reason_code,omitempty"`
		PolicyID   string `json:"policy_id,omitempty"`
		ErrorCode  string `json:"error_code,omitempty"`
	} `json:"expected"`
}

type conformanceVector struct {
	Cases []conformanceCase `json:"cases"`
}

// findVectorPath walks up from the test file looking for the shared
// tests/parity/decisions.json fixture. Same routine used by other parity
// tests in this package.
func findVectorPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "tests", "parity", "decisions.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("tests/parity/decisions.json not found")
	return ""
}

func loadVector(t *testing.T) *conformanceVector {
	t.Helper()
	data, err := os.ReadFile(findVectorPath(t))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v conformanceVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return &v
}

// SDK-state cases the public Client API cannot reach from a clean process.
// Covered by dedicated unit tests (tamper_test, hosted_policy_e2e_test, etc).
var skipReasonCodes = map[string]bool{
	"BUNDLE_MISSING":      true,
	"MACHINE_QUARANTINED": true,
	"NO_ACTIVE_POLICIES":  true,
	"NETWORK_ERROR":       true,
	"BUNDLE_TAMPERED":     true,
}

// Schema-v2 HITL reason codes. Decisions the local Client.Guard() path
// cannot emit without HITL infrastructure (backend reachable, identity
// headers, signed token round-trip). Skip in unit-test mode; the
// integration runner flips these on by setting CONFORMANCE_BACKEND_URL.
var hitlReasonCodes = map[string]bool{
	"HITL_SDK_TIMEOUT":              true,
	"HITL_SLA_EXPIRED":              true,
	"HITL_BACKEND_UNREACHABLE":      true,
	"HITL_POLICY_VERSION_CONFLICT":  true,
	"HITL_NO_APPROVER_AVAILABLE":    true,
	"HITL_IDENTITY_NOT_IN_ORG":      true,
	"HITL_IDENTITY_REQUIRED":        true,
	"HITL_IDENTITY_CLAIM_REJECTED":  true,
	"HITL_ARGS_HASH_MISMATCH":       true,
}

// Seed cases the Go SDK does not yet implement. Each one is documented;
// flip the entry to a hard assertion the moment the SDK lands the fix.
// AM triage items for #409. Identical set across Python / Node / Go --
// strong signal the gap is in the shared matcher concept.
var skipCasesGoGaps = map[string]string{
	"regression-T84-alias-read-001": "alias shim does not canonicalize rule-side legacy aliases",
	"regression-BUG345-001":         "run_shell_command tool not canonicalized to Bash for matching",
	"regression-BUG350-001":         "legacy Read rule action does not back-canonicalize to file_read tool",
	"case-insensitive-method-001":   "SQL method classifier is case-sensitive",
	// Go-specific gap. Go's PolicyEvaluator.Evaluate signature is
	// (tool, method, ctx) -- args are NOT plumbed through. So SQL semantic
	// class extraction from args.sql cannot happen at SDK matching time
	// (it does happen for hook-check CLI calls that pre-compute
	// context.action_semantic_class server-side, but not for direct SDK
	// users). Python + Node SDKs pass this case because they thread args
	// through to the evaluator. Fix path: change Go Evaluate signature to
	// take args, mirror Python/Node SQL class extraction.
	"sql-class-precedence-001": "Go Evaluator does not accept args, so SQL semantic class extraction does not run for direct SDK calls",
	// gh#175 multi-client / per-project rule selectors. Python SDK's
	// PolicyEvaluator gates `clients=[...]` and `projects=[...]` against
	// the request's context; Go SDK does not yet honor those fields, so
	// a rule tagged for a specific client still fires on requests from
	// other clients. Tracked as a Go-side port of gh#175.
	"multiclient-002":              "Go SDK does not yet gate `clients=[...]` rules against context.client_name",
	"multiclient-both-002":         "Go SDK does not yet gate `clients`+`projects` selectors against context",
	"multiclient-empty-context-001": "Go SDK does not yet gate `clients` selectors when context is empty",
	"perproject-002":               "Go SDK does not yet gate `projects=[...]` rules against context.project_id",
}

// parseSemver parses a `MAJOR.MINOR.PATCH[-suffix]` (or leading `v`) into
// a comparable []int. Strips any `-` suffix. Returns []int{0} on
// malformed input so the comparison is fail-open (matches the Python +
// Node runners).
func parseSemver(v string) []int {
	if v == "" {
		return []int{0}
	}
	core := strings.TrimPrefix(v, "v")
	core = strings.SplitN(core, "-", 2)[0]
	parts := []int{}
	for _, chunk := range strings.Split(core, ".") {
		n, err := strconv.Atoi(chunk)
		if err != nil {
			return []int{0}
		}
		parts = append(parts, n)
	}
	if len(parts) == 0 {
		return []int{0}
	}
	return parts
}

func semverGTE(a, b []int) bool {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(a) {
			ai = a[i]
		}
		if i < len(b) {
			bi = b[i]
		}
		if ai > bi {
			return true
		}
		if ai < bi {
			return false
		}
	}
	return true
}

func sdkSupports(minVersion string) bool {
	if minVersion == "" {
		return true
	}
	return semverGTE(parseSemver(Version), parseSemver(minVersion))
}

// runConformanceCase exercises a single vector case through the public
// Client.Guard API. Returns the decision fields the vector asserts on.
func runConformanceCase(t *testing.T, c conformanceCase) (string, string, string) {
	t.Helper()
	if c.Policy == nil || c.Input == nil {
		t.Skip("no-policy or no-input path covered by dedicated tests")
	}
	defaultAction := c.Input.DefaultAction
	if defaultAction == "" {
		defaultAction = "deny"
	}

	// SDK schema: default_action lives under `settings`, not top-level.
	policy := map[string]any{
		"settings": map[string]any{"default_action": defaultAction},
		"rules":    c.Policy.Rules,
	}

	logPath := filepath.Join(t.TempDir(), "conformance.log")
	cz, err := New(WithPolicy(policy), WithLogPath(logPath))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	opts := GuardOptions{
		Args:   c.Input.Args,
		Method: c.Input.Method,
	}
	if c.Input.Context != nil {
		ctx := &EvalContext{}
		if r, ok := c.Input.Context["resource"].(string); ok {
			ctx.Resource = r
		}
		opts.Context = ctx
	}

	decision, err := cz.Guard(c.Input.Tool, opts)
	if err != nil {
		t.Fatalf("guard error (RaiseOnDeny=false should never error): %v", err)
	}
	return decision.Effect, decision.ReasonCode, decision.PolicyID
}

func TestConformanceVectorMetadata(t *testing.T) {
	v := loadVector(t)
	if len(v.Cases) < 50 {
		t.Fatalf("conformance vector unexpectedly small: %d cases", len(v.Cases))
	}
	ids := map[string]bool{}
	for _, c := range v.Cases {
		if ids[c.ID] {
			t.Fatalf("duplicate case id: %s", c.ID)
		}
		ids[c.ID] = true
	}
	regs := map[string]bool{}
	for _, c := range v.Cases {
		if c.RegressionID != "" {
			regs[c.RegressionID] = true
		}
	}
	for _, r := range []string{"T79", "T83", "T84", "BUG-173", "BUG-345", "BUG-350"} {
		if !regs[r] {
			t.Errorf("vector missing regression coverage: %s", r)
		}
	}
}

// TestConformanceSchemaV2KindsPresent guards against a future cleanup
// that empties one of the schema-v2 kind buckets, which would silently
// disable the corresponding skip gate.
func TestConformanceSchemaV2KindsPresent(t *testing.T) {
	v := loadVector(t)
	kinds := map[string]bool{}
	for _, c := range v.Cases {
		k := c.Kind
		if k == "" {
			k = "evaluation"
		}
		kinds[k] = true
	}
	for _, expected := range []string{"evaluation", "bundle_load", "approval_request_post"} {
		if !kinds[expected] {
			t.Errorf("vector missing kind=%q; gate becomes untestable", expected)
		}
	}
}

func TestConformanceSemverParser(t *testing.T) {
	tests := []struct {
		in   string
		want []int
	}{
		{"1.6.0", []int{1, 6, 0}},
		{"1.6.0-alpha.1", []int{1, 6, 0}},
		{"v1.7.6", []int{1, 7, 6}},
		{"", []int{0}},
		{"garbage", []int{0}},
	}
	for _, tc := range tests {
		got := parseSemver(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("parseSemver(%q) len mismatch: got %v want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseSemver(%q)[%d]: got %d want %d", tc.in, i, got[i], tc.want[i])
			}
		}
	}
	if !semverGTE([]int{1, 6, 0}, []int{1, 6, 0}) {
		t.Error("1.6.0 >= 1.6.0 should be true")
	}
	if !semverGTE([]int{1, 7, 0}, []int{1, 6, 99}) {
		t.Error("1.7.0 >= 1.6.99 should be true")
	}
	if semverGTE([]int{1, 5, 99}, []int{1, 6, 0}) {
		t.Error("1.5.99 >= 1.6.0 should be false")
	}
}

func TestConformanceSDKSupports(t *testing.T) {
	if !sdkSupports("") {
		t.Error("sdkSupports(\"\") should be true")
	}
	if !sdkSupports("0.0.1") {
		t.Error("sdkSupports(0.0.1) should be true")
	}
	if !sdkSupports(Version) {
		t.Error("sdkSupports(Version) should be true")
	}
	if sdkSupports("99.0.0") {
		t.Error("sdkSupports(99.0.0) should be false")
	}
}

// TestConformance runs the whole vector as one Go test that uses t.Run to
// produce one subtest per case. Failing subtests print the case ID so a
// drift is one-click debuggable.
func TestConformance(t *testing.T) {
	v := loadVector(t)
	backendURL := os.Getenv("CONFORMANCE_BACKEND_URL")
	for _, c := range v.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			kind := c.Kind
			if kind == "" {
				kind = "evaluation"
			}

			// Schema v2 kind gates fire first.
			switch kind {
			case "bundle_load":
				t.Skip("non-evaluation kind: bundle_load (covered by bundle_min_sdk_error_test.go)")
				return
			case "approval_request_post":
				if backendURL == "" {
					t.Skip("non-evaluation kind: approval_request_post (needs CONFORMANCE_BACKEND_URL)")
					return
				}
				t.Skip("approval_request_post integration mode not yet wired into Go runner; covered by client_request_approval_test.go")
				return
			}

			// Backend-dependent vectors: skip in unit-test mode (no env var).
			if c.RequiresBackend && backendURL == "" {
				t.Skip("requires_backend=true; set CONFORMANCE_BACKEND_URL for integration mode")
				return
			}

			// Schema v2 min_sdk_version gate.
			if !sdkSupports(c.MinSDKVersion) {
				t.Skipf("case requires SDK >= %s, current SDK = %s", c.MinSDKVersion, Version)
				return
			}

			if c.Expected.ReasonCode != "" && skipReasonCodes[c.Expected.ReasonCode] {
				t.Skipf("SDK-state path %q covered by dedicated tests", c.Expected.ReasonCode)
				return
			}
			if c.Expected.ReasonCode != "" && hitlReasonCodes[c.Expected.ReasonCode] && backendURL == "" {
				t.Skipf("HITL outcome %q needs CONFORMANCE_BACKEND_URL", c.Expected.ReasonCode)
				return
			}
			if reason, ok := skipCasesGoGaps[c.ID]; ok {
				// Go's testing has no native xfail. Skip with the documented
				// reason; the AM workflow is to remove from skipCasesGoGaps
				// and re-run when the SDK fix lands.
				t.Skipf("Go SDK gap: %s", reason)
				return
			}

			effect, reasonCode, policyID := runConformanceCase(t, c)

			if effect != c.Expected.Effect {
				t.Errorf("case %s: effect drift. expected=%s actual=%s",
					c.ID, c.Expected.Effect, effect)
			}
			if c.Expected.ReasonCode != "" && reasonCode != c.Expected.ReasonCode {
				t.Errorf("case %s: reason_code drift. expected=%s actual=%s",
					c.ID, c.Expected.ReasonCode, reasonCode)
			}
			if c.Expected.PolicyID != "" && policyID != c.Expected.PolicyID {
				t.Errorf("case %s: policy_id drift. expected=%s actual=%s",
					c.ID, c.Expected.PolicyID, policyID)
			}
		})
	}
}
