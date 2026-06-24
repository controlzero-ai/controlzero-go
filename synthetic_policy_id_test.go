package controlzero

import (
	"strings"
	"testing"

	"controlzero.ai/sdk/go/internal/bundle"
)

// Note: this test file is part of the `controlzero` package
// (internal-style tests so it can reference unexported helpers if
// needed). The bundle subpackage at `controlzero.ai/sdk/go/internal/bundle`
// is imported for its TranslateToLocalPolicy function -- the path
// matches go.mod's module declaration.

// Tests for the synthetic:* policy_id sentinels (T79).
//
// These tests pin the contract that the audit dashboard relies on
// to distinguish four very different bug classes (stale bundle,
// missing resource gate, vocabulary mismatch, genuine no-match)
// that all previously rendered identically as Decision=Deny,
// PolicyID="", reason_code=NO_RULE_MATCH.

func TestSyntheticPolicyIDConstants_HaveCanonicalPrefix(t *testing.T) {
	cases := []string{
		SyntheticPolicyIDNoRuleMatch,
		SyntheticPolicyIDNoActive,
		SyntheticPolicyIDBundleMiss,
		SyntheticPolicyIDResGateSkip,
		SyntheticPolicyIDQuarantine,
		SyntheticPolicyIDEngineUnavail,
		SyntheticPolicyIDUnattributedDeny,
	}
	for _, c := range cases {
		if !strings.HasPrefix(c, SyntheticPolicyIDPrefix) {
			t.Errorf("synthetic id %q missing prefix %q", c, SyntheticPolicyIDPrefix)
		}
	}
}

func TestSyntheticPolicyIDConstants_ExactValues(t *testing.T) {
	// Renames are a hard wire-format break across SDKs + frontend.
	want := map[string]string{
		"prefix":             "synthetic:",
		"no_rule_match":      "synthetic:NO_RULE_MATCH",
		"no_active":          "synthetic:NO_ACTIVE_POLICIES",
		"observe_no_policy":  "synthetic:OBSERVE_MODE_NO_POLICY",
		"bundle_missing":     "synthetic:BUNDLE_MISSING",
		"resource_gate_skip": "synthetic:RESOURCE_GATE_SKIP",
		"quarantine":         "synthetic:QUARANTINE",
		"engine_unavail":     "synthetic:ENGINE_UNAVAILABLE",
		"unattributed_deny":  "synthetic:UNATTRIBUTED_DENY",
	}
	got := map[string]string{
		"prefix":             SyntheticPolicyIDPrefix,
		"no_rule_match":      SyntheticPolicyIDNoRuleMatch,
		"no_active":          SyntheticPolicyIDNoActive,
		"observe_no_policy":  SyntheticPolicyIDObserveNoPol,
		"bundle_missing":     SyntheticPolicyIDBundleMiss,
		"resource_gate_skip": SyntheticPolicyIDResGateSkip,
		"quarantine":         SyntheticPolicyIDQuarantine,
		"engine_unavail":     SyntheticPolicyIDEngineUnavail,
		"unattributed_deny":  SyntheticPolicyIDUnattributedDeny,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: want %q, got %q", k, v, got[k])
		}
	}
}

func TestSyntheticPolicyIDs_SetHasExactlyEightMembers(t *testing.T) {
	// Bumped to eight when synthetic:UNATTRIBUTED_DENY was added (#1472):
	// the backend stamps it on a deny with an empty policy_id; SDKs
	// recognize it for cross-surface lockstep.
	if len(ValidSyntheticPolicyIDs) != 8 {
		t.Errorf("ValidSyntheticPolicyIDs size = %d, want 8", len(ValidSyntheticPolicyIDs))
	}
	for k := range ValidSyntheticPolicyIDs {
		if !strings.HasPrefix(k, SyntheticPolicyIDPrefix) {
			t.Errorf("ValidSyntheticPolicyIDs entry %q missing prefix", k)
		}
	}
}

// ---- evaluator no-match path -------------------------------------------

func TestEvaluator_NoRuleMatch_StampsSyntheticNoRuleMatch(t *testing.T) {
	rules := []PolicyRule{
		{
			ID:      "r1",
			Name:    "r1",
			Effect:  "allow",
			Actions: []string{"safe_tool:*"},
			Reason:  "ok",
		},
	}
	ev := NewPolicyEvaluator(rules)
	decision := ev.Evaluate("other_tool", "*", nil)
	if decision.Effect != "deny" {
		t.Fatalf("want deny, got %s", decision.Effect)
	}
	if decision.PolicyID != SyntheticPolicyIDNoRuleMatch {
		t.Errorf("PolicyID = %q, want %q", decision.PolicyID, SyntheticPolicyIDNoRuleMatch)
	}
	if decision.ReasonCode != ReasonCodeNoRuleMatch {
		t.Errorf("ReasonCode = %q, want %q", decision.ReasonCode, ReasonCodeNoRuleMatch)
	}
}

func TestEvaluator_ResourceGateSkip_StampsSyntheticResGateSkip(t *testing.T) {
	// T83-class signature: rule's Actions matched but Resources gate
	// excluded the call. Audit chip MUST reflect this for ops to
	// chase the right bug class.
	rules := []PolicyRule{
		{
			ID:        "safe-only",
			Name:      "safe-only",
			Effect:    "allow",
			Actions:   []string{"delete_file:*"},
			Resources: []string{"/safe/*"},
			Reason:    "only safe",
		},
	}
	ev := NewPolicyEvaluator(rules)
	decision := ev.Evaluate("delete_file", "*", &EvalContext{Resource: "/unsafe/x"})
	if decision.Effect != "deny" {
		t.Fatalf("want deny, got %s", decision.Effect)
	}
	if decision.PolicyID != SyntheticPolicyIDResGateSkip {
		t.Errorf("PolicyID = %q, want %q", decision.PolicyID, SyntheticPolicyIDResGateSkip)
	}
}

func TestEvaluator_NoActionMatch_DoesNotStampResGateSkip(t *testing.T) {
	// If NO rule's actions matched the call at all, the deny is
	// NO_RULE_MATCH, not RESOURCE_GATE_SKIP.
	rules := []PolicyRule{
		{
			ID:        "r",
			Name:      "r",
			Effect:    "allow",
			Actions:   []string{"totally_different_tool:*"},
			Resources: []string{"/safe/*"},
			Reason:    "ok",
		},
	}
	ev := NewPolicyEvaluator(rules)
	decision := ev.Evaluate("delete_file", "*", &EvalContext{Resource: "/unsafe/x"})
	if decision.PolicyID != SyntheticPolicyIDNoRuleMatch {
		t.Errorf("PolicyID = %q, want %q", decision.PolicyID, SyntheticPolicyIDNoRuleMatch)
	}
}

func TestEvaluator_UserRuleMatch_DoesNotStampSynthetic(t *testing.T) {
	// User-authored rule denies must keep their native PolicyID.
	rules := []PolicyRule{
		{
			ID:      "p_01HXY",
			Name:    "block-bash",
			Effect:  "deny",
			Actions: []string{"Bash:*"},
			Reason:  "no shell",
		},
	}
	ev := NewPolicyEvaluator(rules)
	decision := ev.Evaluate("Bash", "*", nil)
	if decision.Effect != "deny" {
		t.Fatalf("want deny, got %s", decision.Effect)
	}
	if decision.PolicyID != "p_01HXY" {
		t.Errorf("PolicyID = %q, want p_01HXY", decision.PolicyID)
	}
	if strings.HasPrefix(decision.PolicyID, SyntheticPolicyIDPrefix) {
		t.Errorf("user-rule deny must NOT carry synthetic prefix, got %q", decision.PolicyID)
	}
}

// ---- empty bundle (OBSERVE_MODE_NO_POLICY, #1247 parity) ----------------
//
// #69: a genuinely-empty bundle (explicit `policies: []`, no default_on_empty)
// now resolves to the canonical OBSERVE posture (allow + a loud
// OBSERVE_MODE_NO_POLICY signal), matching Python/Node -- NOT the old
// hard-coded NO_ACTIVE_POLICIES deny. The degraded cases (missing/non-array
// policies, count>0+empty) fail closed via BUNDLE_MISSING; those are covered
// in bundle_observe_1303_decision_test.go.

func TestEmptyBundle_TranslatorEmitsSyntheticID(t *testing.T) {
	local := bundle.TranslateToLocalPolicy(map[string]any{
		"policies": []any{},
	})
	rules, ok := local["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("expected 1 synthetic rule, got %v", local["rules"])
	}
	rule := rules[0].(map[string]any)
	if rule["id"] != "synthetic:OBSERVE_MODE_NO_POLICY" {
		t.Errorf("rule.id = %v, want synthetic:OBSERVE_MODE_NO_POLICY", rule["id"])
	}
	if rule["reason_code"] != "OBSERVE_MODE_NO_POLICY" {
		t.Errorf("rule.reason_code = %v, want OBSERVE_MODE_NO_POLICY", rule["reason_code"])
	}
	if rule["effect"] != "allow" {
		t.Errorf("rule.effect = %v, want allow (observe)", rule["effect"])
	}
}

func TestEmptyBundle_RoundtripCarriesSyntheticID(t *testing.T) {
	local := bundle.TranslateToLocalPolicy(map[string]any{
		"policies": []any{},
	})
	rules, err := LoadPolicy(local)
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}
	ev := NewPolicyEvaluator(rules)
	decision := ev.Evaluate("anything", "*", nil)
	if decision.Effect != "allow" {
		t.Fatalf("want allow (observe), got %s", decision.Effect)
	}
	if decision.PolicyID != SyntheticPolicyIDObserveNoPol {
		t.Errorf("PolicyID = %q, want %q", decision.PolicyID, SyntheticPolicyIDObserveNoPol)
	}
	if decision.ReasonCode != ReasonCodeObserveModeNoPolicy {
		t.Errorf("ReasonCode = %q, want %q", decision.ReasonCode, ReasonCodeObserveModeNoPolicy)
	}
}
