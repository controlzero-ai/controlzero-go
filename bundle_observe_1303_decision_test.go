package controlzero_test

import (
	"testing"

	"controlzero.ai/sdk/go"
	"controlzero.ai/sdk/go/internal/bundle"
)

// End-to-end #1247 + #1303 decision parity for the hosted path:
// bundle.TranslateToLocalPolicy -> LoadPolicyFull -> PolicyEvaluator.
//
// This mirrors the Python test_part3_active_policy_count_1303.py `_decide`
// helper (translate -> load_policy -> evaluate) so the verdict a real
// caller gets is asserted, not just the translator's intermediate map. It
// proves the synthetic OBSERVE_MODE_NO_POLICY / NO_ACTIVE_POLICIES /
// BUNDLE_MISSING rules round-trip through LoadPolicy and reach the
// evaluator with their effect + reason_code intact.
//
// Fails-if-reverted: removing the empty-vs-degraded discriminator turns
// the degraded cases from deny back into allow (the rm-rf fail-open,
// #1303); removing the observe posture turns the genuine-empty case from
// allow back into the old hard-coded deny (regressing #1247).

func decide1303(t *testing.T, payload map[string]any) controlzero.PolicyDecision {
	t.Helper()
	local := bundle.TranslateToLocalPolicy(payload)
	parsed, err := controlzero.LoadPolicyFull(local)
	if err != nil {
		t.Fatalf("LoadPolicyFull: %v", err)
	}
	ev := controlzero.NewPolicyEvaluatorWithSettings(parsed.Rules, parsed.Settings)
	return ev.Evaluate("Bash", "rm", nil)
}

func meta1303(count any) map[string]any {
	return map[string]any{"metadata": map[string]any{"active_policy_count": count}}
}

func merge1303(parts ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, p := range parts {
		for k, v := range p {
			out[k] = v
		}
	}
	return out
}

func TestDecide1303_CountZeroEmptyObserves(t *testing.T) {
	d := decide1303(t, merge1303(map[string]any{"policies": []any{}}, meta1303(0.0)))
	if d.Effect != "allow" {
		t.Errorf("effect = %q, want allow (observe)", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeObserveModeNoPolicy {
		t.Errorf("reason_code = %q, want OBSERVE_MODE_NO_POLICY", d.ReasonCode)
	}
}

func TestDecide1303_CountZeroMissingPoliciesKeyDenies(t *testing.T) {
	d := decide1303(t, meta1303(0.0))
	if d.Effect != "deny" {
		t.Errorf("count==0 + no policies key must deny; effect = %q", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeBundleMissing {
		t.Errorf("reason_code = %q, want BUNDLE_MISSING", d.ReasonCode)
	}
}

func TestDecide1303_CountZeroNonArrayPoliciesDenies(t *testing.T) {
	d := decide1303(t, merge1303(map[string]any{"policies": "not-a-list"}, meta1303(0.0)))
	if d.Effect != "deny" {
		t.Errorf("count==0 + non-array policies must deny; effect = %q", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeBundleMissing {
		t.Errorf("reason_code = %q, want BUNDLE_MISSING", d.ReasonCode)
	}
}

func TestDecide1303_CountPositiveEmptyDenies(t *testing.T) {
	// Stripped bundle: ships [] but project has attachments -> fail closed.
	d := decide1303(t, merge1303(map[string]any{"policies": []any{}}, meta1303(3.0)))
	if d.Effect != "deny" {
		t.Errorf("stripped bundle must deny; effect = %q", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeBundleMissing {
		t.Errorf("reason_code = %q, want BUNDLE_MISSING", d.ReasonCode)
	}
}

func TestDecide1303_CountAbsentEmptyObserves(t *testing.T) {
	d := decide1303(t, map[string]any{"policies": []any{}})
	if d.Effect != "allow" {
		t.Errorf("effect = %q, want allow (observe)", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeObserveModeNoPolicy {
		t.Errorf("reason_code = %q, want OBSERVE_MODE_NO_POLICY", d.ReasonCode)
	}
}

func TestDecide1303_CountAbsentDegradedDenies(t *testing.T) {
	payload := map[string]any{
		"policies": []any{map[string]any{"id": "p", "rules": []any{}}},
	}
	d := decide1303(t, payload)
	if d.Effect != "deny" {
		t.Errorf("degraded (no count) must deny; effect = %q", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeBundleMissing {
		t.Errorf("reason_code = %q, want BUNDLE_MISSING", d.ReasonCode)
	}
}

func TestDecide1303_MalformedCountFallsBackToObserve(t *testing.T) {
	d := decide1303(t, merge1303(map[string]any{"policies": []any{}}, meta1303("0")))
	if d.Effect != "allow" {
		t.Errorf("malformed count + explicit [] -> observe allow; effect = %q", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeObserveModeNoPolicy {
		t.Errorf("reason_code = %q, want OBSERVE_MODE_NO_POLICY", d.ReasonCode)
	}
}

func TestDecide1303_DefaultOnEmptyDenyOverridesObserve(t *testing.T) {
	payload := merge1303(
		map[string]any{"policies": []any{}, "default_on_empty": "deny"},
		meta1303(0.0),
	)
	d := decide1303(t, payload)
	if d.Effect != "deny" {
		t.Errorf("default_on_empty=deny must deny; effect = %q", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeNoActivePolicies {
		t.Errorf("reason_code = %q, want NO_ACTIVE_POLICIES", d.ReasonCode)
	}
}

func TestDecide1303_RealDenyRuleStillFires(t *testing.T) {
	payload := merge1303(map[string]any{
		"policies": []any{
			map[string]any{
				"id":    "p",
				"rules": []any{map[string]any{"effect": "deny", "actions": []any{"Bash:rm"}}},
			},
		},
	}, meta1303(1.0))
	d := decide1303(t, payload)
	if d.Effect != "deny" {
		t.Errorf("real deny rule must fire; effect = %q", d.Effect)
	}
}
