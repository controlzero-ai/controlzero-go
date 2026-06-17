package bundle

import "testing"

// #1303 cross-surface parity (parity-audit CRITICAL): an UNRECOGNIZED, future,
// or empty rule effect on a validly-signed rule must fail CLOSED -> deny, never
// allow. Python (_translate_rule `else "deny"`) and Node (`effect = 'deny'`)
// both deny; Go used to coerce to "allow" (bundle.go translateRule), which made
// an unknown rule allow-*-for-its-pattern -- the exact #1303 fail-open and the
// single surface that still had it. Reverting translateRule's coercion back to
// "allow" reopens the cross-surface fail-open and fails this test.
func TestTranslateRule_UnknownEffectFailsClosedToDeny(t *testing.T) {
	for _, eff := range []string{"bogus", "permit", "AUDIT_AND_ALLOW", "", "Allow", "DENY"} {
		local := TranslateToLocalPolicy(map[string]any{
			"policies": []any{
				map[string]any{
					"id":    "p1",
					"rules": []any{map[string]any{"effect": eff, "actions": []any{"Bash:*"}}},
				},
			},
			// count > 0 so this is NOT the genuine-empty path -- a real attached
			// rule that simply has an unrecognized effect.
			"metadata": map[string]any{"active_policy_count": 1},
		})
		rules, ok := local["rules"].([]any)
		if !ok || len(rules) == 0 {
			t.Fatalf("effect=%q: no rules produced: %v", eff, local["rules"])
		}
		for _, r := range rules {
			m, _ := r.(map[string]any)
			if m["effect"] == "allow" || m["effect"] == "warn" || m["effect"] == "audit" {
				t.Fatalf("effect=%q coerced to %q (fail-OPEN); an unknown effect must deny", eff, m["effect"])
			}
		}
		// The Bash:* rule must be present as a deny.
		sawDeny := false
		for _, r := range rules {
			m, _ := r.(map[string]any)
			if m["effect"] == "deny" {
				sawDeny = true
			}
		}
		if !sawDeny {
			t.Errorf("effect=%q: expected a deny rule, got %v", eff, rules)
		}
	}
}

// Canonical effects must pass through unchanged (the fix must not over-deny a
// legitimately-allow rule).
func TestTranslateRule_KnownEffectsPreserved(t *testing.T) {
	cases := map[string]string{"allow": "allow", "deny": "deny", "warn": "warn", "audit": "audit"}
	for in, want := range cases {
		local := TranslateToLocalPolicy(map[string]any{
			"policies": []any{
				map[string]any{"id": "p1", "rules": []any{map[string]any{"effect": in, "actions": []any{"Bash:*"}}}},
			},
			"metadata": map[string]any{"active_policy_count": 1},
		})
		rules, _ := local["rules"].([]any)
		if len(rules) == 0 {
			t.Fatalf("effect=%q: no rules", in)
		}
		m, _ := rules[0].(map[string]any)
		if m["effect"] != want {
			t.Errorf("effect=%q -> %q, want %q", in, m["effect"], want)
		}
	}
}
