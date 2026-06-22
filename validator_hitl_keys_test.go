package controlzero

// Tests for HITL-5c (gh#540): policy validator additive surface in
// Go SDK v1.7.6.
//
// Covers every new branch in policy_loader.go:
//   - EscalateOnDeny is recognized + plumbed into PolicyRule (default false).
//   - levenshteinLE1 helper: 0/1-edit pairs return true; >=2-edit pairs return false.
//   - Typo guardrail: warns on near-miss unknown rule keys (Levenshtein-1).
//   - Typo guardrail: silent on unknown keys far from any known one.
//   - Existing v1.7.5 policies (no escalate_on_deny) still parse identically.
//
// Lives in the controlzero package (not _test) so the unexported
// `levenshteinLE1` helper is directly callable.

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// ---- levenshteinLE1 helper -------------------------------------------------

func TestLevenshteinLE1(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical_strings", "escalate_on_deny", "escalate_on_deny", true},
		{"empty_strings", "", "", true},
		{"one_substitution", "eqcalate_on_deny", "escalate_on_deny", true},
		{"one_insertion", "escalate_on_dny", "escalate_on_deny", true},
		{"one_deletion", "escalate_on_denyx", "escalate_on_deny", true},
		{"two_substitutions", "escalate_on_dnen", "escalate_on_deny", false},
		{"length_diff_gt_1_short", "a", "abc", false},
		{"length_diff_gt_1_long", "escalate", "escalate_on_deny", false},
		{"completely_different", "foo", "bar", false},
		{"one_char_identical", "a", "a", true},
		{"one_char_substitution", "a", "b", true},
		{"one_char_deletion", "a", "", true},
		{"one_char_insertion", "", "a", true},
		{"swap_branch_b_shorter", "escalate_on_deny", "escalate_on_den", true},
		{"substitution_at_end", "escalate_on_denz", "escalate_on_deny", true},
		{"tail_diff_two", "foo", "fooxx", false},
		{"tail_diff_one", "foo", "foox", true},
		// Transposition is distance 2 in basic Levenshtein, not 1.
		// Documented behavior; if we ever upgrade to Damerau-Levenshtein,
		// this case flips and that's an intentional change.
		{"transposition_not_caught", "escalate_on_dney", "escalate_on_deny", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := levenshteinLE1(c.a, c.b); got != c.want {
				t.Errorf("levenshteinLE1(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
			}
		})
	}
}

// ---- knownRuleKeys allowlist ----------------------------------------------

func TestKnownRuleKeysIncludesEscalateOnDeny(t *testing.T) {
	if !knownRuleKeys["escalate_on_deny"] {
		t.Errorf("'escalate_on_deny' missing from knownRuleKeys")
	}
}

func TestKnownRuleKeysIncludesLegacyKeys(t *testing.T) {
	legacy := []string{
		"id", "name", "deny", "allow", "effect", "action", "actions",
		"resource", "resources", "when", "conditions", "reason", "reason_code",
	}
	for _, k := range legacy {
		if !knownRuleKeys[k] {
			t.Errorf("legacy key %q missing from knownRuleKeys", k)
		}
	}
}

func TestKnownRuleKeysNoUnexpectedAdditions(t *testing.T) {
	// Defensive: if someone adds a new key, this test fails so they
	// remember to update the typo guardrail intentionally.
	expected := map[string]bool{
		"id":               true,
		"name":             true,
		"deny":             true,
		"allow":            true,
		"effect":           true,
		"action":           true,
		"actions":          true,
		"resource":         true,
		"resources":        true,
		"when":             true,
		"conditions":       true,
		"reason":           true,
		"reason_code":      true,
		"reason_localized": true, // #25, gh#1439
		"escalate_on_deny": true,
	}
	if len(knownRuleKeys) != len(expected) {
		t.Errorf("knownRuleKeys has %d entries, want %d", len(knownRuleKeys), len(expected))
	}
	for k := range expected {
		if !knownRuleKeys[k] {
			t.Errorf("expected key %q missing", k)
		}
	}
	for k := range knownRuleKeys {
		if !expected[k] {
			t.Errorf("unexpected key %q in knownRuleKeys; if intentional, update this test", k)
		}
	}
}

// ---- EscalateOnDeny additive plumbing -------------------------------------

func TestEscalateOnDenyDefaultFalse(t *testing.T) {
	parsed, err := LoadPolicyFull(map[string]any{
		"version": "1",
		"rules": []any{
			map[string]any{"deny": "Bash:sudo *", "reason": "no sudo"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPolicyFull error: %v", err)
	}
	if parsed.Rules[0].EscalateOnDeny != false {
		t.Errorf("EscalateOnDeny = %v, want false (default)", parsed.Rules[0].EscalateOnDeny)
	}
}

func TestEscalateOnDenyTrueWhenSet(t *testing.T) {
	parsed, err := LoadPolicyFull(map[string]any{
		"version": "1",
		"rules": []any{
			map[string]any{
				"deny":             "Bash:sudo *",
				"reason":           "no sudo",
				"escalate_on_deny": true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadPolicyFull error: %v", err)
	}
	if !parsed.Rules[0].EscalateOnDeny {
		t.Errorf("EscalateOnDeny = false, want true")
	}
}

func TestEscalateOnDenyExplicitFalseStaysFalse(t *testing.T) {
	parsed, err := LoadPolicyFull(map[string]any{
		"version": "1",
		"rules": []any{
			map[string]any{"deny": "Bash:sudo *", "escalate_on_deny": false},
		},
	})
	if err != nil {
		t.Fatalf("LoadPolicyFull error: %v", err)
	}
	if parsed.Rules[0].EscalateOnDeny {
		t.Errorf("EscalateOnDeny = true, want false")
	}
}

func TestEscalateOnDenyTruthyNonBoolCoerced(t *testing.T) {
	// YAML/JSON may decode `escalate_on_deny: 1` as int. Coerce.
	cases := []any{1, int64(1), 1.0, "yes", "true", "1", "on"}
	for _, val := range cases {
		parsed, err := LoadPolicyFull(map[string]any{
			"version": "1",
			"rules": []any{
				map[string]any{"deny": "Bash:sudo *", "escalate_on_deny": val},
			},
		})
		if err != nil {
			t.Fatalf("LoadPolicyFull error for %v: %v", val, err)
		}
		if !parsed.Rules[0].EscalateOnDeny {
			t.Errorf("EscalateOnDeny = false for input %v (%T), want true", val, val)
		}
	}
}

func TestEscalateOnDenyFalsyNonBoolCoerced(t *testing.T) {
	cases := []any{0, int64(0), 0.0, "false", "0", "no", "off", "", "FALSE"}
	for _, val := range cases {
		parsed, err := LoadPolicyFull(map[string]any{
			"version": "1",
			"rules": []any{
				map[string]any{"deny": "Bash:sudo *", "escalate_on_deny": val},
			},
		})
		if err != nil {
			t.Fatalf("LoadPolicyFull error for %v: %v", val, err)
		}
		if parsed.Rules[0].EscalateOnDeny {
			t.Errorf("EscalateOnDeny = true for input %v (%T), want false", val, val)
		}
	}
}

func TestEscalateOnDenyAllowRuleCanCarryField(t *testing.T) {
	// Field is rule-level, not effect-coupled.
	parsed, err := LoadPolicyFull(map[string]any{
		"version": "1",
		"rules": []any{
			map[string]any{
				"allow":            "Bash:make test",
				"escalate_on_deny": true,
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadPolicyFull error: %v", err)
	}
	if !parsed.Rules[0].EscalateOnDeny {
		t.Errorf("EscalateOnDeny = false on allow rule, want true")
	}
	if parsed.Rules[0].Effect != "allow" {
		t.Errorf("Effect = %q, want allow", parsed.Rules[0].Effect)
	}
}

// ---- Typo guardrail (stderr warnings) -------------------------------------

// captureStderrHITL replaces os.Stderr for the duration of fn, returning
// everything the helper wrote to it. Restores the original Stderr on
// return regardless of panic.
func captureStderrHITL(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	return <-done
}

func TestTypoGuardrailWarnsOnNearMissEscalateOnDeny(t *testing.T) {
	// `escalate_on_dny` is one deletion from `escalate_on_deny`.
	out := captureStderrHITL(t, func() {
		_, err := LoadPolicyFull(map[string]any{
			"version": "1",
			"rules": []any{
				map[string]any{
					"deny":            "Bash:sudo *",
					"escalate_on_dny": true,
				},
			},
		})
		if err != nil {
			t.Fatalf("LoadPolicyFull error: %v", err)
		}
	})
	if !strings.Contains(out, "escalate_on_dny") {
		t.Errorf("stderr missing typo'd key, got: %q", out)
	}
	if !strings.Contains(out, "escalate_on_deny") {
		t.Errorf("stderr missing suggestion, got: %q", out)
	}
	if !strings.Contains(out, "did you mean") {
		t.Errorf("stderr missing 'did you mean' phrase, got: %q", out)
	}
}

func TestTypoGuardrailWarnsOnActionTypo(t *testing.T) {
	// `actiom` is one substitution from `action`.
	out := captureStderrHITL(t, func() {
		_, err := LoadPolicyFull(map[string]any{
			"version": "1",
			"rules": []any{
				map[string]any{
					"actiom": "Bash:make",
					"deny":   "Bash:make",
				},
			},
		})
		if err != nil {
			t.Fatalf("LoadPolicyFull error: %v", err)
		}
	})
	if !strings.Contains(out, "actiom") {
		t.Errorf("stderr missing typo'd key, got: %q", out)
	}
	if !strings.Contains(out, "action") {
		t.Errorf("stderr missing suggestion, got: %q", out)
	}
}

func TestTypoGuardrailSilentOnFarUnknownKey(t *testing.T) {
	out := captureStderrHITL(t, func() {
		_, err := LoadPolicyFull(map[string]any{
			"version": "1",
			"rules": []any{
				map[string]any{
					"deny":                         "Bash:sudo *",
					"completely_made_up_field_xyz": "some value",
				},
			},
		})
		if err != nil {
			t.Fatalf("LoadPolicyFull error: %v", err)
		}
	})
	if out != "" {
		t.Errorf("expected silent stderr on far-unknown key, got: %q", out)
	}
}

func TestTypoGuardrailSilentOnTransposition(t *testing.T) {
	// Transpositions are distance 2 in basic Levenshtein, so the
	// guardrail explicitly does NOT warn. Documented behavior.
	out := captureStderrHITL(t, func() {
		_, err := LoadPolicyFull(map[string]any{
			"version": "1",
			"rules": []any{
				map[string]any{
					"deny":             "Bash:sudo *",
					"escalate_on_dney": true, // n<->e transposition
				},
			},
		})
		if err != nil {
			t.Fatalf("LoadPolicyFull error: %v", err)
		}
	})
	if out != "" {
		t.Errorf("expected silent stderr on transposition, got: %q", out)
	}
}

func TestTypoGuardrailSilentWhenAllKeysKnown(t *testing.T) {
	out := captureStderrHITL(t, func() {
		_, err := LoadPolicyFull(map[string]any{
			"version": "1",
			"rules": []any{
				map[string]any{
					"id":               "r1",
					"name":             "no sudo",
					"deny":             "Bash:sudo *",
					"reason":           "policy",
					"escalate_on_deny": true,
				},
			},
		})
		if err != nil {
			t.Fatalf("LoadPolicyFull error: %v", err)
		}
	})
	if out != "" {
		t.Errorf("expected silent stderr when all keys known, got: %q", out)
	}
}

func TestTypoGuardrailDoesNotBreakParsing(t *testing.T) {
	// Even with the typo warning fired, the rule should still parse.
	parsed, err := LoadPolicyFull(map[string]any{
		"version": "1",
		"rules": []any{
			map[string]any{
				"deny":            "Bash:sudo *",
				"escalate_on_dny": true, // typo
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadPolicyFull error: %v", err)
	}
	if len(parsed.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(parsed.Rules))
	}
	if parsed.Rules[0].Effect != "deny" {
		t.Errorf("Effect = %q, want deny", parsed.Rules[0].Effect)
	}
}

// ---- v1.7.5 backward compatibility ----------------------------------------

func TestExistingMinimalPolicyUnchanged(t *testing.T) {
	parsed, err := LoadPolicyFull(map[string]any{
		"version": "1",
		"rules": []any{
			map[string]any{"deny": "*"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPolicyFull error: %v", err)
	}
	if parsed.Rules[0].Effect != "deny" {
		t.Errorf("Effect = %q, want deny", parsed.Rules[0].Effect)
	}
	if parsed.Rules[0].EscalateOnDeny != false {
		t.Errorf("EscalateOnDeny = %v, want false (default for unset)", parsed.Rules[0].EscalateOnDeny)
	}
}

func TestExistingComplexPolicyUnchanged(t *testing.T) {
	parsed, err := LoadPolicyFull(map[string]any{
		"version":  "1",
		"settings": map[string]any{"tamper_behavior": "warn"},
		"rules": []any{
			map[string]any{"id": "r1", "deny": "Bash:sudo *", "reason": "no sudo"},
			map[string]any{"id": "r2", "allow": "Bash:make *"},
			map[string]any{"id": "r3", "deny": "*", "when": map[string]any{"model": "claude-opus-*"}},
		},
	})
	if err != nil {
		t.Fatalf("LoadPolicyFull error: %v", err)
	}
	if len(parsed.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(parsed.Rules))
	}
	for i, r := range parsed.Rules {
		if r.EscalateOnDeny {
			t.Errorf("rule[%d].EscalateOnDeny = true, want false (not set)", i)
		}
	}
}
