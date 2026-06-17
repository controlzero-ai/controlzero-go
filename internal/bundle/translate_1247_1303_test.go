// #1247 + #1303 parity tests for the Go bundle translator.
//
// Mirrors the Python suite
// sdks/python/controlzero/tests/test_part3_active_policy_count_1303.py.
// The previous Go translator hard-coded a deny-all synthetic rule on ANY
// empty rule set and dropped the default_on_* knobs. This brings it to
// parity with the post-fix Python semantics:
//
//   - count == 0  + explicit []     -> OBSERVE allow  (#1247 genuine empty)
//   - count == 0  + missing/bad key -> FAIL CLOSED (BUNDLE_MISSING deny)
//   - count  > 0  + empty policies  -> FAIL CLOSED (stripped bundle)
//   - count  > 0  + degraded rules  -> FAIL CLOSED
//   - count absent + explicit []    -> OBSERVE allow  (shape heuristic)
//   - count absent + degraded rules -> FAIL CLOSED
//   - malformed count               -> treated as absent, never a genuine 0
//   - default_on_empty=deny overrides observe
//
// Each assertion fails if the empty-vs-degraded discriminator or the
// default_on_* propagation is reverted: a stripped/degraded bundle would
// flip from deny back to allow (the rm-rf fail-open, #1303), and a
// genuinely-empty project would flip from observe back to the old
// hard-coded deny (regressing #1247).
package bundle

import "testing"

// emptyRuleVerdict translates the payload and returns the single
// synthetic catch-all rule the translator emits when no real rules
// survive. Helper keeps each case a one-liner like the Python `_decide`.
func emptyRuleVerdict(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	out := TranslateToLocalPolicy(payload)
	rules, ok := out["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("want exactly 1 synthetic rule, got %v", out["rules"])
	}
	r, ok := rules[0].(map[string]any)
	if !ok {
		t.Fatalf("synthetic rule is not a map: %v", rules[0])
	}
	return r
}

func meta(count any) map[string]any {
	return map[string]any{"metadata": map[string]any{"active_policy_count": count}}
}

func merge(parts ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, p := range parts {
		for k, v := range p {
			out[k] = v
		}
	}
	return out
}

// --- count == 0 -> genuinely empty -> OBSERVE (must NOT regress #1247) -------

func TestTranslate1303_CountZeroEmptyPoliciesObserves(t *testing.T) {
	r := emptyRuleVerdict(t, merge(map[string]any{"policies": []any{}}, meta(0.0)))
	if r["effect"] != "allow" {
		t.Errorf("effect = %v, want allow (observe)", r["effect"])
	}
	if r["reason_code"] != "OBSERVE_MODE_NO_POLICY" {
		t.Errorf("reason_code = %v, want OBSERVE_MODE_NO_POLICY", r["reason_code"])
	}
	if r["id"] != "synthetic:OBSERVE_MODE_NO_POLICY" {
		t.Errorf("id = %v, want synthetic:OBSERVE_MODE_NO_POLICY", r["id"])
	}
}

func TestTranslate1303_CountZeroNoPoliciesKeyFailsClosed(t *testing.T) {
	// count==0 but the `policies` key is MISSING (truncated/malformed). A
	// genuine empty project ALWAYS ships an explicit []; a missing key is
	// degraded -> must FAIL CLOSED, not observe-allow. (#1303)
	r := emptyRuleVerdict(t, meta(0.0))
	if r["effect"] != "deny" {
		t.Errorf("effect = %v, want deny (degraded fail-closed)", r["effect"])
	}
	if r["reason_code"] != "BUNDLE_MISSING" {
		t.Errorf("reason_code = %v, want BUNDLE_MISSING", r["reason_code"])
	}
}

func TestTranslate1303_CountZeroMalformedPoliciesFailsClosed(t *testing.T) {
	// count==0 but `policies` is a non-array (malformed). Not an explicit
	// empty list -> degraded -> fail closed.
	r := emptyRuleVerdict(t, merge(map[string]any{"policies": "not-a-list"}, meta(0.0)))
	if r["effect"] != "deny" {
		t.Errorf("effect = %v, want deny", r["effect"])
	}
	if r["reason_code"] != "BUNDLE_MISSING" {
		t.Errorf("reason_code = %v, want BUNDLE_MISSING", r["reason_code"])
	}
}

// --- count > 0 + empty policies -> FAIL CLOSED (the headline part-3 fix) -----

func TestTranslate1303_CountPositiveEmptyPoliciesDenies(t *testing.T) {
	// Stripped bundle: ships `policies: []` but the project HAS 3
	// attachments. Pre-fix this OBSERVED (allow-all). Now it denies.
	r := emptyRuleVerdict(t, merge(map[string]any{"policies": []any{}}, meta(3.0)))
	if r["effect"] != "deny" {
		t.Errorf("stripped bundle with attachments must fail CLOSED; effect = %v", r["effect"])
	}
	if r["reason_code"] != "BUNDLE_MISSING" {
		t.Errorf("reason_code = %v, want BUNDLE_MISSING", r["reason_code"])
	}
}

func TestTranslate1303_CountPositiveDegradedRulesDenies(t *testing.T) {
	payload := merge(map[string]any{
		"policies": []any{map[string]any{"id": "p", "rules": []any{}}},
	}, meta(1.0))
	r := emptyRuleVerdict(t, payload)
	if r["effect"] != "deny" {
		t.Errorf("effect = %v, want deny", r["effect"])
	}
	if r["reason_code"] != "BUNDLE_MISSING" {
		t.Errorf("reason_code = %v, want BUNDLE_MISSING", r["reason_code"])
	}
}

// --- count absent (older backend) -> fall back to shape heuristic ------------

func TestTranslate1303_CountAbsentEmptyPoliciesObserves(t *testing.T) {
	r := emptyRuleVerdict(t, map[string]any{"policies": []any{}})
	if r["effect"] != "allow" {
		t.Errorf("effect = %v, want allow (observe)", r["effect"])
	}
	if r["reason_code"] != "OBSERVE_MODE_NO_POLICY" {
		t.Errorf("reason_code = %v, want OBSERVE_MODE_NO_POLICY", r["reason_code"])
	}
}

func TestTranslate1303_CountAbsentDegradedDenies(t *testing.T) {
	payload := map[string]any{
		"policies": []any{map[string]any{"id": "p", "rules": []any{}}},
	}
	r := emptyRuleVerdict(t, payload)
	if r["effect"] != "deny" {
		t.Errorf("effect = %v, want deny (degraded, no count)", r["effect"])
	}
	if r["reason_code"] != "BUNDLE_MISSING" {
		t.Errorf("reason_code = %v, want BUNDLE_MISSING", r["reason_code"])
	}
}

func TestTranslate1303_CountAbsentMissingPoliciesKeyFailsClosed(t *testing.T) {
	// No metadata AND no `policies` key at all (fully degraded). Not an
	// explicit [] -> fail closed.
	r := emptyRuleVerdict(t, map[string]any{})
	if r["effect"] != "deny" {
		t.Errorf("effect = %v, want deny (no policies key)", r["effect"])
	}
	if r["reason_code"] != "BUNDLE_MISSING" {
		t.Errorf("reason_code = %v, want BUNDLE_MISSING", r["reason_code"])
	}
}

// --- malformed count -> treated as absent, never a genuine 0 -----------------

func TestBundleActivePolicyCount_RejectsNonIntegers(t *testing.T) {
	// A string / bool / negative / non-whole-float count must NOT be read
	// as a real 0 that would observe a stripped bundle.
	bad := []any{"0", true, false, -1.0, 1.5, nil, int(-3)}
	for _, b := range bad {
		if _, ok := bundleActivePolicyCount(meta(b)); ok {
			t.Errorf("active_policy_count=%v(%T) must be treated as absent", b, b)
		}
	}
}

func TestBundleActivePolicyCount_BoolNotReadAsOne(t *testing.T) {
	// bool must never be read as count==1 (Python rejects the int subclass).
	if _, ok := bundleActivePolicyCount(meta(true)); ok {
		t.Error("active_policy_count=true must be treated as absent, not 1")
	}
}

func TestBundleActivePolicyCount_ReadsValidIntegers(t *testing.T) {
	if n, ok := bundleActivePolicyCount(meta(0.0)); !ok || n != 0 {
		t.Errorf("count 0.0: got (%d,%v), want (0,true)", n, ok)
	}
	if n, ok := bundleActivePolicyCount(meta(7.0)); !ok || n != 7 {
		t.Errorf("count 7.0: got (%d,%v), want (7,true)", n, ok)
	}
	// Native ints (payloads built directly as Go maps) also accepted.
	if n, ok := bundleActivePolicyCount(meta(int(4))); !ok || n != 4 {
		t.Errorf("count int(4): got (%d,%v), want (4,true)", n, ok)
	}
	if _, ok := bundleActivePolicyCount(map[string]any{}); ok {
		t.Error("no metadata: want absent")
	}
	if _, ok := bundleActivePolicyCount(map[string]any{"metadata": "nope"}); ok {
		t.Error("non-map metadata: want absent")
	}
}

func TestTranslate1303_MalformedCountFallsBackToShape(t *testing.T) {
	// A bad count with an explicit `policies: []` falls back to the shape
	// heuristic (explicit [] -> observe), NOT to a stripped-bundle deny.
	r := emptyRuleVerdict(t, merge(map[string]any{"policies": []any{}}, meta("0")))
	if r["effect"] != "allow" {
		t.Errorf("effect = %v, want allow (malformed count -> shape says genuine empty)", r["effect"])
	}
	if r["reason_code"] != "OBSERVE_MODE_NO_POLICY" {
		t.Errorf("reason_code = %v, want OBSERVE_MODE_NO_POLICY", r["reason_code"])
	}
}

// --- default_on_empty override ----------------------------------------------

func TestTranslate1303_DefaultOnEmptyDenyOverridesObserve(t *testing.T) {
	// A genuinely-empty project with default_on_empty=deny must FAIL
	// CLOSED (deny + NO_ACTIVE_POLICIES), not observe-allow. Reverting the
	// knob propagation flips this back to allow.
	payload := merge(
		map[string]any{"policies": []any{}, "default_on_empty": "deny"},
		meta(0.0),
	)
	r := emptyRuleVerdict(t, payload)
	if r["effect"] != "deny" {
		t.Errorf("default_on_empty=deny must deny; effect = %v", r["effect"])
	}
	if r["reason_code"] != "NO_ACTIVE_POLICIES" {
		t.Errorf("reason_code = %v, want NO_ACTIVE_POLICIES", r["reason_code"])
	}
}

func TestTranslate1303_DefaultOnEmptyWarnOverridesObserve(t *testing.T) {
	payload := merge(
		map[string]any{"policies": []any{}, "default_on_empty": "warn"},
		meta(0.0),
	)
	r := emptyRuleVerdict(t, payload)
	if r["effect"] != "warn" {
		t.Errorf("default_on_empty=warn must warn; effect = %v", r["effect"])
	}
	if r["reason_code"] != "NO_ACTIVE_POLICIES" {
		t.Errorf("reason_code = %v, want NO_ACTIVE_POLICIES", r["reason_code"])
	}
}

// --- knob propagation into the translated map -------------------------------

func TestTranslate1303_PropagatesDefaultsIntoSettings(t *testing.T) {
	out := TranslateToLocalPolicy(map[string]any{
		"policies":           []any{},
		"default_action":     "warn",
		"default_on_missing": "allow",
		"default_on_empty":   "deny",
		"default_on_tamper":  "quarantine",
	})
	settings, ok := out["settings"].(map[string]any)
	if !ok {
		t.Fatalf("settings block missing: %v", out["settings"])
	}
	cases := map[string]string{
		"default_action":     "warn",
		"default_on_missing": "allow",
		"default_on_empty":   "deny",
		"default_on_tamper":  "quarantine",
	}
	for k, want := range cases {
		if settings[k] != want {
			t.Errorf("settings[%q] = %v, want %q", k, settings[k], want)
		}
		// Mirrored at the top level for the bundle wire shape too.
		if out[k] != want {
			t.Errorf("top-level %q = %v, want %q", k, out[k], want)
		}
	}
}

func TestTranslate1303_CanonicalFallbacksWhenAbsent(t *testing.T) {
	out := TranslateToLocalPolicy(map[string]any{"policies": []any{}})
	settings := out["settings"].(map[string]any)
	want := map[string]string{
		"default_action":     "deny",
		"default_on_missing": "deny",
		"default_on_empty":   "observe",
		"default_on_tamper":  "warn",
	}
	for k, v := range want {
		if settings[k] != v {
			t.Errorf("canonical settings[%q] = %v, want %q", k, settings[k], v)
		}
	}
}

func TestTranslate1303_UnknownDefaultsCoerceToCanonical(t *testing.T) {
	out := TranslateToLocalPolicy(map[string]any{
		"policies":         []any{},
		"default_action":   "bogus",
		"default_on_empty": 123, // non-string
	})
	settings := out["settings"].(map[string]any)
	if settings["default_action"] != "deny" {
		t.Errorf("unknown default_action must coerce to deny, got %v", settings["default_action"])
	}
	if settings["default_on_empty"] != "observe" {
		t.Errorf("non-string default_on_empty must coerce to observe, got %v", settings["default_on_empty"])
	}
}

// --- real rules win regardless of count (sanity) -----------------------------

func TestTranslate1303_RealRuleEnforcedRegardlessOfCount(t *testing.T) {
	payload := merge(map[string]any{
		"policies": []any{
			map[string]any{
				"id":    "p",
				"rules": []any{map[string]any{"effect": "deny", "actions": []any{"Bash:rm"}}},
			},
		},
	}, meta(1.0))
	out := TranslateToLocalPolicy(payload)
	rules := out["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("want 1 real rule, got %d", len(rules))
	}
	r := rules[0].(map[string]any)
	if r["effect"] != "deny" || r["action"] != "Bash:rm" {
		t.Errorf("real deny rule altered: %v", r)
	}
}
