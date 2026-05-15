package controlzero_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"controlzero.ai/sdk/go"
)

// TestDefaultPolicySettingsZeroValues pins the canonical defaults so a
// typo in the constants does not silently flip an org's enforcement
// behaviour.
func TestDefaultPolicySettingsZeroValues(t *testing.T) {
	s := controlzero.DefaultPolicySettings()
	if s.DefaultAction != "deny" {
		t.Errorf("DefaultAction = %q, want %q", s.DefaultAction, "deny")
	}
	if s.DefaultOnMissing != "deny" {
		t.Errorf("DefaultOnMissing = %q, want %q", s.DefaultOnMissing, "deny")
	}
	if s.DefaultOnTamper != "warn" {
		t.Errorf("DefaultOnTamper = %q, want %q", s.DefaultOnTamper, "warn")
	}
	if s.TamperBehavior != "warn" {
		t.Errorf("TamperBehavior = %q, want %q", s.TamperBehavior, "warn")
	}
}

// TestEffectiveTamperBehaviorPrefersNewField: the new
// default_on_tamper field wins when both names are present.
func TestEffectiveTamperBehaviorPrefersNewField(t *testing.T) {
	s := controlzero.PolicySettings{
		DefaultOnTamper: "deny-all",
		TamperBehavior:  "warn",
	}
	if got := s.EffectiveTamperBehavior(); got != "deny-all" {
		t.Errorf("EffectiveTamperBehavior = %q, want %q", got, "deny-all")
	}
}

// TestEffectiveTamperBehaviorFallsBackToLegacy: the legacy name is
// honoured when the new one is empty.
func TestEffectiveTamperBehaviorFallsBackToLegacy(t *testing.T) {
	s := controlzero.PolicySettings{TamperBehavior: "quarantine"}
	if got := s.EffectiveTamperBehavior(); got != "quarantine" {
		t.Errorf("EffectiveTamperBehavior = %q, want %q", got, "quarantine")
	}
}

// TestEffectiveTamperBehaviorFallsBackToDefault: both empty -> "warn".
func TestEffectiveTamperBehaviorFallsBackToDefault(t *testing.T) {
	s := controlzero.PolicySettings{}
	if got := s.EffectiveTamperBehavior(); got != "warn" {
		t.Errorf("EffectiveTamperBehavior = %q, want %q", got, "warn")
	}
}

// TestLoadPolicyFullReturnsSettings: settings block is parsed and
// attached to the ParsedPolicy. Covers the happy path.
func TestLoadPolicyFullReturnsSettings(t *testing.T) {
	parsed, err := controlzero.LoadPolicyFull(map[string]any{
		"version": "1",
		"settings": map[string]any{
			"default_action":     "allow",
			"default_on_missing": "allow",
			"default_on_tamper":  "deny-all",
		},
		"rules": []any{map[string]any{"deny": "delete_*"}},
	})
	if err != nil {
		t.Fatalf("LoadPolicyFull: %v", err)
	}
	if parsed.Settings.DefaultAction != "allow" {
		t.Errorf("DefaultAction = %q, want allow", parsed.Settings.DefaultAction)
	}
	if parsed.Settings.DefaultOnMissing != "allow" {
		t.Errorf("DefaultOnMissing = %q, want allow", parsed.Settings.DefaultOnMissing)
	}
	if parsed.Settings.DefaultOnTamper != "deny-all" {
		t.Errorf("DefaultOnTamper = %q, want deny-all", parsed.Settings.DefaultOnTamper)
	}
	if len(parsed.Rules) != 1 {
		t.Errorf("len(Rules) = %d, want 1", len(parsed.Rules))
	}
}

// TestLoadPolicyFullTopLevelDefaults: the bundle wire format carries
// defaults at the TOP level, not under settings. Both shapes must work.
func TestLoadPolicyFullTopLevelDefaults(t *testing.T) {
	parsed, err := controlzero.LoadPolicyFull(map[string]any{
		"version":            "1",
		"default_action":     "warn",
		"default_on_missing": "deny",
		"default_on_tamper":  "deny",
		"rules":              []any{map[string]any{"allow": "*"}},
	})
	if err != nil {
		t.Fatalf("LoadPolicyFull: %v", err)
	}
	if parsed.Settings.DefaultAction != "warn" {
		t.Errorf("DefaultAction = %q, want warn", parsed.Settings.DefaultAction)
	}
	if parsed.Settings.DefaultOnMissing != "deny" {
		t.Errorf("DefaultOnMissing = %q, want deny", parsed.Settings.DefaultOnMissing)
	}
	if parsed.Settings.DefaultOnTamper != "deny" {
		t.Errorf("DefaultOnTamper = %q, want deny", parsed.Settings.DefaultOnTamper)
	}
}

// TestLoadPolicyFullLegacyTamperBehavior: tamper_behavior alone
// populates both TamperBehavior AND DefaultOnTamper for one-release
// migration.
func TestLoadPolicyFullLegacyTamperBehavior(t *testing.T) {
	parsed, err := controlzero.LoadPolicyFull(map[string]any{
		"version": "1",
		"settings": map[string]any{
			"tamper_behavior": "quarantine",
		},
		"rules": []any{map[string]any{"allow": "*"}},
	})
	if err != nil {
		t.Fatalf("LoadPolicyFull: %v", err)
	}
	if parsed.Settings.TamperBehavior != "quarantine" {
		t.Errorf("TamperBehavior = %q, want quarantine", parsed.Settings.TamperBehavior)
	}
	if parsed.Settings.DefaultOnTamper != "quarantine" {
		t.Errorf("DefaultOnTamper = %q, want quarantine (alias)", parsed.Settings.DefaultOnTamper)
	}
}

// TestLoadPolicyFullRejectsUnknownDefaultAction: a typo or malicious
// value MUST NOT silently flip an org's no-match behaviour.
func TestLoadPolicyFullRejectsUnknownDefaultAction(t *testing.T) {
	_, err := controlzero.LoadPolicyFull(map[string]any{
		"version":        "1",
		"default_action": "YOLO",
		"rules":          []any{map[string]any{"allow": "*"}},
	})
	if err == nil {
		t.Fatal("expected validation error on bad default_action")
	}
	var pve *controlzero.PolicyValidationError
	if !errors.As(err, &pve) {
		t.Fatalf("expected *PolicyValidationError, got %T: %v", err, err)
	}
}

// TestLoadPolicyFullRejectsUnknownOnMissing covers the other two
// enum-guarded knobs via the same path.
func TestLoadPolicyFullRejectsUnknownOnMissing(t *testing.T) {
	_, err := controlzero.LoadPolicyFull(map[string]any{
		"version":            "1",
		"default_on_missing": "fallback",
		"rules":              []any{map[string]any{"allow": "*"}},
	})
	if err == nil {
		t.Fatal("expected validation error on bad default_on_missing")
	}
}

// TestLoadPolicyFullRejectsUnknownOnTamper guards the tamper enum.
func TestLoadPolicyFullRejectsUnknownOnTamper(t *testing.T) {
	_, err := controlzero.LoadPolicyFull(map[string]any{
		"version":           "1",
		"default_on_tamper": "ignore",
		"rules":             []any{map[string]any{"allow": "*"}},
	})
	if err == nil {
		t.Fatal("expected validation error on bad default_on_tamper")
	}
}

// TestLoadPolicyFullRejectsBadSettingsShape: settings must be a map.
func TestLoadPolicyFullRejectsBadSettingsShape(t *testing.T) {
	_, err := controlzero.LoadPolicyFull(map[string]any{
		"version":  "1",
		"settings": "not a map",
		"rules":    []any{map[string]any{"allow": "*"}},
	})
	if err == nil {
		t.Fatal("expected validation error on bad settings shape")
	}
}

// TestLoadPolicyBackwardsCompat: the legacy LoadPolicy() signature
// must keep working so pre-#228 callers (including the CLI) do not
// break on upgrade.
func TestLoadPolicyBackwardsCompat(t *testing.T) {
	rules, err := controlzero.LoadPolicy(map[string]any{
		"version": "1",
		"rules":   []any{map[string]any{"deny": "*"}},
	})
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("len(rules) = %d, want 1", len(rules))
	}
}

// TestEvaluatorDefaultActionAllow: the canonical #228 scenario.
// User's db-read-only policy has no matching rule for "write_thing",
// and the org has set default_action=allow. We must allow.
func TestEvaluatorDefaultActionAllow(t *testing.T) {
	rules, _ := controlzero.LoadPolicy(map[string]any{
		"version": "1",
		"rules":   []any{map[string]any{"deny": "delete_*"}},
	})
	ev := controlzero.NewPolicyEvaluatorWithSettings(rules, controlzero.PolicySettings{DefaultAction: "allow"})
	d := ev.Evaluate("write_thing", "", nil)
	if d.Effect != "allow" {
		t.Errorf("Effect = %q, want allow", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeNoRuleMatch {
		t.Errorf("ReasonCode = %q, want NO_RULE_MATCH", d.ReasonCode)
	}
}

// TestEvaluatorDefaultActionWarn: warn mirrors allow on wire but
// effect is "warn" so operators can see what would have been blocked.
func TestEvaluatorDefaultActionWarn(t *testing.T) {
	rules, _ := controlzero.LoadPolicy(map[string]any{
		"version": "1",
		"rules":   []any{map[string]any{"deny": "delete_*"}},
	})
	ev := controlzero.NewPolicyEvaluatorWithSettings(rules, controlzero.PolicySettings{DefaultAction: "warn"})
	d := ev.Evaluate("write_thing", "", nil)
	if d.Effect != "warn" {
		t.Errorf("Effect = %q, want warn", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeNoRuleMatch {
		t.Errorf("ReasonCode = %q, want NO_RULE_MATCH", d.ReasonCode)
	}
}

// TestEvaluatorDefaultActionDenyExplicit: deny is the canonical
// default; explicitly asking for it must still produce deny.
func TestEvaluatorDefaultActionDenyExplicit(t *testing.T) {
	rules, _ := controlzero.LoadPolicy(map[string]any{
		"version": "1",
		"rules":   []any{map[string]any{"deny": "delete_*"}},
	})
	ev := controlzero.NewPolicyEvaluatorWithSettings(rules, controlzero.PolicySettings{DefaultAction: "deny"})
	d := ev.Evaluate("write_thing", "", nil)
	if d.Effect != "deny" {
		t.Errorf("Effect = %q, want deny", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeNoRuleMatch {
		t.Errorf("ReasonCode = %q, want NO_RULE_MATCH", d.ReasonCode)
	}
}

// TestEvaluatorUnknownDefaultActionFailsClosed: a typo or future
// schema MUST fall back to deny, never silently flip an org open.
func TestEvaluatorUnknownDefaultActionFailsClosed(t *testing.T) {
	rules, _ := controlzero.LoadPolicy(map[string]any{
		"version": "1",
		"rules":   []any{map[string]any{"deny": "delete_*"}},
	})
	ev := controlzero.NewPolicyEvaluatorWithSettings(rules, controlzero.PolicySettings{DefaultAction: "MAYBE"})
	d := ev.Evaluate("write_thing", "", nil)
	if d.Effect != "deny" {
		t.Errorf("Effect = %q, want deny (fail-closed on unknown)", d.Effect)
	}
}

// TestEvaluatorEmptyDefaultActionFailsClosed: when nothing is set,
// preserve the legacy fail-closed contract.
func TestEvaluatorEmptyDefaultActionFailsClosed(t *testing.T) {
	rules, _ := controlzero.LoadPolicy(map[string]any{
		"version": "1",
		"rules":   []any{map[string]any{"deny": "delete_*"}},
	})
	ev := controlzero.NewPolicyEvaluator(rules)
	d := ev.Evaluate("write_thing", "", nil)
	if d.Effect != "deny" {
		t.Errorf("Effect = %q, want deny (legacy fail-closed)", d.Effect)
	}
}

// TestEvaluatorMatchEmitsRuleMatch: a matched rule gets the
// RULE_MATCH reason_code regardless of whether the rule declared one.
func TestEvaluatorMatchEmitsRuleMatch(t *testing.T) {
	rules, _ := controlzero.LoadPolicy(map[string]any{
		"version": "1",
		"rules":   []any{map[string]any{"deny": "delete_*"}},
	})
	ev := controlzero.NewPolicyEvaluator(rules)
	d := ev.Evaluate("delete_thing", "", nil)
	if d.Effect != "deny" {
		t.Errorf("Effect = %q, want deny", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeRuleMatch {
		t.Errorf("ReasonCode = %q, want RULE_MATCH", d.ReasonCode)
	}
}

// TestEvaluatorRulePreservesReasonCodeWhenSet: the backend bundle
// translator stamps `reason_code: NO_ACTIVE_POLICIES` on synthetic
// empty-bundle denies. The evaluator must carry that through.
func TestEvaluatorRulePreservesReasonCodeWhenSet(t *testing.T) {
	rules := []controlzero.PolicyRule{{
		ID:         "bundle-empty",
		Name:       "bundle-empty",
		Effect:     "deny",
		Actions:    []string{"*"},
		ReasonCode: "NO_ACTIVE_POLICIES",
	}}
	ev := controlzero.NewPolicyEvaluator(rules)
	d := ev.Evaluate("whatever", "", nil)
	if d.ReasonCode != "NO_ACTIVE_POLICIES" {
		t.Errorf("ReasonCode = %q, want NO_ACTIVE_POLICIES (from rule)", d.ReasonCode)
	}
}

// TestEvaluatorSetDefaultActionMutates: the setter updates the
// configured default_action on an existing evaluator.
func TestEvaluatorSetDefaultActionMutates(t *testing.T) {
	rules, _ := controlzero.LoadPolicy(map[string]any{
		"version": "1",
		"rules":   []any{map[string]any{"deny": "delete_*"}},
	})
	ev := controlzero.NewPolicyEvaluator(rules)
	ev.SetDefaultAction("allow")
	d := ev.Evaluate("write_thing", "", nil)
	if d.Effect != "allow" {
		t.Errorf("Effect = %q, want allow after SetDefaultAction", d.Effect)
	}
}

// TestClientExposesPolicySettings: Client.PolicySettings() must
// return the values parsed from the input policy, so external tools
// (e.g. `controlzero status`) can introspect the effective settings.
func TestClientExposesPolicySettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	content := `
version: "1"
settings:
  default_action: allow
  default_on_missing: allow
  default_on_tamper: deny-all
rules:
  - deny: "delete_*"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := controlzero.New(
		controlzero.WithPolicyFile(path),
		controlzero.WithLogPath(filepath.Join(dir, "audit.log")),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	s := c.PolicySettings()
	if s.DefaultAction != "allow" {
		t.Errorf("DefaultAction = %q, want allow", s.DefaultAction)
	}
	if s.DefaultOnMissing != "allow" {
		t.Errorf("DefaultOnMissing = %q, want allow", s.DefaultOnMissing)
	}
	if s.DefaultOnTamper != "deny-all" {
		t.Errorf("DefaultOnTamper = %q, want deny-all", s.DefaultOnTamper)
	}
}

// TestClientHonoursDefaultActionEndToEnd: #228 scenario via the
// full Client API, not just the evaluator.
func TestClientHonoursDefaultActionEndToEnd(t *testing.T) {
	dir := t.TempDir()
	c, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"version":        "1",
			"default_action": "allow",
			"rules":          []any{map[string]any{"deny": "delete_*"}},
		}),
		controlzero.WithLogPath(filepath.Join(dir, "audit.log")),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	d, err := c.Guard("write_thing", controlzero.GuardOptions{})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if d.Effect != "allow" {
		t.Errorf("Effect = %q, want allow (default_action=allow)", d.Effect)
	}
	if d.ReasonCode != controlzero.ReasonCodeNoRuleMatch {
		t.Errorf("ReasonCode = %q, want NO_RULE_MATCH", d.ReasonCode)
	}
}

// TestValidReasonCodesContainsAllEight: pins the cross-language enum
// membership so a rename does not drift across SDKs.
func TestValidReasonCodesContainsAllEight(t *testing.T) {
	want := []string{
		"RULE_MATCH", "NO_RULE_MATCH", "NO_ACTIVE_POLICIES",
		"BUNDLE_MISSING", "BUNDLE_TAMPERED", "MACHINE_QUARANTINED",
		"NETWORK_ERROR", "DLP_BLOCKED",
	}
	if len(controlzero.ValidReasonCodes) != len(want) {
		t.Errorf("len(ValidReasonCodes) = %d, want %d", len(controlzero.ValidReasonCodes), len(want))
	}
	for _, v := range want {
		if !controlzero.ValidReasonCodes[v] {
			t.Errorf("%s missing from ValidReasonCodes", v)
		}
	}
}
