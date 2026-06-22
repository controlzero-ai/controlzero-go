package controlzero_test

import (
	"strings"
	"testing"

	"controlzero.ai/sdk/go"
	"controlzero.ai/sdk/go/internal/bundle"
)

// Korean block/warning message localization (#25, gh#1439).
//
// Go parity for the Python tests/test_localized_reason.py:
//   - per-rule ReasonLocalized override selected by CONTROLZERO_LOCALE;
//   - English stays byte-identical when locale unset / English / key missing;
//   - SDK-generated NO_RULE_MATCH + synthetic OBSERVE localize under ko and
//     emit the EXACT legacy (short-form) Go English otherwise;
//   - the bundle round-trip allowlist guard: ReasonLocalized survives
//     translateRule / TranslateToLocalPolicy (gh#175 / #1303 silent-strip);
//   - localization is display-only -- never changes the decided effect.
//
// (The Go enforcer has no DLP path, so DLP localization is covered in the
// Python + Node suites.)

const enNoRuleMatchDenyGo = "No matching policy rule (fail-closed default)"

func hasHangul(s string) bool {
	for _, r := range s {
		if r >= '가' && r <= '힣' {
			return true
		}
	}
	return false
}

func denyRuleLoc(localized map[string]string) controlzero.PolicyRule {
	return controlzero.PolicyRule{
		ID:              "r1",
		Name:            "r1",
		Effect:          "deny",
		Actions:         []string{"delete_*:*"},
		Resources:       []string{"*"},
		Reason:          "Deletion is blocked",
		ReasonLocalized: localized,
	}
}

func TestReasonLocalized_KoSelected(t *testing.T) {
	ev := controlzero.NewPolicyEvaluator([]controlzero.PolicyRule{denyRuleLoc(map[string]string{"ko": "삭제가 차단되었습니다"})})
	ev.SetLocale("ko")
	d := ev.Evaluate("delete_file", "*", nil)
	if d.Effect != "deny" {
		t.Fatalf("effect = %q, want deny", d.Effect)
	}
	if d.Reason != "삭제가 차단되었습니다" {
		t.Errorf("reason = %q, want Korean", d.Reason)
	}
}

func TestReasonLocalized_UnsetUsesEnglish(t *testing.T) {
	ev := controlzero.NewPolicyEvaluator([]controlzero.PolicyRule{denyRuleLoc(map[string]string{"ko": "삭제가 차단되었습니다"})})
	ev.SetLocale("")
	if got := ev.Evaluate("delete_file", "*", nil).Reason; got != "Deletion is blocked" {
		t.Errorf("reason = %q, want English default", got)
	}
}

func TestReasonLocalized_KoMissingFallsBackToEnglish(t *testing.T) {
	ev := controlzero.NewPolicyEvaluator([]controlzero.PolicyRule{denyRuleLoc(map[string]string{"en": "English only"})})
	ev.SetLocale("ko")
	if got := ev.Evaluate("delete_file", "*", nil).Reason; got != "Deletion is blocked" {
		t.Errorf("reason = %q, want plain English fallback", got)
	}
}

func TestReasonLocalized_PlainReasonUnchangedAllLocales(t *testing.T) {
	for _, loc := range []string{"", "en", "ko", "ja", "fr"} {
		ev := controlzero.NewPolicyEvaluator([]controlzero.PolicyRule{denyRuleLoc(nil)})
		ev.SetLocale(loc)
		if got := ev.Evaluate("delete_file", "*", nil).Reason; got != "Deletion is blocked" {
			t.Errorf("locale %q: reason = %q, want unchanged", loc, got)
		}
	}
}

func TestReasonLocalized_RegionSubtagMatchesKo(t *testing.T) {
	for _, loc := range []string{"ko-KR", "ko_KR", "KO"} {
		ev := controlzero.NewPolicyEvaluator([]controlzero.PolicyRule{denyRuleLoc(map[string]string{"ko": "삭제가 차단되었습니다"})})
		ev.SetLocale(loc)
		if got := ev.Evaluate("delete_file", "*", nil).Reason; got != "삭제가 차단되었습니다" {
			t.Errorf("locale %q: reason = %q, want Korean", loc, got)
		}
	}
}

func TestReasonLocalized_ReadFromEnv(t *testing.T) {
	t.Setenv("CONTROLZERO_LOCALE", "ko")
	ev := controlzero.NewPolicyEvaluator([]controlzero.PolicyRule{denyRuleLoc(map[string]string{"ko": "삭제가 차단되었습니다"})})
	if got := ev.Evaluate("delete_file", "*", nil).Reason; got != "삭제가 차단되었습니다" {
		t.Errorf("reason = %q, want Korean from env", got)
	}
}

func TestNoRuleMatch_EnglishExactLegacy(t *testing.T) {
	ev := controlzero.NewPolicyEvaluatorWithSettings(nil, controlzero.PolicySettings{DefaultAction: "deny"})
	ev.SetLocale("")
	d := ev.Evaluate("bash", "find", nil)
	if d.ReasonCode != controlzero.ReasonCodeNoRuleMatch {
		t.Fatalf("reason_code = %q, want NO_RULE_MATCH", d.ReasonCode)
	}
	if d.Reason != enNoRuleMatchDenyGo {
		t.Errorf("reason = %q, want exact legacy English %q", d.Reason, enNoRuleMatchDenyGo)
	}
}

func TestNoRuleMatch_KoreanUnderKo(t *testing.T) {
	ev := controlzero.NewPolicyEvaluatorWithSettings(nil, controlzero.PolicySettings{DefaultAction: "deny"})
	ev.SetLocale("ko")
	d := ev.Evaluate("bash", "find", nil)
	if d.ReasonCode != controlzero.ReasonCodeNoRuleMatch {
		t.Fatalf("reason_code = %q, want NO_RULE_MATCH", d.ReasonCode)
	}
	if d.Reason == enNoRuleMatchDenyGo || !hasHangul(d.Reason) {
		t.Errorf("reason = %q, want Korean", d.Reason)
	}
}

func TestNoRuleMatch_AllowWarnLocalized(t *testing.T) {
	for _, def := range []string{"allow", "warn"} {
		en := controlzero.NewPolicyEvaluatorWithSettings(nil, controlzero.PolicySettings{DefaultAction: def})
		en.SetLocale("")
		want := "No matching policy rule (default_action=" + def + ")"
		if got := en.Evaluate("bash", "find", nil).Reason; got != want {
			t.Errorf("default %q: en reason = %q, want %q", def, got, want)
		}
		ko := controlzero.NewPolicyEvaluatorWithSettings(nil, controlzero.PolicySettings{DefaultAction: def})
		ko.SetLocale("ko")
		if got := ko.Evaluate("bash", "find", nil).Reason; !hasHangul(got) {
			t.Errorf("default %q: ko reason = %q, want Korean", def, got)
		}
	}
}

// --- synthetic OBSERVE round-trip (empty bundle) ---------------------------

func observeDecide(t *testing.T, locale string) controlzero.PolicyDecision {
	t.Helper()
	payload := map[string]any{
		"policies": []any{},
		"metadata": map[string]any{"active_policy_count": 0.0},
	}
	local := bundle.TranslateToLocalPolicy(payload)
	parsed, err := controlzero.LoadPolicyFull(local)
	if err != nil {
		t.Fatalf("LoadPolicyFull: %v", err)
	}
	ev := controlzero.NewPolicyEvaluatorWithSettings(parsed.Rules, parsed.Settings)
	ev.SetLocale(locale)
	return ev.Evaluate("Bash", "run", nil)
}

func TestObserveMode_EnglishUnchanged(t *testing.T) {
	d := observeDecide(t, "")
	if d.ReasonCode != controlzero.ReasonCodeObserveModeNoPolicy {
		t.Fatalf("reason_code = %q, want OBSERVE_MODE_NO_POLICY", d.ReasonCode)
	}
	if d.Effect != "allow" {
		t.Errorf("effect = %q, want allow", d.Effect)
	}
	if !strings.HasPrefix(d.Reason, "OBSERVE MODE:") {
		t.Errorf("reason = %q, want exact legacy English prefix", d.Reason)
	}
}

func TestObserveMode_KoreanUnderKo(t *testing.T) {
	d := observeDecide(t, "ko")
	if d.ReasonCode != controlzero.ReasonCodeObserveModeNoPolicy {
		t.Fatalf("reason_code = %q, want OBSERVE_MODE_NO_POLICY", d.ReasonCode)
	}
	if d.Effect != "allow" { // display-only; effect unchanged
		t.Errorf("effect = %q, want allow", d.Effect)
	}
	if !hasHangul(d.Reason) || strings.HasPrefix(d.Reason, "OBSERVE MODE:") {
		t.Errorf("reason = %q, want Korean", d.Reason)
	}
}

// --- bundle round-trip allowlist guard -------------------------------------

func TestSignedBundleRoundTripSurfacesKorean(t *testing.T) {
	payload := map[string]any{
		"policies": []any{
			map[string]any{
				"id":       "pol-1",
				"priority": 1.0,
				"rules": []any{
					map[string]any{
						"id":               "deny-delete",
						"effect":           "deny",
						"actions":          []any{"delete_*"},
						"reason":           "Deletion is blocked",
						"reason_localized": map[string]any{"ko": "삭제가 차단되었습니다"},
					},
				},
			},
		},
		"metadata": map[string]any{"active_policy_count": 1.0},
	}
	local := bundle.TranslateToLocalPolicy(payload)
	parsed, err := controlzero.LoadPolicyFull(local)
	if err != nil {
		t.Fatalf("LoadPolicyFull: %v", err)
	}
	found := false
	for _, r := range parsed.Rules {
		if r.ReasonLocalized != nil && r.ReasonLocalized["ko"] == "삭제가 차단되었습니다" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reason_localized stripped in bundle round-trip (allowlist trap)")
	}
	evKo := controlzero.NewPolicyEvaluatorWithSettings(parsed.Rules, parsed.Settings)
	evKo.SetLocale("ko")
	if got := evKo.Evaluate("delete_file", "*", nil).Reason; got != "삭제가 차단되었습니다" {
		t.Errorf("ko reason = %q, want Korean", got)
	}
	evEn := controlzero.NewPolicyEvaluatorWithSettings(parsed.Rules, parsed.Settings)
	evEn.SetLocale("")
	if got := evEn.Evaluate("delete_file", "*", nil).Reason; got != "Deletion is blocked" {
		t.Errorf("en reason = %q, want English", got)
	}
}

func TestLoadPolicyAcceptsReasonLocalized(t *testing.T) {
	parsed, err := controlzero.LoadPolicyFull(map[string]any{
		"version": "1",
		"rules": []any{
			map[string]any{
				"deny":             "delete_*",
				"reason":           "Deletion is blocked",
				"reason_localized": map[string]any{"ko": "삭제가 차단되었습니다"},
			},
		},
	})
	if err != nil {
		t.Fatalf("LoadPolicyFull: %v", err)
	}
	if len(parsed.Rules) != 1 || parsed.Rules[0].ReasonLocalized["ko"] != "삭제가 차단되었습니다" {
		t.Errorf("reason_localized not parsed: %+v", parsed.Rules)
	}
}

func TestLoadPolicyMalformedReasonLocalizedErrors(t *testing.T) {
	_, err := controlzero.LoadPolicyFull(map[string]any{
		"version": "1",
		"rules": []any{
			map[string]any{"deny": "delete_*", "reason_localized": "not-a-map"},
		},
	})
	if err == nil {
		t.Errorf("expected load error for malformed reason_localized")
	}
}

func TestLocalizationDisplayOnly(t *testing.T) {
	for _, loc := range []string{"", "en", "ko"} {
		ev := controlzero.NewPolicyEvaluator([]controlzero.PolicyRule{denyRuleLoc(map[string]string{"ko": "차단됨"})})
		ev.SetLocale(loc)
		d := ev.Evaluate("delete_file", "*", nil)
		if d.Effect != "deny" || d.PolicyID != "r1" {
			t.Errorf("locale %q: effect=%q id=%q, want deny/r1", loc, d.Effect, d.PolicyID)
		}
	}
}
