package controlzero

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Canonical default values when the bundle or YAML does not carry the
// knobs. Matches the backend's canonical defaults (see
// bundle_handler.go: DefaultBundleAction / DefaultBundleOnMissing /
// DefaultBundleOnTamper) and the hard-coded Python/Node SDK behaviour
// pre-#228 Phase 2 so upgrading is non-breaking in both directions.
const (
	DefaultPolicyAction    = "deny"
	DefaultPolicyOnMissing = "deny"
	DefaultPolicyOnTamper  = "warn"
)

// ValidTamperBehaviors mirrors the Python + Node enum so policies
// authored once validate identically across all SDKs. Source of truth:
// docs/behavior-matrix.md section S3.
var ValidTamperBehaviors = map[string]bool{
	"warn":       true,
	"deny":       true,
	"deny-all":   true,
	"quarantine": true,
}

// ValidDefaultActions is the canonical enum for settings.default_action
// and bundle-level default_action. See S1.
var ValidDefaultActions = map[string]bool{
	"deny":  true,
	"allow": true,
	"warn":  true,
}

// ValidOnMissing is the canonical enum for settings.default_on_missing
// and bundle-level default_on_missing. See S2. `last-known-good` is
// deferred to Phase 3.
var ValidOnMissing = map[string]bool{
	"deny":  true,
	"allow": true,
}

// PolicySettings carries the three enforcement-default knobs defined in
// docs/behavior-matrix.md:
//
//   - DefaultAction     deny | allow | warn
//     fired when the bundle has rules but nothing matches.
//   - DefaultOnMissing  deny | allow
//     fired when the client is enrolled but no bundle could be loaded.
//   - DefaultOnTamper   warn | deny | deny-all | quarantine
//     mirrors the existing tamper_behavior field. Both names are
//     accepted in YAML; tamper_behavior is the legacy name.
//
// The zero value of this struct is the canonical fallback (deny/deny/
// warn). This matches every SDK's hard-coded pre-#228 behaviour, so a
// caller that never reads settings keeps the old behaviour.
type PolicySettings struct {
	// DefaultAction is the decision applied when the evaluator loads
	// rules but none match. Values: deny (default), allow, warn.
	DefaultAction string

	// DefaultOnMissing is the decision applied when the client cannot
	// load a bundle at all. Values: deny (default), allow.
	DefaultOnMissing string

	// DefaultOnTamper is the mode used when tamper is detected. Values:
	// warn (default), deny, deny-all, quarantine.
	DefaultOnTamper string

	// TamperBehavior is the legacy alias for DefaultOnTamper. Kept for
	// one release so operators with existing YAML files do not break.
	// Populated from settings.tamper_behavior if present.
	TamperBehavior string
}

// DefaultPolicySettings returns a settings block pre-populated with the
// canonical defaults.
func DefaultPolicySettings() PolicySettings {
	return PolicySettings{
		DefaultAction:    DefaultPolicyAction,
		DefaultOnMissing: DefaultPolicyOnMissing,
		DefaultOnTamper:  DefaultPolicyOnTamper,
		TamperBehavior:   DefaultPolicyOnTamper,
	}
}

// EffectiveTamperBehavior returns the effective tamper mode, preferring
// the new DefaultOnTamper field but falling back to the legacy
// TamperBehavior alias and finally to the canonical default.
func (s PolicySettings) EffectiveTamperBehavior() string {
	if s.DefaultOnTamper != "" {
		return s.DefaultOnTamper
	}
	if s.TamperBehavior != "" {
		return s.TamperBehavior
	}
	return DefaultPolicyOnTamper
}

// ParsedPolicy is the full result of loading a policy source. Matches
// Python's ParsedPolicy and Node's ParsedPolicy one-to-one so fixtures
// + cross-language parity tests stay consistent.
type ParsedPolicy struct {
	Rules    []PolicyRule
	Settings PolicySettings
}

// LoadPolicy parses a policy from a map[string]any (in-memory) or a path
// (string ending in .yaml/.yml/.json). Returns the canonicalized rule list
// or a *PolicyValidationError / *PolicyLoadError on failure.
//
// Backwards-compatible signature: historic callers treat the first
// return as a []PolicyRule which is still correct. New callers should
// prefer LoadPolicyFull for access to PolicySettings.
func LoadPolicy(source any) ([]PolicyRule, error) {
	parsed, err := LoadPolicyFull(source)
	if err != nil {
		return nil, err
	}
	return parsed.Rules, nil
}

// LoadPolicyFull is LoadPolicy but also returns the parsed settings
// block. Introduced in #228 Phase 2. Prefer this in new code so the
// evaluator can honour default_action / default_on_missing /
// default_on_tamper.
func LoadPolicyFull(source any) (ParsedPolicy, error) {
	switch s := source.(type) {
	case map[string]any:
		return validateAndTranslate(s, "<map>")
	case string:
		return loadFromFile(s)
	default:
		return ParsedPolicy{}, &PolicyLoadError{
			Message: fmt.Sprintf("unsupported policy source type: %T", source),
			Source:  fmt.Sprintf("%v", source),
		}
	}
}

// canonicalizeAction translates a friendly pattern to canonical "tool:method" form.
//
//	"*"             -> "*"
//	"delete_*"      -> "delete_*:*"   (no colon = match any method)
//	"github:*"      -> "github:*"
//	"github:list_*" -> "github:list_*"
func canonicalizeAction(pattern string) string {
	if pattern == "*" {
		return "*"
	}
	if strings.Contains(pattern, ":") {
		return pattern
	}
	return pattern + ":*"
}

func loadFromFile(path string) (ParsedPolicy, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ParsedPolicy{}, &PolicyLoadError{
			Message: "policy file not found: " + path,
			Source:  path,
		}
	}

	suffix := strings.ToLower(filepath.Ext(path))
	text, err := os.ReadFile(path)
	if err != nil {
		return ParsedPolicy{}, &PolicyLoadError{
			Message: "cannot read policy file",
			Source:  path,
			Cause:   err,
		}
	}

	var data any

	switch suffix {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(text, &data); err != nil {
			return ParsedPolicy{}, &PolicyLoadError{
				Message: "YAML parse error: " + err.Error(),
				Source:  path,
				Cause:   err,
			}
		}
	case ".json":
		if err := json.Unmarshal(text, &data); err != nil {
			return ParsedPolicy{}, &PolicyLoadError{
				Message: "JSON parse error: " + err.Error(),
				Source:  path,
				Cause:   err,
			}
		}
	default:
		return ParsedPolicy{}, &PolicyLoadError{
			Message: "unsupported file format: " + suffix + " (use .yaml, .yml, or .json)",
			Source:  path,
		}
	}

	if data == nil {
		return ParsedPolicy{}, &PolicyValidationError{
			Errors: []string{"policy file is empty"},
			Source: path,
		}
	}
	dataMap, ok := normalizeToStringMap(data).(map[string]any)
	if !ok {
		return ParsedPolicy{}, &PolicyValidationError{
			Errors: []string{fmt.Sprintf("policy root must be a mapping/object, got %T", data)},
			Source: path,
		}
	}

	return validateAndTranslate(dataMap, path)
}

// normalizeToStringMap converts yaml's map[any]any to map[string]any recursively.
// JSON unmarshal already gives us map[string]any, but YAML doesn't.
func normalizeToStringMap(v any) any {
	switch m := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprintf("%v", k)] = normalizeToStringMap(val)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[k] = normalizeToStringMap(val)
		}
		return out
	case []any:
		out := make([]any, len(m))
		for i, val := range m {
			out[i] = normalizeToStringMap(val)
		}
		return out
	default:
		return v
	}
}

// parseSettings extracts the settings block and validates each field
// against the canonical enums. Unknown fields are accepted (forward
// compat). Zero-value fields are left as the canonical default.
func parseSettings(raw any) (PolicySettings, []string) {
	s := DefaultPolicySettings()
	if raw == nil {
		return s, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return s, []string{"'settings' must be a mapping if present"}
	}

	var errs []string

	if v, ok := m["default_action"]; ok && v != nil {
		str := fmt.Sprintf("%v", v)
		if !ValidDefaultActions[str] {
			errs = append(errs, fmt.Sprintf(
				"settings.default_action must be one of [allow deny warn], got %q", str))
		} else {
			s.DefaultAction = str
		}
	}

	if v, ok := m["default_on_missing"]; ok && v != nil {
		str := fmt.Sprintf("%v", v)
		if !ValidOnMissing[str] {
			errs = append(errs, fmt.Sprintf(
				"settings.default_on_missing must be one of [allow deny], got %q", str))
		} else {
			s.DefaultOnMissing = str
		}
	}

	if v, ok := m["default_on_tamper"]; ok && v != nil {
		str := fmt.Sprintf("%v", v)
		if !ValidTamperBehaviors[str] {
			errs = append(errs, fmt.Sprintf(
				"settings.default_on_tamper must be one of [warn deny deny-all quarantine], got %q", str))
		} else {
			s.DefaultOnTamper = str
		}
	}

	// Legacy alias. If both default_on_tamper and tamper_behavior are
	// present, the newer default_on_tamper wins (already set above).
	if v, ok := m["tamper_behavior"]; ok && v != nil {
		str := fmt.Sprintf("%v", v)
		if !ValidTamperBehaviors[str] {
			errs = append(errs, fmt.Sprintf(
				"settings.tamper_behavior must be one of [warn deny deny-all quarantine], got %q", str))
		} else {
			s.TamperBehavior = str
			if _, newerSet := m["default_on_tamper"]; !newerSet {
				s.DefaultOnTamper = str
			}
		}
	}

	return s, errs
}

func validateAndTranslate(data map[string]any, sourceLabel string) (ParsedPolicy, error) {
	var errs []string

	version := "1"
	if v, ok := data["version"]; ok {
		version = fmt.Sprintf("%v", v)
	}
	if version != "1" {
		errs = append(errs, fmt.Sprintf("unsupported version %q, expected \"1\"", version))
	}

	// Top-level default_action / default_on_missing / default_on_tamper
	// are ALSO accepted (bundle wire format, schema 1.1). They take
	// precedence over settings.* if both are present, matching the
	// Python bundle translator.
	settingsRaw := data["settings"]
	settings, settingsErrs := parseSettings(settingsRaw)
	errs = append(errs, settingsErrs...)

	for _, pair := range []struct {
		key        string
		validSet   map[string]bool
		set        func(string)
		enumLabel  string
	}{
		{"default_action", ValidDefaultActions, func(s string) { settings.DefaultAction = s }, "[allow deny warn]"},
		{"default_on_missing", ValidOnMissing, func(s string) { settings.DefaultOnMissing = s }, "[allow deny]"},
		{"default_on_tamper", ValidTamperBehaviors, func(s string) { settings.DefaultOnTamper = s }, "[warn deny deny-all quarantine]"},
	} {
		if v, ok := data[pair.key]; ok && v != nil {
			str := fmt.Sprintf("%v", v)
			if !pair.validSet[str] {
				errs = append(errs, fmt.Sprintf("%s must be one of %s, got %q", pair.key, pair.enumLabel, str))
				continue
			}
			pair.set(str)
		}
	}

	rulesRaw, ok := data["rules"]
	if !ok || rulesRaw == nil {
		errs = append(errs, "missing required field 'rules'")
	}
	rulesList, ok := rulesRaw.([]any)
	if !ok && rulesRaw != nil {
		errs = append(errs, fmt.Sprintf("'rules' must be a list, got %T", rulesRaw))
	} else if len(rulesList) == 0 && rulesRaw != nil {
		errs = append(errs, "'rules' must contain at least one rule")
	}

	if len(errs) > 0 {
		return ParsedPolicy{}, &PolicyValidationError{Errors: errs, Source: sourceLabel}
	}

	out := make([]PolicyRule, 0, len(rulesList))
	for i, raw := range rulesList {
		ruleMap, ok := raw.(map[string]any)
		if !ok {
			errs = append(errs, fmt.Sprintf("rules[%d]: must be a mapping, got %T", i, raw))
			continue
		}

		_, hasDeny := ruleMap["deny"]
		_, hasAllow := ruleMap["allow"]
		explicitEffect, hasExplicit := ruleMap["effect"].(string)

		var effect string
		var pattern any

		if hasExplicit {
			validEffects := map[string]bool{"allow": true, "deny": true, "warn": true, "audit": true}
			if !validEffects[explicitEffect] {
				errs = append(errs, fmt.Sprintf("rules[%d].effect: must be allow/deny/warn/audit, got %q", i, explicitEffect))
				continue
			}
			effect = explicitEffect
			pattern = ruleMap["action"]
			if pattern == nil {
				pattern = ruleMap["actions"]
			}
		} else if hasDeny && hasAllow {
			errs = append(errs, fmt.Sprintf("rules[%d]: cannot set both 'deny' and 'allow'", i))
			continue
		} else if hasDeny {
			effect = "deny"
			pattern = ruleMap["deny"]
		} else if hasAllow {
			effect = "allow"
			pattern = ruleMap["allow"]
		} else {
			errs = append(errs, fmt.Sprintf("rules[%d]: must specify one of 'deny', 'allow', or 'effect'", i))
			continue
		}

		if pattern == nil {
			errs = append(errs, fmt.Sprintf("rules[%d]: missing tool pattern", i))
			continue
		}

		var rawPatterns []string
		switch p := pattern.(type) {
		case string:
			rawPatterns = []string{p}
		case []any:
			for _, item := range p {
				s, ok := item.(string)
				if !ok {
					errs = append(errs, fmt.Sprintf("rules[%d]: pattern list must contain only strings", i))
					rawPatterns = nil
					break
				}
				rawPatterns = append(rawPatterns, s)
			}
		default:
			errs = append(errs, fmt.Sprintf("rules[%d]: pattern must be a string or list", i))
			continue
		}
		if rawPatterns == nil {
			continue
		}

		actions := make([]string, len(rawPatterns))
		for j, p := range rawPatterns {
			actions[j] = canonicalizeAction(p)
		}

		var resources []string
		if r, ok := ruleMap["resources"]; ok && r != nil {
			resources = toStringSlice(r)
		} else if r, ok := ruleMap["resource"]; ok && r != nil {
			resources = toStringSlice(r)
		}

		id := ""
		if v, ok := ruleMap["id"]; ok {
			id = fmt.Sprintf("%v", v)
		}
		name := ""
		if v, ok := ruleMap["name"]; ok {
			name = fmt.Sprintf("%v", v)
		}
		if name == "" {
			if id != "" {
				name = id
			} else {
				name = fmt.Sprintf("rule-%d", i)
			}
		}

		var conditions map[string]any
		if w, ok := ruleMap["when"].(map[string]any); ok {
			conditions = w
		} else if c, ok := ruleMap["conditions"].(map[string]any); ok {
			conditions = c
		}

		reasonStr := ""
		if r, ok := ruleMap["reason"]; ok && r != nil {
			reasonStr = fmt.Sprintf("%v", r)
		}

		// Carry reason_code through from the rule. Today the backend
		// bundle translator emits this on synthetic empty-bundle denies
		// (NO_ACTIVE_POLICIES). User-authored rules usually leave it
		// empty and the evaluator fills it in with RULE_MATCH on match.
		reasonCode := ""
		if rc, ok := ruleMap["reason_code"]; ok && rc != nil {
			reasonCode = fmt.Sprintf("%v", rc)
		}

		out = append(out, PolicyRule{
			ID:         id,
			Name:       name,
			Effect:     effect,
			Actions:    actions,
			Resources:  resources,
			Conditions: conditions,
			Reason:     reasonStr,
			ReasonCode: reasonCode,
		})
	}

	if len(errs) > 0 {
		return ParsedPolicy{}, &PolicyValidationError{Errors: errs, Source: sourceLabel}
	}

	return ParsedPolicy{Rules: out, Settings: settings}, nil
}

func toStringSlice(v any) []string {
	switch s := v.(type) {
	case string:
		return []string{s}
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	case []string:
		return append([]string{}, s...)
	}
	return nil
}
