package controlzero

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadPolicy parses a policy from a map[string]any (in-memory) or a path
// (string ending in .yaml/.yml/.json). Returns the canonicalized rule list
// or a *PolicyValidationError / *PolicyLoadError on failure.
func LoadPolicy(source any) ([]PolicyRule, error) {
	switch s := source.(type) {
	case map[string]any:
		return validateAndTranslate(s, "<map>")
	case string:
		return loadFromFile(s)
	default:
		return nil, &PolicyLoadError{
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

func loadFromFile(path string) ([]PolicyRule, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, &PolicyLoadError{
			Message: "policy file not found: " + path,
			Source:  path,
		}
	}

	suffix := strings.ToLower(filepath.Ext(path))
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, &PolicyLoadError{
			Message: "cannot read policy file",
			Source:  path,
			Cause:   err,
		}
	}

	var data any

	switch suffix {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(text, &data); err != nil {
			return nil, &PolicyLoadError{
				Message: "YAML parse error: " + err.Error(),
				Source:  path,
				Cause:   err,
			}
		}
	case ".json":
		if err := json.Unmarshal(text, &data); err != nil {
			return nil, &PolicyLoadError{
				Message: "JSON parse error: " + err.Error(),
				Source:  path,
				Cause:   err,
			}
		}
	default:
		return nil, &PolicyLoadError{
			Message: "unsupported file format: " + suffix + " (use .yaml, .yml, or .json)",
			Source:  path,
		}
	}

	if data == nil {
		return nil, &PolicyValidationError{
			Errors: []string{"policy file is empty"},
			Source: path,
		}
	}
	dataMap, ok := normalizeToStringMap(data).(map[string]any)
	if !ok {
		return nil, &PolicyValidationError{
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

func validateAndTranslate(data map[string]any, sourceLabel string) ([]PolicyRule, error) {
	var errs []string

	version := "1"
	if v, ok := data["version"]; ok {
		version = fmt.Sprintf("%v", v)
	}
	if version != "1" {
		errs = append(errs, fmt.Sprintf("unsupported version %q, expected \"1\"", version))
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
		return nil, &PolicyValidationError{Errors: errs, Source: sourceLabel}
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

		out = append(out, PolicyRule{
			ID:         id,
			Name:       name,
			Effect:     effect,
			Actions:    actions,
			Resources:  resources,
			Conditions: conditions,
			Reason:     reasonStr,
		})
	}

	if len(errs) > 0 {
		return nil, &PolicyValidationError{Errors: errs, Source: sourceLabel}
	}

	return out, nil
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
