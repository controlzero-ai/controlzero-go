package controlzero

import (
	"path"
)

// PolicyRule is the canonical internal representation of a single policy rule.
// The user-facing schema (see policy_loader.go) is friendlier; this is what
// the evaluator consumes after translation.
type PolicyRule struct {
	ID         string
	Name       string
	Effect     string // "allow" or "deny"
	Actions    []string
	Resources  []string
	Conditions map[string]any
	Reason     string // Human-readable explanation, surfaced in audit + denies
}

// PolicyEvaluator runs in-process. Fail-closed by default: if no rule matches,
// the call is denied.
//
// Pattern matching uses path.Match, which is Go's stdlib equivalent of
// fnmatch (case-sensitive shell glob). Friendly schema like "delete_*" is
// canonicalized to "delete_*:*" in policy_loader.go BEFORE rules reach
// this evaluator. By the time rules arrive here, every action is in
// canonical "tool:method" form.
type PolicyEvaluator struct {
	rules []PolicyRule
}

// NewPolicyEvaluator constructs an evaluator with an optional initial rule set.
func NewPolicyEvaluator(rules []PolicyRule) *PolicyEvaluator {
	return &PolicyEvaluator{rules: rules}
}

// Load replaces the rule set.
func (e *PolicyEvaluator) Load(rules []PolicyRule) {
	e.rules = rules
}

// EvalContext is optional context for resource-level matching.
type EvalContext struct {
	Resource string
	Tags     map[string]string
}

// Evaluate returns a PolicyDecision for the given tool/method. Always returns;
// never panics.
func (e *PolicyEvaluator) Evaluate(tool, method string, ctx *EvalContext) PolicyDecision {
	if method == "" {
		method = "*"
	}
	action := tool + ":" + method
	var resource string
	if ctx != nil {
		resource = ctx.Resource
	}

	evaluated := 0
	for _, rule := range e.rules {
		evaluated++
		if !globAny(rule.Actions, action) {
			continue
		}
		if len(rule.Resources) > 0 {
			if resource == "" || !globAny(rule.Resources, resource) {
				continue
			}
		}
		id := rule.ID
		if id == "" {
			id = rule.Name
		}
		// User-provided reason wins. Falls back to canned text only if the
		// rule had no `reason:` field in the source policy.
		reason := rule.Reason
		if reason == "" {
			reason = "Matched rule " + id
		}
		return PolicyDecision{
			Effect:         rule.Effect,
			PolicyID:       id,
			Reason:         reason,
			EvaluatedRules: evaluated,
		}
	}

	// Fail-closed default
	return PolicyDecision{
		Effect:         "deny",
		PolicyID:       "",
		Reason:         "No matching policy rule (fail-closed default)",
		EvaluatedRules: evaluated,
	}
}

// globAny reports whether any pattern matches value via path.Match.
//
// path.Match is the Go stdlib glob matcher. It is case-sensitive and supports
// *, ?, and character classes -- the same syntax users learn from .gitignore.
// Critically, * does NOT match path separators in path.Match, but our patterns
// use ":" as a separator (not "/"), so the standard ":" handling is fine.
func globAny(patterns []string, value string) bool {
	for _, p := range patterns {
		ok, err := path.Match(p, value)
		if err == nil && ok {
			return true
		}
	}
	return false
}
