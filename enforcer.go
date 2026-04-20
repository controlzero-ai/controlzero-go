package controlzero

import (
	"path"
)

// PolicyRule is the canonical internal representation of a single policy rule.
// The user-facing schema (see policy_loader.go) is friendlier; this is what
// the evaluator consumes after translation.
//
// ReasonCode is an optional rule-level override of the emitted
// reason_code. Today the backend bundle translator stamps it on
// synthetic empty-bundle denies (NO_ACTIVE_POLICIES); user-authored
// rules usually leave it empty and the evaluator fills it with
// RULE_MATCH on match.
type PolicyRule struct {
	ID         string
	Name       string
	Effect     string // "allow" or "deny"
	Actions    []string
	Resources  []string
	Conditions map[string]any
	Reason     string // Human-readable explanation, surfaced in audit + denies
	ReasonCode string // Machine-readable code (see reason_codes.go)
}

// PolicyEvaluator runs in-process. Fail-closed by default: if no rule
// matches AND no default_action was provided, the call is denied.
//
// Pattern matching uses path.Match, which is Go's stdlib equivalent of
// fnmatch (case-sensitive shell glob). Friendly schema like "delete_*"
// is canonicalized to "delete_*:*" in policy_loader.go BEFORE rules
// reach this evaluator. By the time rules arrive here, every action is
// in canonical "tool:method" form.
//
// defaultAction controls the no-match path (added in #228 Phase 2):
//
//	""     -> fall back to "deny" with ReasonCodeNoRuleMatch (legacy /
//	           fail-closed contract; matches pre-Phase-2 behaviour).
//	"deny" -> deny + ReasonCodeNoRuleMatch.
//	"allow" -> allow + ReasonCodeNoRuleMatch.
//	"warn" -> warn + ReasonCodeNoRuleMatch (effect "warn"; caller
//	           decides whether to fire).
//	any other value -> treated as empty; fall back to deny. This is
//	defensive: a corrupt or future-version bundle MUST NOT flip an
//	org from deny to allow through a typo.
type PolicyEvaluator struct {
	rules         []PolicyRule
	defaultAction string
}

// NewPolicyEvaluator constructs an evaluator with an optional initial rule set.
// defaultAction is left empty, which keeps the legacy fail-closed
// contract (deny on no-match). Use NewPolicyEvaluatorWithSettings to
// honour a bundle's default_action.
func NewPolicyEvaluator(rules []PolicyRule) *PolicyEvaluator {
	return &PolicyEvaluator{rules: rules}
}

// NewPolicyEvaluatorWithSettings constructs an evaluator that honours
// the per-bundle settings block. If settings.DefaultAction is empty or
// unknown, the evaluator falls back to deny (fail-closed contract).
func NewPolicyEvaluatorWithSettings(rules []PolicyRule, settings PolicySettings) *PolicyEvaluator {
	return &PolicyEvaluator{
		rules:         rules,
		defaultAction: settings.DefaultAction,
	}
}

// Load replaces the rule set.
func (e *PolicyEvaluator) Load(rules []PolicyRule) {
	e.rules = rules
}

// SetDefaultAction sets the no-match default. Accepts "deny" / "allow"
// / "warn"; any other value (including empty) reverts to the
// fail-closed contract.
func (e *PolicyEvaluator) SetDefaultAction(action string) {
	e.defaultAction = action
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
		// Carry forward a rule-level reason_code if one was set
		// (e.g. the backend's synthetic NO_ACTIVE_POLICIES deny).
		// Otherwise label the match with the canonical RULE_MATCH.
		rc := rule.ReasonCode
		if rc == "" {
			rc = ReasonCodeRuleMatch
		}
		return PolicyDecision{
			Effect:         rule.Effect,
			PolicyID:       id,
			Reason:         reason,
			ReasonCode:     rc,
			EvaluatedRules: evaluated,
		}
	}

	// No rule matched. Honour the bundle's default_action if one is
	// set AND is a known value. Any other value reverts to the legacy
	// fail-closed contract: a corrupt or future-schema bundle MUST
	// NOT flip an org from deny to allow through a typo.
	effect := "deny"
	reason := "No matching policy rule (fail-closed default)"
	switch e.defaultAction {
	case "allow":
		effect = "allow"
		reason = "No matching policy rule (default_action=allow)"
	case "warn":
		effect = "warn"
		reason = "No matching policy rule (default_action=warn)"
	case "deny", "":
		// Explicit or legacy fail-closed. Reason already set above.
	default:
		// Unknown value -> fail-closed. Do not silently allow.
	}

	return PolicyDecision{
		Effect:         effect,
		PolicyID:       "",
		Reason:         reason,
		ReasonCode:     ReasonCodeNoRuleMatch,
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
