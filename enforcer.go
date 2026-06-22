package controlzero

import (
	"path"
	"strings"

	"controlzero.ai/sdk/go/internal/hookextractors"
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

	// ReasonLocalized is a locale-keyed override of Reason (
	// #25, gh#1439). A {locale: message} map. When CONTROLZERO_LOCALE
	// selects a locale present here, the evaluator surfaces that
	// message instead of Reason. Empty / missing key => fall back to
	// Reason (plain English / operator text), so existing reason-regex
	// consumers are unaffected. Additive contract: NO BREAKING CHANGES.
	ReasonLocalized map[string]string

	// EscalateOnDeny is the HITL escalation tag (HITL-5c, gh#540):
	// when true and the rule's effect is `deny`, future SDK versions
	// will mark the resulting PolicyDecision as hitl_eligible=true.
	// The actual approval-request flow ships in v1.8.0 (HITL-6a,
	// gh#542); v1.7.6 just acknowledges the field so a customer
	// pre-tagging rules for HITL does not crash an old client.
	EscalateOnDeny bool
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
	// locale is the active reason-localization locale (#25,
	// gh#1439). "" means English (the default); reason text is then
	// byte-identical to the pre-localization SDK so existing
	// reason-regex consumers are unaffected. Read from
	// CONTROLZERO_LOCALE at construction.
	locale string
}

// NewPolicyEvaluator constructs an evaluator with an optional initial rule set.
// defaultAction is left empty, which keeps the legacy fail-closed
// contract (deny on no-match). Use NewPolicyEvaluatorWithSettings to
// honour a bundle's default_action.
func NewPolicyEvaluator(rules []PolicyRule) *PolicyEvaluator {
	return &PolicyEvaluator{rules: rules, locale: ResolveLocale("")}
}

// NewPolicyEvaluatorWithSettings constructs an evaluator that honours
// the per-bundle settings block. If settings.DefaultAction is empty or
// unknown, the evaluator falls back to deny (fail-closed contract).
func NewPolicyEvaluatorWithSettings(rules []PolicyRule, settings PolicySettings) *PolicyEvaluator {
	return &PolicyEvaluator{
		rules:         rules,
		defaultAction: settings.DefaultAction,
		locale:        ResolveLocale(""),
	}
}

// SetLocale sets the active reason-localization locale (#25,
// gh#1439). "" forces English. Display-only: never changes which rule
// matches or the effect, only the reason text.
func (e *PolicyEvaluator) SetLocale(locale string) {
	e.locale = ResolveLocale(locale)
}

// Locale returns the effective reason-localization locale ("" == English).
func (e *PolicyEvaluator) Locale() string {
	return e.locale
}

// resolveReason resolves the human-readable reason for a matched rule,
// localized. Priority (#25, gh#1439):
// rule.ReasonLocalized[locale] -> synthetic-rule system override by
// reason_code -> plain rule.Reason -> canned. English/unset locale
// returns rule.Reason unchanged.
func (e *PolicyEvaluator) resolveReason(rule PolicyRule, id string) string {
	loc := e.locale
	if loc != "" && loc != "en" {
		if rule.ReasonLocalized != nil {
			if msg, ok := rule.ReasonLocalized[loc]; ok && msg != "" {
				return msg
			}
			primary := loc
			for _, sep := range []string{"-", "_"} {
				if idx := strings.Index(primary, sep); idx > 0 {
					primary = primary[:idx]
					break
				}
			}
			if msg, ok := rule.ReasonLocalized[primary]; ok && msg != "" {
				return msg
			}
		}
		if strings.HasPrefix(rule.ID, "synthetic:") && rule.ReasonCode != "" {
			if msg, ok := localizedOverride(rule.ReasonCode, loc); ok {
				return msg
			}
		}
	}
	if rule.Reason != "" {
		return rule.Reason
	}
	return "Matched rule " + id
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
//
// gh#175 P1.1: ClientName and ProjectID are part of the audit trail
// for the multi-client + per-project rule selectors. The Go enforcer
// does NOT yet gate on these fields (selector evaluation is tracked
// under the gh#175 Go SDK port slice); they are surfaced into the
// audit row so the cross-SDK audit shape is invariant and dashboards
// can SELECT client_name / project_id without special-casing the Go
// surface. Empty string means "no value detected".
type EvalContext struct {
	Resource   string
	Tags       map[string]string
	ClientName string
	ProjectID  string
	// ActionSemanticClass is the #350 portable SQL class
	// (read|write|admin|exec) precomputed by a caller -- e.g. the
	// hook-check CLI, which resolves the canonical tool and the class
	// before reaching the evaluator. When set it takes precedence over
	// the in-core derivation from args["sql"]. Mirrors the Python +
	// Node evaluator's context["action_semantic_class"] input.
	ActionSemanticClass string
}

// Evaluate returns a PolicyDecision for the given tool/method. Always
// returns; never panics. Back-compat wrapper that routes through the
// shared core (EvaluateWithArgs) with no args, so the single derivation
// path is the only path -- callers with a SQL payload should prefer
// EvaluateWithArgs so the #350 semantic class is derived in the CORE.
func (e *PolicyEvaluator) Evaluate(tool, method string, ctx *EvalContext) PolicyDecision {
	return e.EvaluateWithArgs(tool, method, nil, ctx)
}

// EvaluateWithArgs is the #362 P1-1 shared evaluator CORE path: it accepts
// the raw tool args and derives the #350 SQL semantic class INSIDE the
// evaluator, byte-identical to the Python + Node enforcers
// (PolicyEvaluator.evaluate(tool, method, context, args)). Two sources for
// the class action, in priority order:
//
//  1. ctx.ActionSemanticClass (a caller -- e.g. the hook-check CLI -- that
//     already resolved the canonical tool + class), then
//  2. derive on the fly from args["sql"] when the tool is exactly
//     "database" and the arg is a non-empty SQL string.
//
// This matches Python/Node EXACTLY: the literal "database" tool is the
// trigger (the SDK guard() path does NOT alias-resolve here -- alias
// resolution is the hook-check CLI's job, which then feeds
// ActionSemanticClass). The derived class is surfaced onto the returned
// decision.SemanticClass so the audit row is identical regardless of which
// entry point the caller used, and a rule that matches EITHER the
// per-keyword action (database:DROP) OR the class action (database:admin)
// fires. Always returns; never panics.
func (e *PolicyEvaluator) EvaluateWithArgs(tool, method string, args map[string]any, ctx *EvalContext) PolicyDecision {
	semanticClass, semanticAction := e.deriveSemanticClass(tool, args, ctx)
	decision := e.evaluateAction(tool, method, semanticAction, ctx)
	decision.SemanticClass = semanticClass
	return decision
}

// deriveSemanticClass computes the #350 portable SQL class and the
// corresponding class-action string for a call, mirroring the
// Python/Node evaluator derivation exactly. Returns ("", "") for non-SQL
// calls. semanticAction is "tool:class" (only when distinct from the
// per-keyword action). Kept in the CORE so every entry point -- Evaluate,
// EvaluateWithArgs, EvaluateWithSemanticClass -- shares one derivation.
func (e *PolicyEvaluator) deriveSemanticClass(tool string, args map[string]any, ctx *EvalContext) (semanticClass, semanticAction string) {
	// Priority 1: a caller-precomputed class action (hook-check CLI).
	if ctx != nil && ctx.ActionSemanticClass != "" {
		semanticAction = ctx.ActionSemanticClass
		// Recover the bare class (everything after the last ':') so the
		// audit row's decision.SemanticClass matches Python/Node.
		if idx := strings.LastIndex(semanticAction, ":"); idx >= 0 && idx+1 < len(semanticAction) {
			semanticClass = semanticAction[idx+1:]
		} else {
			semanticClass = semanticAction
		}
		return semanticClass, semanticAction
	}
	// Priority 2: derive from args["sql"] for the literal "database" tool,
	// byte-identical to Python (`tool == "database" and args`) and Node
	// (`tool === 'database' && typeof args.sql === 'string'`).
	if tool != "database" || args == nil {
		return "", ""
	}
	sqlVal, ok := args["sql"]
	if !ok {
		return "", ""
	}
	sqlText, ok := sqlVal.(string)
	if !ok || sqlText == "" {
		return "", ""
	}
	cls := hookextractors.SQLSemanticClass(sqlText)
	if cls == "" {
		return "", ""
	}
	return cls, tool + ":" + cls
}

// EvaluateWithSemanticClass is Evaluate plus the #350 SQL semantic-class
// layer with a caller-precomputed class action. semanticAction is the
// portable parallel action a database call resolves to
// (database:read|write|admin|exec); pass "" for non-SQL calls. When
// non-empty, a rule that matches EITHER the per-keyword action
// (database:DROP) OR the semantic-class action (database:admin) fires.
//
// Retained for back-compat; prefer EvaluateWithArgs, which derives the
// class in the CORE from the raw args so no caller has to precompute it.
// Mirrors the Python + Node evaluator change shipped in #350.
func (e *PolicyEvaluator) EvaluateWithSemanticClass(tool, method, semanticAction string, ctx *EvalContext) PolicyDecision {
	decision := e.evaluateAction(tool, method, semanticAction, ctx)
	// Surface the bare class onto the decision so the audit shape matches
	// the EvaluateWithArgs path even when the caller precomputed the
	// action. (database:read -> "read")
	if semanticAction != "" {
		if idx := strings.LastIndex(semanticAction, ":"); idx >= 0 && idx+1 < len(semanticAction) {
			decision.SemanticClass = semanticAction[idx+1:]
		}
	}
	return decision
}

func (e *PolicyEvaluator) evaluateAction(tool, method, semanticAction string, ctx *EvalContext) PolicyDecision {
	if method == "" {
		method = "*"
	}
	action := tool + ":" + method
	var resource string
	if ctx != nil {
		resource = ctx.Resource
	}

	// T84: expand candidate actions through the legacy <-> canonical
	// alias table so pre-#350 customer rules using legacy database
	// action names (database:query, database:DROP, database:execute,
	// ...) keep matching modern SDK calls that emit canonical
	// semantic classes (database:read|write|admin|exec), and vice
	// versa. NO BREAKING CHANGES contract -- see #389.
	seedActions := []string{action}
	// #350 semantic-class layer: the portable database:<class> action is
	// matched alongside the per-keyword action. Expanded through the same
	// alias table so a rule written either way still fires. The
	// per-keyword action stays FIRST so it takes precedence in the
	// candidate ordering.
	if semanticAction != "" && semanticAction != action {
		seedActions = append(seedActions, semanticAction)
	}
	candidateActions := ExpandCandidateActions(seedActions)

	evaluated := 0
	// T79: track the T83-class signature so the no-match path can be
	// labelled RESOURCE_GATE_SKIP rather than the generic NO_RULE_MATCH.
	actionMatchedAny := false
	actionMatchedResourceSkipped := false
	for _, rule := range e.rules {
		evaluated++
		matched := false
		for _, ca := range candidateActions {
			if globAny(rule.Actions, ca) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		actionMatchedAny = true
		if len(rule.Resources) > 0 {
			// T83: a rule whose Resources list contains "*" matches
			// universally and must NOT require the caller to supply
			// EvalContext.Resource. The dashboard always emits
			// resources:["*"] for unscoped rules; pre-T83 every
			// guard call without an explicit resource skipped every
			// rule and fell through to the default deny.
			hasUniversal := false
			for _, p := range rule.Resources {
				if p == "*" {
					hasUniversal = true
					break
				}
			}
			if !hasUniversal {
				if resource == "" || !globAny(rule.Resources, resource) {
					actionMatchedResourceSkipped = true
					continue
				}
			}
		}
		id := rule.ID
		if id == "" {
			id = rule.Name
		}
		// User-provided reason wins, localized when CONTROLZERO_LOCALE selects
		// a locale the rule (or system pack) has copy for. Falls back to the
		// plain reason / canned text, so English output is byte-identical to
		// before (#25, gh#1439).
		reason := e.resolveReason(rule, id)
		// Carry forward a rule-level reason_code if one was set
		// (e.g. the backend's synthetic NO_ACTIVE_POLICIES deny).
		// Otherwise label the match with the canonical RULE_MATCH.
		rc := rule.ReasonCode
		if rc == "" {
			rc = ReasonCodeRuleMatch
		}
		return PolicyDecision{
			Effect:              rule.Effect,
			PolicyID:            id,
			Reason:              reason,
			ReasonCode:          rc,
			EvaluatedRules:      evaluated,
			PolicyEngineVersion: PolicyEngineVersion,
		}
	}

	// No rule matched. Honour the bundle's default_action if one is
	// set AND is a known value. Any other value reverts to the legacy
	// fail-closed contract: a corrupt or future-schema bundle MUST
	// NOT flip an org from deny to allow through a typo.
	effect := "deny"
	switch e.defaultAction {
	case "allow":
		effect = "allow"
	case "warn":
		effect = "warn"
	case "deny", "":
		// Explicit or legacy fail-closed.
	default:
		// Unknown value -> fail-closed. Do not silently allow.
	}

	// #25 (gh#1439): the variant strings live in the in-binary
	// message pack keyed by NO_RULE_MATCH:<effect>. English values are
	// byte-identical to the legacy Go strings (so this is a no-op when
	// CONTROLZERO_LOCALE is unset); with ko set the Korean variant surfaces.
	// effect is always one of deny/allow/warn here, so the key always
	// resolves; the literal is a defensive fallback only.
	reason, ok := systemMessage("NO_RULE_MATCH:"+effect, e.locale)
	if !ok {
		reason = "No matching policy rule (fail-closed default)"
	}

	// T79: distinguish the T83-class signature ("a rule's actions
	// matched but its resources gate excluded the call") from the
	// generic no-match. Both still apply default_action; the synthetic
	// PolicyID is what the audit dashboard reads to surface the right
	// remediation chip + tooltip.
	syntheticID := SyntheticPolicyIDNoRuleMatch
	if effect == "deny" && actionMatchedAny && actionMatchedResourceSkipped {
		syntheticID = SyntheticPolicyIDResGateSkip
	}

	return PolicyDecision{
		Effect:              effect,
		PolicyID:            syntheticID,
		Reason:              reason,
		ReasonCode:          ReasonCodeNoRuleMatch,
		EvaluatedRules:      evaluated,
		PolicyEngineVersion: PolicyEngineVersion,
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
