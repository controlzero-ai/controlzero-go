// Package controlzero is the Go SDK for Control Zero AI agent governance.
//
// It provides policies, audit, and observability for tool calls. Works
// locally with no signup.
package controlzero

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// PolicyDecision is the result of evaluating a tool call against a policy.
//
// ReasonCode is a machine-readable, cross-language enum value drawn
// from the constants in reason_codes.go (RULE_MATCH, NO_RULE_MATCH,
// NO_ACTIVE_POLICIES, BUNDLE_MISSING, BUNDLE_TAMPERED,
// MACHINE_QUARANTINED, NETWORK_ERROR, DLP_BLOCKED). Automation should
// branch on ReasonCode, not on Reason -- Reason is free text that may
// be re-worded between releases. Empty string when the decision
// predates #228 Phase 2 or when a user-authored rule did not declare
// a reason_code of its own.
type PolicyDecision struct {
	Effect         string // "allow", "deny", "warn", "audit"
	PolicyID       string
	Reason         string
	ReasonCode     string
	EvaluatedRules int
	// Phase 1B (#451). Engine version that produced this decision.
	// Stamped on every PolicyDecision returned by the SDK. The audit
	// pipeline mirrors the same value onto the audit row, so a stale
	// SDK install shows up as a row whose engine bytes lag the live
	// backend.
	PolicyEngineVersion string
	// GateMatched is the multi-client + per-project rule selectors
	// audit column (gh#175 outside-voice P1.1). One of:
	//   "none"    - rule had no selectors (legacy rule) OR no rule fired
	//   "client"  - rule had only `clients:` set and it matched
	//   "project" - rule had only `projects:` set and it matched
	//   "both"    - rule had both, both matched
	//
	// The Go SDK enforcer does not yet evaluate selectors (tracked
	// under the gh#175 Go SDK port slice); until that lands, every
	// Go decision carries GateMatched="none". The column exists
	// today so the cross-SDK audit shape is invariant: dashboards
	// can always SELECT gate_matched without special-casing by
	// surface.
	GateMatched string

	// RequiresApproval indicates the policy engine decided this call
	// needs a human-in-the-loop grant before it can proceed. HITL
	// Phase 2d (Go-SDK port). Defaults to false (omitempty in any
	// JSON serialisation downstream), so older callers and rules that
	// never set the field keep their pre-2d behaviour exactly.
	RequiresApproval bool
	// ApprovalAction is the canonical action label the SDK ships to
	// the grants endpoint when RequiresApproval is true. Pointer so a
	// nil value is distinguishable from a deliberate empty string
	// (the wire shape omits the field on nil). Mirrors the optional
	// approval_action attribute on the Python and Node LLM decision
	// envelopes.
	ApprovalAction *string

	// SemanticClass is the #350 portable SQL semantic class
	// (read|write|admin|exec) the call resolved to, or "" for non-SQL
	// calls. Surfaced onto the audit row as action_semantic_class so a
	// dashboard can filter on the dialect-independent class. Mirrors
	// decision.semantic_class on the Python + Node decision envelopes.
	SemanticClass string
}

// PolicyEngineVersion is the version of the policy engine the SDK is
// wired to. Kept in lockstep with crates/Cargo.toml workspace.package
// version. When the WASM engine ships in Phase 8 this becomes
// runtime-derived from the loaded engine bundle. Mirrors
// POLICY_ENGINE_VERSION in the Python SDK and the
// POLICY_ENGINE_VERSION export in the Node SDK.
//
// Drift CI: scripts/ci/check-engine-version-drift.sh asserts this
// literal matches the Rust workspace version on every CI run.
//
// Naming note: shares the bare name with PolicyDecision.PolicyEngineVersion.
// Inside the package this is unambiguous (Go resolves field name vs
// package-level identifier by syntactic position). Renaming the field
// would be a breaking API change; renaming the constant to anything
// other than the field name re-introduces the Python/Node mismatch
// reviewers complained about.
const PolicyEngineVersion = "0.1.0"

// Decision returns Effect. Reads more naturally in user code.
func (d PolicyDecision) Decision() string { return d.Effect }

// Allowed reports whether the call was allowed.
func (d PolicyDecision) Allowed() bool { return d.Effect == "allow" }

// Denied reports whether the call was denied.
func (d PolicyDecision) Denied() bool { return d.Effect == "deny" }

// PolicyDeniedError is returned by Guard when a deny decision is reached AND
// the caller passed RaiseOnDeny.
type PolicyDeniedError struct {
	Decision PolicyDecision
}

func (e *PolicyDeniedError) Error() string {
	reason := e.Decision.Reason
	if reason == "" {
		reason = "no reason provided"
	}
	return "policy denied: " + reason
}

// Is lets `errors.Is(err, controlzero.ErrPolicyDenied)` trip on any
// static deny outcome. HITL deny-class errors (HITLTimeoutError,
// HITLNoApproverAvailable, HITLIdentityClaimRejected,
// SecretApprovalRequired) implement the same contract so a single
// errors.Is check covers every denial path.
func (e *PolicyDeniedError) Is(target error) bool {
	return target == ErrPolicyDenied
}

// PolicyValidationError is returned when a policy file or map fails schema validation.
type PolicyValidationError struct {
	Errors []string
	Source string
}

func (e *PolicyValidationError) Error() string {
	src := e.Source
	if src == "" {
		src = "<unknown>"
	}
	return fmt.Sprintf(
		"policy validation failed for %s:\n  - %s",
		src,
		strings.Join(e.Errors, "\n  - "),
	)
}

// PolicyLoadError is returned when a policy file cannot be loaded.
type PolicyLoadError struct {
	Message string
	Source  string
	Cause   error
}

func (e *PolicyLoadError) Error() string {
	full := fmt.Sprintf("%s (source: %s)", e.Message, e.Source)
	if e.Cause != nil {
		full += fmt.Sprintf("\n  caused by: %v", e.Cause)
	}
	return full
}

func (e *PolicyLoadError) Unwrap() error { return e.Cause }

// HostedModeNotImplemented is returned when an API key is set but no local
// policy is provided. Hosted mode is not yet implemented in this slim
// package; users should provide a local policy or use the legacy SDK.
var ErrHostedModeNotImplemented = errors.New(
	"controlzero: hosted mode (dashboard policies + remote audit) is not yet implemented in this package.\n" +
		"  - For local mode, provide a policy: controlzero.New(controlzero.WithPolicy(...))\n" +
		"  - For hosted mode today, use the legacy SDK at sdks/go/control-zero\n" +
		"  - Hosted mode in this package is coming in a future release.",
)

// ErrHybridMode is returned when an API key and local policy are both
// provided AND WithStrictHosted was set. T103: message reworded from
// "manual policy override detected" to "explicit local policy overrides
// the hosted bundle". Semantics unchanged.
var ErrHybridMode = errors.New(
	"controlzero: explicit local policy overrides the hosted bundle (strict_hosted=true)",
)

// defaultAuthRemediation is the copy-pasteable next step shown when the
// backend sends no structured 401 body.
const defaultAuthRemediation = "Generate a new API key in the dashboard " +
	"(Settings -> API Keys, https://app.controlzero.ai/settings/api-keys) " +
	"and set CONTROLZERO_API_KEY to it."

// HostedAuthError is returned when the project API key is rejected by
// the backend (401/403). Permanent: retrying with the same key will not
// help. Maps to E1101.
//
// #1254: the bare "API key rejected (401)" gave the user no idea
// WHY or what to do. The Error() string now always says the key is
// invalid/revoked/expired and how to fix it. When the backend supplies a
// structured 401 body, Reason + Remediation are preserved so programmatic
// callers can branch on Reason while humans read the actionable message.
// The backend keeps Reason coarse on purpose (not_found / revoked /
// expired / placeholder all collapse to "invalid_or_revoked") so a 401 is
// never an enumeration oracle; the SDK does not try to refine it.
type HostedAuthError struct {
	// Msg is the headline. When empty, a default actionable headline is used.
	Msg string
	// Reason is the coarse machine-readable reason from the backend, or ""
	// when the backend sent no structured body (older backend).
	Reason string
	// Remediation is the copy-pasteable next step. Defaults to
	// defaultAuthRemediation when empty.
	Remediation string
}

func (e *HostedAuthError) Error() string {
	headline := e.Msg
	if headline == "" {
		headline = "Your Control Zero API key was rejected by the backend " +
			"(invalid, revoked, or expired)."
	}
	remediation := e.Remediation
	if remediation == "" {
		remediation = defaultAuthRemediation
	}
	return "controlzero: " + headline + " " + remediation
}

// newHostedAuthError builds a HostedAuthError from a backend 401/403 body.
// body is the raw response bytes; a non-JSON or empty body just yields the
// actionable default (never panics). context is an optional phrase like
// "during bundle pull" added to the headline. The structured fields may be
// at the top level (reason) or nested under "error"; both are read.
func newHostedAuthError(body []byte, context string) *HostedAuthError {
	var reason, remediation, backendMsg string
	if len(body) > 0 {
		var parsed struct {
			Reason      string `json:"reason"`
			Remediation string `json:"remediation"`
			Message     string `json:"message"`
			Error       struct {
				Reason      string `json:"reason"`
				Remediation string `json:"remediation"`
				Message     string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &parsed); err == nil {
			reason = firstNonEmpty(parsed.Reason, parsed.Error.Reason)
			remediation = firstNonEmpty(parsed.Remediation, parsed.Error.Remediation)
			backendMsg = firstNonEmpty(parsed.Message, parsed.Error.Message)
		}
		// Back-compat: some backends put a plain string in the top-level
		// "error" key (e.g. {"error":"key revoked"}) instead of the nested
		// object. Read it as the backend message when present so its text is
		// still surfaced. (Our own coarse backend never sends such a string;
		// it uses the structured object above.)
		if backendMsg == "" {
			var topErr struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(body, &topErr); err == nil {
				backendMsg = topErr.Error
			}
		}
	}

	headline := "Your Control Zero API key was rejected by the backend (invalid, revoked, or expired)."
	if context != "" {
		headline = "Your Control Zero API key was rejected by the backend " + context + " (invalid, revoked, or expired)."
	}
	if backendMsg != "" && backendMsg != "invalid API key" {
		headline = headline + " (backend: " + backendMsg + ")"
	}
	return &HostedAuthError{Msg: headline, Reason: reason, Remediation: remediation}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// HostedBootstrapError is returned when hosted mode cannot initialize
// (backend unreachable, malformed response, etc.) AND no cached bundle
// is available. The SDK fails closed: without a valid policy, New()
// refuses to construct.
type HostedBootstrapError struct{ Msg string }

func (e *HostedBootstrapError) Error() string { return "controlzero: " + e.Msg }

// BundleFormatError wraps a bundle wire-format problem surfaced to the
// user. Distinct from bundle signature/crypto failures.
type BundleFormatError struct{ Msg string }

func (e *BundleFormatError) Error() string { return "controlzero: " + e.Msg }

// BundleSignatureError wraps a signature/AEAD failure surfaced to the
// user. Fails closed -- the bundle is untrusted.
type BundleSignatureError struct{ Msg string }

func (e *BundleSignatureError) Error() string { return "controlzero: " + e.Msg }

// --- Multi-client + per-project selectors (#175 / #602 follow-up) ---------
//
// gh#602 ships the min_sdk_version gate that pairs with the rule
// selectors introduced in PR #601. Bundles that include any rule with
// `clients:` / `projects:` selectors carry `metadata.min_sdk_version`;
// the Go SDK compares this against `controlzero.Version` at load time
// and returns BundleRequiresNewerSDKError when the SDK is older.

// ECodeBundleRequiresNewerSDK is the stable E#### code emitted on
// every BundleRequiresNewerSDKError. Mirrors the Python + Node
// catalog so customers see the same docs URL regardless of which
// SDK they tripped the gate on.
const ECodeBundleRequiresNewerSDK = "E1712"

// BundleRequiresNewerSDKError is returned when the hosted policy
// bundle's metadata.min_sdk_version declares a higher SDK floor than
// the SDK shipping in this binary. The bundle uses post-#175 rule
// selectors (clients / projects) this SDK does not understand;
// loading it would silently treat the selectors as wildcards
// (over-block every unselected agent), so the SDK refuses the bundle
// instead.
//
// Required / Actual / UpgradeCommand together give the customer
// everything they need to self-serve the upgrade without filing
// support. Per gh#602 hard limit on the error contract.
type BundleRequiresNewerSDKError struct {
	Required        string
	Actual          string
	UpgradeCommand  string
}

func (e *BundleRequiresNewerSDKError) Error() string {
	return fmt.Sprintf(
		"controlzero: bundle requires controlzero SDK >= %s; this SDK is %s. Upgrade with: %s.",
		e.Required, e.Actual, e.UpgradeCommand,
	)
}

// ECode returns the stable E#### code for this error. Callers that
// want to branch on the error class without an errors.As dance can
// read this field directly.
func (e *BundleRequiresNewerSDKError) ECode() string { return ECodeBundleRequiresNewerSDK }

// --- Credential leak detection (epic #666, PR-4) --------------------------
//
// CredentialLeakBlockedError is returned by the credential leak hook
// `hooks.OnToolOutput(...)` when the configured Action is
// hooks.ActionBlock and the scanner finds at least one credential
// match. Maps to E2001 -- the same code Python uses for cross-SDK
// parity. The audit row is emitted BEFORE this error is returned so
// the operator dashboard always sees the detection even when the
// agent never observes the redacted output.

// ECodeCredentialLeakBlocked is the stable E#### code for credential
// leak block. Matches the Python CredentialLeakBlocked.E_CODE.
const ECodeCredentialLeakBlocked = "E2001"

// CredentialLeakBlockedError is the typed Go counterpart of the
// Python CredentialLeakBlocked exception. Carries the credential
// match count plus the originating source / tool labels for callers
// that want to log or surface the detection without reflecting on
// the raw sentinel error.
//
// Callers can match either by type (errors.As against this type) or
// by sentinel (errors.Is against hooks.ErrCredentialLeakBlocked); the
// hook's Handle method returns an fmt.Errorf chain that satisfies
// both contracts.
type CredentialLeakBlockedError struct {
	// MatchCount is the number of credential matches the scanner
	// reported on the inspected tool output.
	MatchCount int
	// Source labels the origin of the inspected text (tool_output,
	// tool_stderr, file_read, grep_match).
	Source string
	// ToolName is the agent-side tool that produced the inspected
	// text.
	ToolName string
}

func (e *CredentialLeakBlockedError) Error() string {
	return fmt.Sprintf(
		"controlzero: credential leak detected; tool output blocked (code=%s, source=%s, tool=%s, matches=%d)",
		ECodeCredentialLeakBlocked, e.Source, e.ToolName, e.MatchCount,
	)
}

// ECode returns the stable E#### code for credential leak block.
func (e *CredentialLeakBlockedError) ECode() string { return ECodeCredentialLeakBlocked }
