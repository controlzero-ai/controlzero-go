// Package controlzero is the Go SDK for Control Zero AI agent governance.
//
// It provides policies, audit, and observability for tool calls. Works
// locally with no signup.
package controlzero

import (
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

// HostedAuthError is returned when the project API key is rejected by
// the backend (401/403). Permanent: retrying with the same key will not
// help.
type HostedAuthError struct{ Msg string }

func (e *HostedAuthError) Error() string { return "controlzero: " + e.Msg }

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
