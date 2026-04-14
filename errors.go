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
type PolicyDecision struct {
	Effect         string // "allow", "deny", "warn", "audit"
	PolicyID       string
	Reason         string
	EvaluatedRules int
}

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
// provided AND WithStrictHosted was set.
var ErrHybridMode = errors.New(
	"controlzero: manual policy override detected (strict_hosted=true)",
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
