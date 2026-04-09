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
