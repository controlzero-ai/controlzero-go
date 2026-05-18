// HITL-6c (gh#542 / #578 Go-SDK parity).
//
// 11 HITL exception types mirroring Python's controlzero.errors:
//
//	HITLTimeoutError              -> PolicyDeniedError (wraps)
//	HITLBackendUnreachableError   -> HostedBootstrapError (wraps)
//	HITLPolicyVersionConflictError-> HybridModeError (wraps)
//	HITLNotConfiguredError        -> RuntimeError-ish (plain typed)
//	HITLNoApproverAvailable       -> PolicyDeniedError (wraps)
//	HITLIdentityNotInOrg          -> plain typed
//	HITLIdentityRequired          -> plain typed
//	HITLIdentityClaimRejected     -> PolicyDeniedError (wraps)
//	SecretValueLeakInPayload      -> plain typed
//	SecretApprovalRequired        -> PolicyDeniedError (wraps, carries .Pending)
//	SecretNotFound                -> plain typed
//
// Go does not have Python's class inheritance, but errors.Is must still
// trip on the design-doc parents so customer code can write a single
//
//	if errors.Is(err, controlzero.ErrPolicyDenied) { ... }
//
// block to catch HITLTimeoutError, HITLNoApproverAvailable,
// HITLIdentityClaimRejected, and SecretApprovalRequired. We implement
// that contract by giving each "deny-like" HITL error an `Is` method
// that matches the sentinel + an embedded PolicyDecision for parity
// with the Python attribute. The "config-only" classes (Identity*,
// SecretValueLeakInPayload, SecretNotFound) deliberately do NOT match
// ErrPolicyDenied -- they are misconfiguration errors, not deny
// outcomes (Python's RuntimeError -> not PolicyDeniedError).
package controlzero

import (
	"errors"
	"fmt"
)

// Sentinel errors callers use with errors.Is. The concrete typed
// errors below wrap one of these so a customer can write
//
//	if errors.Is(err, controlzero.ErrPolicyDenied) { ... }
//
// regardless of which HITL deny path actually fired.
var (
	// ErrPolicyDenied is the umbrella sentinel for ALL deny-like
	// outcomes (static deny, HITL timeout, HITL no-approver, HITL
	// identity claim rejected, SecretApprovalRequired).
	//
	// PolicyDeniedError (the struct) wraps this. The HITL deny
	// classes below also wrap this so a single errors.Is check
	// catches every denial path.
	ErrPolicyDenied = errors.New("controlzero: policy denied")

	// ErrHostedBootstrap is the umbrella sentinel for bootstrap-class
	// failures (no cached bundle + backend unreachable). HITL
	// HITLBackendUnreachableError wraps this for parity with Python.
	ErrHostedBootstrap = errors.New("controlzero: hosted bootstrap failed")
)

// E-code constants. Stable across SDKs.
const (
	ECodeHITLTimeout              = "E1701"
	ECodeHITLBackendUnreachable   = "E1702"
	ECodeHITLPolicyVersionConflict = "E1703"
	ECodeHITLNotConfigured        = "E1704"
	ECodeHITLNoApproverAvailable  = "E1705"
	ECodeHITLIdentityNotInOrg     = "E1706"
	ECodeHITLIdentityRequired     = "E1707"
	ECodeHITLIdentityClaimRejected = "E1708"
	ECodeSecretValueLeakInPayload = "E1709"
	ECodeSecretApprovalRequired   = "E1710"
	ECodeSecretNotFound           = "E1711"
)

// withECode formats a HITL error message the same way Python does:
//
//	<message>
//	[<E####>] (see https://docs.controlzero.ai/errors/<E####>)
//
// Pure function; no I/O.
func withECode(message, code string) string {
	if code == "" {
		return message
	}
	return fmt.Sprintf(
		"%s\n[%s] Docs: https://docs.controlzero.ai/errors/%s",
		message, code, code,
	)
}

// HITLTimeoutError: E1701. Approver did not decide before the deadline.
// errors.Is(err, ErrPolicyDenied) must return true.
type HITLTimeoutError struct {
	Message string
}

// NewHITLTimeoutError constructs the default-message instance Python
// raises when no diagnostic is provided.
func NewHITLTimeoutError(msg string) *HITLTimeoutError {
	if msg == "" {
		msg = "approval request timed out"
	}
	return &HITLTimeoutError{Message: msg}
}

func (e *HITLTimeoutError) Error() string {
	return withECode(e.Message, ECodeHITLTimeout)
}

// ECode exposes the catalog code for programmatic routing.
func (e *HITLTimeoutError) ECode() string { return ECodeHITLTimeout }

// Is reports whether err is the PolicyDenied sentinel; satisfies the
// design-doc inheritance contract.
func (e *HITLTimeoutError) Is(target error) bool {
	return target == ErrPolicyDenied
}

// HITLBackendUnreachableError: E1702. POST /api/approval-requests
// failed. errors.Is(err, ErrHostedBootstrap) returns true.
//
// Cause is the optional underlying error (e.g. *net.OpError or
// context.DeadlineExceeded) that triggered the unreachable condition.
// When non-nil, Unwrap exposes it so callers can write
// `errors.Is(err, context.DeadlineExceeded)` or
// `errors.As(err, &netErr)` and observe the original transport-layer
// failure without parsing the human message. Sites that only have a
// human diagnostic should keep using NewHITLBackendUnreachableError;
// sites that have an underlying error should use
// NewHITLBackendUnreachableErrorWithCause to preserve the unwrap
// chain.
type HITLBackendUnreachableError struct {
	Message string
	Cause   error
}

func NewHITLBackendUnreachableError(msg string) *HITLBackendUnreachableError {
	if msg == "" {
		msg = "Approval backend unreachable"
	}
	return &HITLBackendUnreachableError{Message: msg}
}

// NewHITLBackendUnreachableErrorWithCause is the cause-preserving
// constructor. msg is the human-readable diagnostic (same format as
// NewHITLBackendUnreachableError); cause is the underlying error
// returned by Unwrap so callers can `errors.Is` / `errors.As` against
// stdlib sentinels (e.g. context.DeadlineExceeded, *net.OpError).
func NewHITLBackendUnreachableErrorWithCause(msg string, cause error) *HITLBackendUnreachableError {
	if msg == "" {
		msg = "Approval backend unreachable"
	}
	return &HITLBackendUnreachableError{Message: msg, Cause: cause}
}

func (e *HITLBackendUnreachableError) Error() string {
	return withECode(e.Message, ECodeHITLBackendUnreachable)
}

func (e *HITLBackendUnreachableError) ECode() string { return ECodeHITLBackendUnreachable }

func (e *HITLBackendUnreachableError) Is(target error) bool {
	return target == ErrHostedBootstrap
}

// Unwrap exposes the optional underlying cause so errors.Is /
// errors.As can walk past the HITL wrapper to the transport-layer
// error.
func (e *HITLBackendUnreachableError) Unwrap() error { return e.Cause }

// HITLPolicyVersionConflictError: E1703.
type HITLPolicyVersionConflictError struct {
	Message string
}

func NewHITLPolicyVersionConflictError(msg string) *HITLPolicyVersionConflictError {
	if msg == "" {
		msg = "Approval policy version conflict"
	}
	return &HITLPolicyVersionConflictError{Message: msg}
}

func (e *HITLPolicyVersionConflictError) Error() string {
	return withECode(e.Message, ECodeHITLPolicyVersionConflict)
}

func (e *HITLPolicyVersionConflictError) ECode() string { return ECodeHITLPolicyVersionConflict }

// Is mirrors the Python class inheritance: HybridModeError parent.
// The exported ErrHybridMode sentinel lives in errors.go; pointing at
// it lets `errors.Is(err, ErrHybridMode)` trip on conflict events.
func (e *HITLPolicyVersionConflictError) Is(target error) bool {
	return target == ErrHybridMode
}

// HITLNotConfiguredError: E1704.
type HITLNotConfiguredError struct {
	Message string
}

func NewHITLNotConfiguredError(msg string) *HITLNotConfiguredError {
	if msg == "" {
		msg = "Approvals not configured for this org"
	}
	return &HITLNotConfiguredError{Message: msg}
}

func (e *HITLNotConfiguredError) Error() string {
	return withECode(e.Message, ECodeHITLNotConfigured)
}

func (e *HITLNotConfiguredError) ECode() string { return ECodeHITLNotConfigured }

// HITLNoApproverAvailable: E1705. Subclasses PolicyDeniedError.
type HITLNoApproverAvailable struct {
	Message string
}

func NewHITLNoApproverAvailable(msg string) *HITLNoApproverAvailable {
	if msg == "" {
		msg = "no approver available"
	}
	return &HITLNoApproverAvailable{Message: msg}
}

func (e *HITLNoApproverAvailable) Error() string {
	return withECode(e.Message, ECodeHITLNoApproverAvailable)
}

func (e *HITLNoApproverAvailable) ECode() string { return ECodeHITLNoApproverAvailable }

func (e *HITLNoApproverAvailable) Is(target error) bool {
	return target == ErrPolicyDenied
}

// HITLIdentityNotInOrg: E1706. Configuration error, NOT a deny.
type HITLIdentityNotInOrg struct {
	Message string
}

func NewHITLIdentityNotInOrg(msg string) *HITLIdentityNotInOrg {
	if msg == "" {
		msg = "Requestor identity is not a member of this org"
	}
	return &HITLIdentityNotInOrg{Message: msg}
}

func (e *HITLIdentityNotInOrg) Error() string {
	return withECode(e.Message, ECodeHITLIdentityNotInOrg)
}

func (e *HITLIdentityNotInOrg) ECode() string { return ECodeHITLIdentityNotInOrg }

// HITLIdentityRequired: E1707. Configuration error, NOT a deny.
type HITLIdentityRequired struct {
	Message string
}

func NewHITLIdentityRequired(msg string) *HITLIdentityRequired {
	if msg == "" {
		msg = "Approvals require X-CZ-Requestor-Email"
	}
	return &HITLIdentityRequired{Message: msg}
}

func (e *HITLIdentityRequired) Error() string {
	return withECode(e.Message, ECodeHITLIdentityRequired)
}

func (e *HITLIdentityRequired) ECode() string { return ECodeHITLIdentityRequired }

// HITLIdentityClaimRejected: E1708. PolicyDeniedError subclass.
type HITLIdentityClaimRejected struct {
	Message string
}

func NewHITLIdentityClaimRejected(msg string) *HITLIdentityClaimRejected {
	if msg == "" {
		msg = "Requestor identity claim rejected by backend"
	}
	return &HITLIdentityClaimRejected{Message: msg}
}

func (e *HITLIdentityClaimRejected) Error() string {
	return withECode(e.Message, ECodeHITLIdentityClaimRejected)
}

func (e *HITLIdentityClaimRejected) ECode() string { return ECodeHITLIdentityClaimRejected }

func (e *HITLIdentityClaimRejected) Is(target error) bool {
	return target == ErrPolicyDenied
}

// SecretValueLeakInPayload: E1709. SDK aborted before sending a
// payload that contained a secret-shaped value.
type SecretValueLeakInPayload struct {
	Message string
}

func NewSecretValueLeakInPayload(msg string) *SecretValueLeakInPayload {
	if msg == "" {
		msg = "secret value detected in wire payload"
	}
	return &SecretValueLeakInPayload{Message: msg}
}

func (e *SecretValueLeakInPayload) Error() string {
	return withECode(e.Message, ECodeSecretValueLeakInPayload)
}

func (e *SecretValueLeakInPayload) ECode() string { return ECodeSecretValueLeakInPayload }

// SecretApprovalRequired: E1710. Carries the PendingApproval that the
// SDK has already POSTed, so the caller can choose to wait() on it.
// PolicyDeniedError subclass.
type SecretApprovalRequired struct {
	Message string
	// Pending is the approval the SDK queued; nil for legacy
	// no-pending callers. Caller can .Wait() to drive the polling
	// loop.
	Pending *PendingApproval
}

func NewSecretApprovalRequired(msg string, pending *PendingApproval) *SecretApprovalRequired {
	if msg == "" {
		msg = "secret access requires approval"
	}
	return &SecretApprovalRequired{Message: msg, Pending: pending}
}

func (e *SecretApprovalRequired) Error() string {
	return withECode(e.Message, ECodeSecretApprovalRequired)
}

func (e *SecretApprovalRequired) ECode() string { return ECodeSecretApprovalRequired }

func (e *SecretApprovalRequired) Is(target error) bool {
	return target == ErrPolicyDenied
}

// SecretNotFound: E1711. Configuration-class, NOT a deny.
type SecretNotFound struct {
	Message string
}

func NewSecretNotFound(msg string) *SecretNotFound {
	if msg == "" {
		msg = "secret not found"
	}
	return &SecretNotFound{Message: msg}
}

func (e *SecretNotFound) Error() string {
	return withECode(e.Message, ECodeSecretNotFound)
}

func (e *SecretNotFound) ECode() string { return ECodeSecretNotFound }
