// HITL-6c Go SDK error-class contract tests. Mirror Python
// test_hitl_6a_exceptions.py 1:1, adapted for Go's errors.Is /
// errors.As idiom.

package controlzero

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type hitlClassCase struct {
	name          string
	makeDefault   func() error
	makeWithMsg   func(string) error
	expectedCode  string
	parentMatches bool // errors.Is(err, ErrPolicyDenied) must be true
	parentSentinel error
}

func hitlClassMatrix() []hitlClassCase {
	return []hitlClassCase{
		{
			name:          "HITLTimeoutError",
			makeDefault:   func() error { return NewHITLTimeoutError("") },
			makeWithMsg:   func(m string) error { return NewHITLTimeoutError(m) },
			expectedCode:  ECodeHITLTimeout,
			parentMatches: true,
			parentSentinel: ErrPolicyDenied,
		},
		{
			name:          "HITLBackendUnreachableError",
			makeDefault:   func() error { return NewHITLBackendUnreachableError("") },
			makeWithMsg:   func(m string) error { return NewHITLBackendUnreachableError(m) },
			expectedCode:  ECodeHITLBackendUnreachable,
			parentMatches: true,
			parentSentinel: ErrHostedBootstrap,
		},
		{
			name:          "HITLPolicyVersionConflictError",
			makeDefault:   func() error { return NewHITLPolicyVersionConflictError("") },
			makeWithMsg:   func(m string) error { return NewHITLPolicyVersionConflictError(m) },
			expectedCode:  ECodeHITLPolicyVersionConflict,
			parentMatches: true,
			parentSentinel: ErrHybridMode,
		},
		{
			name:          "HITLNotConfiguredError",
			makeDefault:   func() error { return NewHITLNotConfiguredError("") },
			makeWithMsg:   func(m string) error { return NewHITLNotConfiguredError(m) },
			expectedCode:  ECodeHITLNotConfigured,
			parentMatches: false,
		},
		{
			name:          "HITLNoApproverAvailable",
			makeDefault:   func() error { return NewHITLNoApproverAvailable("") },
			makeWithMsg:   func(m string) error { return NewHITLNoApproverAvailable(m) },
			expectedCode:  ECodeHITLNoApproverAvailable,
			parentMatches: true,
			parentSentinel: ErrPolicyDenied,
		},
		{
			name:          "HITLIdentityNotInOrg",
			makeDefault:   func() error { return NewHITLIdentityNotInOrg("") },
			makeWithMsg:   func(m string) error { return NewHITLIdentityNotInOrg(m) },
			expectedCode:  ECodeHITLIdentityNotInOrg,
			parentMatches: false,
		},
		{
			name:          "HITLIdentityRequired",
			makeDefault:   func() error { return NewHITLIdentityRequired("") },
			makeWithMsg:   func(m string) error { return NewHITLIdentityRequired(m) },
			expectedCode:  ECodeHITLIdentityRequired,
			parentMatches: false,
		},
		{
			name:          "HITLIdentityClaimRejected",
			makeDefault:   func() error { return NewHITLIdentityClaimRejected("") },
			makeWithMsg:   func(m string) error { return NewHITLIdentityClaimRejected(m) },
			expectedCode:  ECodeHITLIdentityClaimRejected,
			parentMatches: true,
			parentSentinel: ErrPolicyDenied,
		},
		{
			name:          "SecretValueLeakInPayload",
			makeDefault:   func() error { return NewSecretValueLeakInPayload("") },
			makeWithMsg:   func(m string) error { return NewSecretValueLeakInPayload(m) },
			expectedCode:  ECodeSecretValueLeakInPayload,
			parentMatches: false,
		},
		{
			name:          "SecretApprovalRequired",
			makeDefault:   func() error { return NewSecretApprovalRequired("", nil) },
			makeWithMsg:   func(m string) error { return NewSecretApprovalRequired(m, nil) },
			expectedCode:  ECodeSecretApprovalRequired,
			parentMatches: true,
			parentSentinel: ErrPolicyDenied,
		},
		{
			name:          "SecretNotFound",
			makeDefault:   func() error { return NewSecretNotFound("") },
			makeWithMsg:   func(m string) error { return NewSecretNotFound(m) },
			expectedCode:  ECodeSecretNotFound,
			parentMatches: false,
		},
	}
}

func TestHITLErrorDefaultMessageNonEmpty(t *testing.T) {
	for _, c := range hitlClassMatrix() {
		t.Run(c.name, func(t *testing.T) {
			err := c.makeDefault()
			if err.Error() == "" {
				t.Fatalf("default Error() must not be empty for %s", c.name)
			}
		})
	}
}

func TestHITLErrorCustomMessageRoundTrip(t *testing.T) {
	for _, c := range hitlClassMatrix() {
		t.Run(c.name, func(t *testing.T) {
			err := c.makeWithMsg("custom diagnostic message")
			if !strings.Contains(err.Error(), "custom diagnostic message") {
				t.Fatalf("expected custom message in Error() for %s: got %q", c.name, err.Error())
			}
		})
	}
}

func TestHITLErrorECodeAndDocsURL(t *testing.T) {
	for _, c := range hitlClassMatrix() {
		t.Run(c.name, func(t *testing.T) {
			err := c.makeDefault()
			s := err.Error()
			if !strings.Contains(s, "["+c.expectedCode+"]") {
				t.Errorf("missing [%s] in Error() for %s: %q", c.expectedCode, c.name, s)
			}
			if !strings.Contains(s, "docs.controlzero.ai/errors/") {
				t.Errorf("missing docs URL in Error() for %s: %q", c.name, s)
			}
		})
	}
}

func TestHITLErrorECodeAccessor(t *testing.T) {
	for _, c := range hitlClassMatrix() {
		t.Run(c.name, func(t *testing.T) {
			err := c.makeDefault()
			type withECode interface{ ECode() string }
			ec, ok := err.(withECode)
			if !ok {
				t.Fatalf("%s does not implement ECode()", c.name)
			}
			if ec.ECode() != c.expectedCode {
				t.Errorf("%s.ECode() = %q, want %q", c.name, ec.ECode(), c.expectedCode)
			}
		})
	}
}

// errors.Is contract: deny-class HITL errors must match ErrPolicyDenied
// so callers can write a single `if errors.Is(err, ErrPolicyDenied)`.
func TestHITLErrorIsPolicyDeniedContract(t *testing.T) {
	for _, c := range hitlClassMatrix() {
		t.Run(c.name, func(t *testing.T) {
			err := c.makeDefault()
			isDeny := errors.Is(err, ErrPolicyDenied)
			if c.parentSentinel == ErrPolicyDenied && !isDeny {
				t.Errorf("%s must satisfy errors.Is(err, ErrPolicyDenied)", c.name)
			}
			if c.parentSentinel != ErrPolicyDenied && isDeny {
				// "Config-class" errors must NOT be caught by an
				// errors.Is(err, ErrPolicyDenied) block. Mirrors
				// the Python "RuntimeError vs PolicyDeniedError"
				// dichotomy.
				t.Errorf("%s must NOT satisfy errors.Is(err, ErrPolicyDenied) -- "+
					"it is a configuration error, not a deny", c.name)
			}
		})
	}
}

func TestHITLErrorParentSentinelMatches(t *testing.T) {
	for _, c := range hitlClassMatrix() {
		if c.parentSentinel == nil {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			err := c.makeDefault()
			if !errors.Is(err, c.parentSentinel) {
				t.Errorf("%s must satisfy errors.Is(err, %v)", c.name, c.parentSentinel)
			}
		})
	}
}

func TestHITLErrorIsDoesNotMatchUnrelated(t *testing.T) {
	// Sanity: HITLTimeoutError should NOT match ErrHybridMode.
	err := NewHITLTimeoutError("")
	if errors.Is(err, ErrHybridMode) {
		t.Errorf("HITLTimeoutError must not match ErrHybridMode")
	}
}

func TestErrorsAsExtractsConcreteType(t *testing.T) {
	err := error(NewSecretNotFound("missing"))
	var snf *SecretNotFound
	if !errors.As(err, &snf) {
		t.Fatalf("errors.As must extract *SecretNotFound")
	}
	if !strings.Contains(snf.Message, "missing") {
		t.Errorf("expected message to round trip, got %q", snf.Message)
	}
}

func TestSecretApprovalRequiredPendingNilByDefault(t *testing.T) {
	err := NewSecretApprovalRequired("test", nil)
	if err.Pending != nil {
		t.Errorf("Pending must default to nil, got %v", err.Pending)
	}
}

func TestSecretApprovalRequiredPendingPropagates(t *testing.T) {
	pending, err := NewPendingApproval("req-1", 60, "key-1", time.Time{})
	if err != nil {
		t.Fatalf("NewPendingApproval: %v", err)
	}
	sar := NewSecretApprovalRequired("needs approval", pending)
	if sar.Pending != pending {
		t.Errorf("Pending pointer must round-trip")
	}
}

func TestECodeECodeConstantsAreUnique(t *testing.T) {
	codes := []string{
		ECodeHITLTimeout, ECodeHITLBackendUnreachable,
		ECodeHITLPolicyVersionConflict, ECodeHITLNotConfigured,
		ECodeHITLNoApproverAvailable, ECodeHITLIdentityNotInOrg,
		ECodeHITLIdentityRequired, ECodeHITLIdentityClaimRejected,
		ECodeSecretValueLeakInPayload, ECodeSecretApprovalRequired,
		ECodeSecretNotFound,
	}
	seen := make(map[string]bool)
	for _, c := range codes {
		if seen[c] {
			t.Errorf("duplicate E-code: %s", c)
		}
		seen[c] = true
	}
	if len(codes) != 11 {
		t.Errorf("expected 11 HITL E-codes, got %d", len(codes))
	}
}

func TestWithECodeNoCodeReturnsRawMessage(t *testing.T) {
	got := withECode("plain message", "")
	if got != "plain message" {
		t.Errorf("empty code must passthrough, got %q", got)
	}
}

// Sanity: PolicyDeniedError.Is matches ErrPolicyDenied so the umbrella
// sentinel contract holds for static denies too, not just HITL.
func TestStaticPolicyDeniedErrorMatchesUmbrellaSentinel(t *testing.T) {
	err := &PolicyDeniedError{Decision: PolicyDecision{Effect: "deny", Reason: "test"}}
	if !errors.Is(err, ErrPolicyDenied) {
		t.Errorf("PolicyDeniedError must satisfy errors.Is(err, ErrPolicyDenied)")
	}
}
