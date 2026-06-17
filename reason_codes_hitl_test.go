package controlzero_test

// Tests for HITL-5c (gh#540): new HITL reason codes in Go SDK v1.7.6.
//
// The 9 new codes are registered in ValidReasonCodes so a v1.8.0+
// client emitting them via audit doesn't get rejected by a v1.7.6
// ingest path. v1.7.6 itself never EMITS these codes (no HITL flow
// yet); it just recognizes them. Mirrors the Python 1.5.8 + Node
// HITL-5b parity so the cross-SDK enum stays aligned.

import (
	"strings"
	"testing"

	controlzero "controlzero.ai/sdk/go"
)

var hitlReasonCodes = []string{
	controlzero.ReasonCodeHITLSDKTimeout,
	controlzero.ReasonCodeHITLSLAExpired,
	controlzero.ReasonCodeHITLBackendUnreachable,
	controlzero.ReasonCodeHITLPolicyVersionConflict,
	controlzero.ReasonCodeHITLNoApproverAvailable,
	controlzero.ReasonCodeHITLIdentityNotInOrg,
	controlzero.ReasonCodeHITLIdentityRequired,
	controlzero.ReasonCodeHITLIdentityClaimRejected,
	controlzero.ReasonCodeHITLArgsHashMismatch,
}

// TestAllNineHITLCodesExported: the constants exist and are
// non-empty strings prefixed with HITL_.
func TestAllNineHITLCodesExported(t *testing.T) {
	for _, c := range hitlReasonCodes {
		if c == "" {
			t.Errorf("HITL reason code is empty string")
		}
		if !strings.HasPrefix(c, "HITL_") {
			t.Errorf("HITL reason code %q missing HITL_ prefix", c)
		}
	}
	if len(hitlReasonCodes) != 9 {
		t.Errorf("expected 9 HITL codes, got %d", len(hitlReasonCodes))
	}
}

// TestAllNineHITLCodesInValidSet: every new code is registered in
// ValidReasonCodes so audit ingest accepts it.
func TestAllNineHITLCodesInValidSet(t *testing.T) {
	for _, c := range hitlReasonCodes {
		if !controlzero.ValidReasonCodes[c] {
			t.Errorf("%q missing from ValidReasonCodes", c)
		}
	}
}

// TestLegacyCodesStillInValidSet: no regression on existing 1.7.5
// codes (renamed or dropped accidentally).
func TestLegacyCodesStillInValidSet(t *testing.T) {
	legacy := []string{
		controlzero.ReasonCodeRuleMatch,
		controlzero.ReasonCodeNoRuleMatch,
		controlzero.ReasonCodeNoActivePolicies,
		controlzero.ReasonCodeBundleMissing,
		controlzero.ReasonCodeBundleTampered,
		controlzero.ReasonCodeMachineQuarantined,
		controlzero.ReasonCodeNetworkError,
		controlzero.ReasonCodeDLPBlocked,
	}
	for _, c := range legacy {
		if !controlzero.ValidReasonCodes[c] {
			t.Errorf("legacy code %q missing from ValidReasonCodes", c)
		}
	}
}

// TestHITLCodesMatchDesignDocExactly: spelling guard. Any rename
// here breaks cross-SDK parity with the design doc + Python + Node.
// Lock the literals.
func TestHITLCodesMatchDesignDocExactly(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{controlzero.ReasonCodeHITLSDKTimeout, "HITL_SDK_TIMEOUT"},
		{controlzero.ReasonCodeHITLSLAExpired, "HITL_SLA_EXPIRED"},
		{controlzero.ReasonCodeHITLBackendUnreachable, "HITL_BACKEND_UNREACHABLE"},
		{controlzero.ReasonCodeHITLPolicyVersionConflict, "HITL_POLICY_VERSION_CONFLICT"},
		{controlzero.ReasonCodeHITLNoApproverAvailable, "HITL_NO_APPROVER_AVAILABLE"},
		{controlzero.ReasonCodeHITLIdentityNotInOrg, "HITL_IDENTITY_NOT_IN_ORG"},
		{controlzero.ReasonCodeHITLIdentityRequired, "HITL_IDENTITY_REQUIRED"},
		{controlzero.ReasonCodeHITLIdentityClaimRejected, "HITL_IDENTITY_CLAIM_REJECTED"},
		{controlzero.ReasonCodeHITLArgsHashMismatch, "HITL_ARGS_HASH_MISMATCH"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q (cross-SDK spelling drift)", c.got, c.want)
		}
	}
}

// TestValidReasonCodesGrewByExactlyNine: 1.7.5 had 8 codes; 1.7.6
// adds 9 -> 17. The #1247 observe posture adds OBSERVE_MODE_NO_POLICY
// -> 18. If anyone adds another code without updating this test, it
// fires so the addition is intentional + reviewed.
func TestValidReasonCodesGrewByExactlyNine(t *testing.T) {
	const legacyCount = 8
	const hitlCount = 9
	const observeCount = 1 // OBSERVE_MODE_NO_POLICY (#1247)
	want := legacyCount + hitlCount + observeCount
	if len(controlzero.ValidReasonCodes) != want {
		t.Errorf("len(ValidReasonCodes) = %d, want %d (legacy %d + hitl %d + observe %d)",
			len(controlzero.ValidReasonCodes), want, legacyCount, hitlCount, observeCount)
	}
}
