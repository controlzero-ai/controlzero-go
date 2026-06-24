package controlzero

// Canonical reason_code enum values. Stable, machine-readable labels so
// integrations + dashboards can branch on decision provenance without
// regex-matching the human-readable `reason` string.
//
// Added in #228 Phase 2 to bring the Go SDK to parity with the Python
// SDK. The enum is cross-language: the exact same eight strings appear
// on Python, Node, the compiled policy engine, the Gateway, and the
// backend audit envelope. New values are additive; downstream
// consumers MUST tolerate unknown codes.
//
// See docs/behavior-matrix.md section S6 for the canonical list and
// the canonical mapping from surface event -> reason_code.
const (
	// ReasonCodeRuleMatch is emitted when a user-authored policy rule
	// matched and its effect (allow/deny/warn) is the decision.
	ReasonCodeRuleMatch = "RULE_MATCH"

	// ReasonCodeNoRuleMatch is emitted when the bundle loaded cleanly
	// but no rule matched the call. The surface then applies
	// default_action.
	ReasonCodeNoRuleMatch = "NO_RULE_MATCH"

	// ReasonCodeNoActivePolicies is emitted when the bundle is
	// structurally empty (zero attached policies). Synthetic deny
	// rather than a missing-bundle error so the dashboard can
	// distinguish "nothing attached" from "bundle broken."
	ReasonCodeNoActivePolicies = "NO_ACTIVE_POLICIES"

	// ReasonCodeBundleMissing is emitted when the client is enrolled
	// but has no cached bundle and cannot pull a fresh one. The
	// surface then applies default_on_missing.
	ReasonCodeBundleMissing = "BUNDLE_MISSING"

	// ReasonCodeObserveModeNoPolicy is emitted when the project is
	// GENUINELY empty (zero attached policies) and default_on_empty is
	// "observe" (#1247 item 3). The call is ALLOWED but loudly flagged as
	// monitoring-only: the engine is wired up and auditing, not enforcing.
	// SECURITY INVARIANT: only ever produced by the bundle translator's
	// synthetic OBSERVE_MODE_NO_POLICY rule on a genuinely-empty project --
	// a degraded / stale / stripped bundle fails closed with
	// BUNDLE_MISSING instead, never this code.
	ReasonCodeObserveModeNoPolicy = "OBSERVE_MODE_NO_POLICY"

	// ReasonCodeBundleTampered is emitted when bundle verification
	// fails (bad signature, checksum mismatch, unwrap error).
	ReasonCodeBundleTampered = "BUNDLE_TAMPERED"

	// ReasonCodeMachineQuarantined is emitted when the machine is
	// locally quarantined (see tamper.go) and any tool call is denied
	// until recovery.
	ReasonCodeMachineQuarantined = "MACHINE_QUARANTINED"

	// ReasonCodeNetworkError is emitted when the backend is
	// unreachable (DNS, connect, timeout) and no cached bundle is
	// available. The surface then applies default_on_missing.
	ReasonCodeNetworkError = "NETWORK_ERROR"

	// ReasonCodeDLPBlocked is emitted when a DLP rule with
	// action="block" matched the tool arguments and overrode a
	// would-be allow decision.
	ReasonCodeDLPBlocked = "DLP_BLOCKED"

	// HITL approval-flow reason codes (HITL-5c, gh#540). The actual
	// request-approval flow ships in v1.8.0 (HITL-6a, gh#542); v1.7.6
	// registers the codes so audit rows from a v1.8.0+ client can be
	// accepted by a v1.7.6 ingest path without rejection during a
	// mixed-version rollout. v1.7.6 itself never emits these codes.

	// ReasonCodeHITLSDKTimeout is emitted when the SDK waited the
	// configured timeout for an approver verdict and gave up.
	ReasonCodeHITLSDKTimeout = "HITL_SDK_TIMEOUT"

	// ReasonCodeHITLSLAExpired is emitted when the backend's SLA
	// timer expired before any approver acted on the request.
	ReasonCodeHITLSLAExpired = "HITL_SLA_EXPIRED"

	// ReasonCodeHITLBackendUnreachable is emitted when the SDK could
	// not reach the backend to enqueue the approval request.
	ReasonCodeHITLBackendUnreachable = "HITL_BACKEND_UNREACHABLE"

	// ReasonCodeHITLPolicyVersionConflict is emitted when the policy
	// bundle changed between request and verdict, invalidating the
	// pending approval.
	ReasonCodeHITLPolicyVersionConflict = "HITL_POLICY_VERSION_CONFLICT"

	// ReasonCodeHITLNoApproverAvailable is emitted when no eligible
	// approver was online or reachable at request time.
	ReasonCodeHITLNoApproverAvailable = "HITL_NO_APPROVER_AVAILABLE"

	// ReasonCodeHITLIdentityNotInOrg is emitted when the approving
	// identity is not a member of the request's org.
	ReasonCodeHITLIdentityNotInOrg = "HITL_IDENTITY_NOT_IN_ORG"

	// ReasonCodeHITLIdentityRequired is emitted when the request
	// requires an authenticated identity claim and none was provided.
	ReasonCodeHITLIdentityRequired = "HITL_IDENTITY_REQUIRED"

	// ReasonCodeHITLIdentityClaimRejected is emitted when the
	// identity claim attached to the request failed verification.
	ReasonCodeHITLIdentityClaimRejected = "HITL_IDENTITY_CLAIM_REJECTED"

	// ReasonCodeHITLArgsHashMismatch is emitted when the args hash
	// at verdict time differs from the args hash at request time,
	// indicating the call payload mutated mid-approval.
	ReasonCodeHITLArgsHashMismatch = "HITL_ARGS_HASH_MISMATCH"
)

// ValidReasonCodes is the full enum, exposed for tests + downstream
// validators. Unknown codes from a newer SDK version are still
// permitted on the wire; this set is informational, not a gate.
var ValidReasonCodes = map[string]bool{
	ReasonCodeRuleMatch:                 true,
	ReasonCodeNoRuleMatch:               true,
	ReasonCodeNoActivePolicies:          true,
	ReasonCodeBundleMissing:             true,
	ReasonCodeObserveModeNoPolicy:       true,
	ReasonCodeBundleTampered:            true,
	ReasonCodeMachineQuarantined:        true,
	ReasonCodeNetworkError:              true,
	ReasonCodeDLPBlocked:                true,
	ReasonCodeHITLSDKTimeout:            true,
	ReasonCodeHITLSLAExpired:            true,
	ReasonCodeHITLBackendUnreachable:    true,
	ReasonCodeHITLPolicyVersionConflict: true,
	ReasonCodeHITLNoApproverAvailable:   true,
	ReasonCodeHITLIdentityNotInOrg:      true,
	ReasonCodeHITLIdentityRequired:      true,
	ReasonCodeHITLIdentityClaimRejected: true,
	ReasonCodeHITLArgsHashMismatch:      true,
}

// Synthetic policy_id sentinels (T79 / the deny-deny postmortem,
// 2026-05-11). When a deny is emitted by anything OTHER than a
// user-authored rule, the SDK stamps the audit row's PolicyID with
// one of these `synthetic:*` values so the audit dashboard can
// render a recognizable chip and link it to the right
// troubleshooting anchor. Without this, four very different bug
// classes (stale bundle, missing resource gate, vocabulary
// mismatch, genuine no-match) all looked identical in the Policy
// column (blank placeholder + Decision=Deny + reason_code=NO_RULE_MATCH).
//
// Keep these in lockstep with the Python (`SYNTHETIC_*`) and Node
// (`SYNTHETIC_*`) constants; the audit dashboard matches on the
// exact strings.
const (
	SyntheticPolicyIDPrefix        = "synthetic:"
	SyntheticPolicyIDNoRuleMatch   = "synthetic:NO_RULE_MATCH"
	SyntheticPolicyIDNoActive      = "synthetic:NO_ACTIVE_POLICIES"
	SyntheticPolicyIDObserveNoPol  = "synthetic:OBSERVE_MODE_NO_POLICY"
	SyntheticPolicyIDBundleMiss    = "synthetic:BUNDLE_MISSING"
	SyntheticPolicyIDResGateSkip   = "synthetic:RESOURCE_GATE_SKIP"
	SyntheticPolicyIDQuarantine    = "synthetic:QUARANTINE"
	SyntheticPolicyIDEngineUnavail = "synthetic:ENGINE_UNAVAILABLE"
	// SyntheticPolicyIDUnattributedDeny is backend-stamped on a deny that
	// arrived with an empty policy_id; recognized here for lockstep.
	SyntheticPolicyIDUnattributedDeny = "synthetic:UNATTRIBUTED_DENY"
)

// ValidSyntheticPolicyIDs is the full set, exposed for tests and
// for downstream consumers that want to recognize a synthetic deny
// without string-prefix matching.
var ValidSyntheticPolicyIDs = map[string]bool{
	SyntheticPolicyIDNoRuleMatch:      true,
	SyntheticPolicyIDNoActive:         true,
	SyntheticPolicyIDObserveNoPol:     true,
	SyntheticPolicyIDBundleMiss:       true,
	SyntheticPolicyIDResGateSkip:      true,
	SyntheticPolicyIDQuarantine:       true,
	SyntheticPolicyIDEngineUnavail:    true,
	SyntheticPolicyIDUnattributedDeny: true,
}
