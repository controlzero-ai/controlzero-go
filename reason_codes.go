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
)

// ValidReasonCodes is the full enum, exposed for tests + downstream
// validators. Unknown codes from a newer SDK version are still
// permitted on the wire; this set is informational, not a gate.
var ValidReasonCodes = map[string]bool{
	ReasonCodeRuleMatch:          true,
	ReasonCodeNoRuleMatch:        true,
	ReasonCodeNoActivePolicies:   true,
	ReasonCodeBundleMissing:      true,
	ReasonCodeBundleTampered:     true,
	ReasonCodeMachineQuarantined: true,
	ReasonCodeNetworkError:       true,
	ReasonCodeDLPBlocked:         true,
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
	SyntheticPolicyIDBundleMiss    = "synthetic:BUNDLE_MISSING"
	SyntheticPolicyIDResGateSkip   = "synthetic:RESOURCE_GATE_SKIP"
	SyntheticPolicyIDQuarantine    = "synthetic:QUARANTINE"
	SyntheticPolicyIDEngineUnavail = "synthetic:ENGINE_UNAVAILABLE"
)

// ValidSyntheticPolicyIDs is the full set, exposed for tests and
// for downstream consumers that want to recognize a synthetic deny
// without string-prefix matching.
var ValidSyntheticPolicyIDs = map[string]bool{
	SyntheticPolicyIDNoRuleMatch:   true,
	SyntheticPolicyIDNoActive:      true,
	SyntheticPolicyIDBundleMiss:    true,
	SyntheticPolicyIDResGateSkip:   true,
	SyntheticPolicyIDQuarantine:    true,
	SyntheticPolicyIDEngineUnavail: true,
}
