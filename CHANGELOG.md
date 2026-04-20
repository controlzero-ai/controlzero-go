# Changelog

## v1.6.0 -- 2026-04-20

### Enforcement behavior parity (#228 Phase 2)

Brings the Go SDK to parity with Python / Node on the canonical
cross-surface enforcement spec. See `docs/behavior-matrix.md`.

- New `ParsedPolicy` struct returned by the new `LoadPolicyFull`
  function. Carries `Rules` + `Settings`. `LoadPolicy` is unchanged
  and keeps returning `[]PolicyRule` for backwards compatibility.
- New `PolicySettings` struct with three fields:
  `DefaultAction` (deny | allow | warn),
  `DefaultOnMissing` (deny | allow),
  `DefaultOnTamper` (warn | deny | deny-all | quarantine).
  `TamperBehavior` is kept as a legacy alias for one release.
  Zero-value is the canonical fallback (deny/deny/warn).
- Bundle / YAML-level `default_action`, `default_on_missing`,
  `default_on_tamper` are parsed and validated; unknown values are
  rejected with `PolicyValidationError`.
- `PolicyDecision.ReasonCode` is a new field carrying the canonical
  cross-language enum (`RULE_MATCH`, `NO_RULE_MATCH`,
  `NO_ACTIVE_POLICIES`, `BUNDLE_MISSING`, `BUNDLE_TAMPERED`,
  `MACHINE_QUARANTINED`, `NETWORK_ERROR`, `DLP_BLOCKED`). Exported
  as string constants in `reason_codes.go`. Empty string on older
  decisions that predate the field.
- `PolicyEvaluator` now honours `default_action` on no-match via
  `NewPolicyEvaluatorWithSettings` or `SetDefaultAction`. Empty or
  unknown values keep the legacy fail-closed contract (deny).
- `PolicyRule.ReasonCode` lets the backend bundle translator stamp
  synthetic denies (e.g. `NO_ACTIVE_POLICIES` when zero policies are
  attached) and have the evaluator carry them through.
- Quarantine-driven denies now emit `ReasonCode=MACHINE_QUARANTINED`.
  DLP-override denies emit `ReasonCode=DLP_BLOCKED`.
- New `ApplyTamperBehavior` helper reads `PolicySettings` and drives
  the state transitions (warn / deny / deny-all / quarantine) so
  hosted-mode callers have a single entry point.
- Audit envelopes now carry `surface: "go-sdk"` and `reason_code`
  keys alongside the existing `reason` string.

### Shared test fixtures

Eleven canonical spec-compliance fixtures now live under
`tests/fixtures/enforcement-spec/`. `spec_compliance_test.go` in this
module drives them and asserts the expected `(decision, reason_code)`
for every row of the Phase 2 matrix.

## v1.5.0 -- 2026-04-15

### Requirements

- Go 1.24 or later (was 1.22). Forced by the new LangChainGo
  integration, which depends on `github.com/tmc/langchaingo@>=0.1.14`.
  Core SDK APIs are unchanged.

### New integrations

- `integrations/langchaingo` (issue #96) -- `WrapTool` +
  `WrapTools` for `github.com/tmc/langchaingo/tools.Tool`. Guards
  every `Call` invocation through Control Zero first. Denial returns
  `*controlzero.PolicyDeniedError` matchable with `errors.As`.
  `github.com/tmc/langchaingo` is a direct dependency only of the
  `integrations/langchaingo` sub-package; consumers who don't import
  it pay no runtime cost.

## v1.4.0 -- earlier

Initial SDK: Guard, policy loading (YAML/JSON), signed bundle
verification, local audit, DLP scanning, quarantine, enrollment.
