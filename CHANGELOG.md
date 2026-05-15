# Changelog

## v1.7.4 -- 2026-05-16 (PRIVACY, RETRACT)

### Changed

- **`retract v1.7.2` directive added in `go.mod`.** Per the Go retract
  policy. v1.7.2 contained accidentally-included customer-name
  references in inline comments and a realistic-looking
  `cz_live_*` test fixture. Tools resolving the module will now print
  a retraction warning when v1.7.2 is requested. Use v1.7.4 or later.
- **`retract v1.7.3` directive added in `go.mod`.** v1.7.3 was the
  immediate scrub release but is superseded here because the public
  mirror at `controlzero-ai/controlzero-go` had its git history
  rewritten on 2026-05-16 to purge the v1.7.2 dirty commits. As a
  side-effect the v1.7.3 tag no longer resolves on the mirror. Use
  v1.7.4 or later.
- **Public mirror history rewrite (2026-05-16).** The mirror was
  reset to a single clean commit with the current scrubbed tree.
  Old git history and the v1.7.0 / v1.7.1 / v1.7.2 / v1.7.3 tags
  were removed from the mirror to ensure no reader can browse the
  pre-scrub source. The `proxy.golang.org` cached zips for those
  versions remain until Google's module-proxy-removal request
  resolves; v1.7.4 is the only safe version going forward.

## v1.7.3 -- 2026-05-16 (PRIVACY)

### Fixed

- **Customer names and identifiable references removed from the
  public mirror.** Earlier 1.7.x releases (including v1.7.2)
  carried customer names and individual contributor names in inline
  comments and test fixture names as historical context for past
  incidents. This release replaces every such reference with a
  generic technical description while preserving the technical
  meaning of the comment. No behavior change. Concretely affects
  inline comments in `client.go`, `hosted_policy.go`,
  `reason_codes.go`, and the corresponding test files.
- **Realistic-looking placeholder key in test fixtures replaced.**
  The 64-hex-char `cz_live_*` string used as a redaction test
  fixture has been swapped for an obviously-synthetic
  `cz_live_aaaa...` placeholder.
- **Broken cross-link in CHANGELOG.** The v1.6.1 entry linked to
  an issue in the private monorepo (404 for external readers);
  replaced with a link to `docs.controlzero.ai`.

## v1.7.2 -- 2026-05-15

### Added

- **SDK version tracking on audit rows.** Every `audit` POST now carries a
  `controlzero_sdk_version` field of the form `go@v1.7.2`. Backend ingest
  truncates at 64 chars; over-length values are dropped to empty rather than
  rejected, so older clients keep working. Read in the dashboard via the new
  Audit Log column to see which SDK version produced a given decision.
  (#501 / #495 v1)

### Added (cont.)

- **`MaskAPIKey` helper for log redaction.** New `secrets.go` exports a
  `MaskAPIKey(string) string` helper that converts a `cz_live_<rest>` or
  `cz_test_<rest>` value to `cz_live_***` / `cz_test_***`. Use this anywhere
  you log a value that might contain an API key (request error wrappers,
  custom debug output) so the Go SDK matches the masking posture that landed
  in the Python and Node SDKs as part of the Tier 0 leak hotfix. The full
  `doctor` / `migrate` commands remain Python+Node only at this time and are
  on the Go roadmap. (#500 / #174)

## v1.7.1 -- 2026-05-12 (SECURITY)

### Fixed

- **API key leak in the active-source stderr notification.** The T103
  startup line `controlzero: active policy source = hosted (...)`
  printed the first 14 characters of `CONTROLZERO_API_KEY`, which for
  a `cz_live_...` or `cz_test_...` key meant 6 characters of the
  customer secret reached stderr (visible in terminals, screen shares,
  support transcripts, and CI logs). The hint is now masked to
  `cz_live_***` or `cz_test_***` so the mode is still observable but
  no secret bytes are exposed. Upgrade ASAP if you ran v1.7.0 in any
  environment where stderr is observable.

## v1.7.0 -- 2026-05-12

### Changed (governance posture; opt-out path documented)

- **Hosted policy wins by default when `CONTROLZERO_API_KEY` is set.**
  An api_key now means hosted is authoritative; a local file is
  consulted only when no api_key, or when
  `CONTROLZERO_LOCAL_OVERRIDE=1` is set explicitly as a debug/offline
  escape hatch. `WithPolicy` / `WithPolicyFile` passed to
  `controlzero.New(...)` still wins (caller is intentional) with a
  loud stderr warning. `WithStrictHosted(true)` upgrades the warning
  to `ErrHybridMode`. The active policy source is named in a single
  stderr line at Client construction; `CONTROLZERO_QUIET=1` silences
  it.

### Added

- **Governance audit event when LOCAL_OVERRIDE is used.** Every
  Client construction that bypasses the hosted bundle via
  `CONTROLZERO_LOCAL_OVERRIDE=1` emits a one-shot audit event with
  `reason_code=LOCAL_OVERRIDE_ACTIVE` to the remote audit sink so ops
  can filter / alert on the bypass.
- **Cache GC on api_key rotation.** On every fresh bootstrap fetch
  the SDK removes `cache/bootstrap-<scope>.json` +
  `cache/bundle-<scope>.{bin,meta}` files whose scope does NOT match
  the active api_key. Directories planted in the cache dir are
  skipped; stray user files are preserved.
- **`policy.json` accepted alongside `policy.yaml`.** The cwd
  auto-detect now probes `controlzero.{yaml,yml,json}` in order.

### Refs

GH #424 (umbrella), PRs #425 (precedence), #428 (cache GC), #427
(dashboard dedupe), #429 (governance audit event).

## v1.6.1 -- 2026-05-05

### Notes

- No behavior changes. Republish so consumers picking up
  `controlzero.ai/sdk/go` after the latest monorepo sync land on a
  fresh tag with the current README install instructions.
- The Go SDK currently lags the Python (`controlzero` 1.4.x) and Node
  (`@controlzero/sdk` 1.8.x) SDKs on the cross-CLI canonical-tool
  alias map (#341) and the SQL semantic-class layer (#350). Those will
  follow in `v1.7.0`. Track parity work via the
  [Control Zero docs](https://docs.controlzero.ai).

### Install

```bash
go get controlzero.ai/sdk/go@v1.6.1
```

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
