# Changelog

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
