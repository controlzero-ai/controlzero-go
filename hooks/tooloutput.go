// Package hooks exposes the public Go SDK ingest-hook surface for
// credential leak detection (epic #666, PR-4).
//
// Mirrors the Python public surface shape:
//
//   - BuildHandler constructs a configured ingest handler.
//   - OnToolOutput scans one tool-output body and returns the
//     possibly-redacted text plus the audit rows that were forwarded
//     to the configured sink.
//
// Hosts wiring the SDK into a Claude Code / OpenClaw / Codex plugin
// use these two entry points; the underlying scanner + redactor live
// in `internal/credentialscanner` and `internal/credentialhook` so
// they are not part of the public import surface.
//
// Importing this package costs nothing until BuildHandler is called.
// BuildHandler triggers the embedded YAML compile (one-time per
// process call); OnToolOutput is allocation-light per call.
package hooks

import (
	"context"

	"controlzero.ai/sdk/go/internal/credentialhook"
	"controlzero.ai/sdk/go/internal/credentialscanner"
)

// Action re-exports the credentialhook enum so callers do not need
// to import the internal package directly.
type Action = credentialhook.Action

// Re-export the action constants. Keeping the constant identifiers
// at the public surface lets callers write `hooks.ActionRedact`
// without an internal import.
const (
	ActionWarn   = credentialhook.ActionWarn
	ActionRedact = credentialhook.ActionRedact
	ActionBlock  = credentialhook.ActionBlock
)

// Source re-exports the per-call source label.
type Source = credentialhook.Source

const (
	SourceToolOutput = credentialhook.SourceToolOutput
	SourceToolStderr = credentialhook.SourceToolStderr
	SourceFileRead   = credentialhook.SourceFileRead
	SourceGrepMatch  = credentialhook.SourceGrepMatch
)

// HandleInput / HandleOutput / AuditRow / Sink / Handler / ErrCredentialLeakBlocked
// re-exported so the public surface is one package.
type (
	HandleInput  = credentialhook.HandleInput
	HandleOutput = credentialhook.HandleOutput
	AuditRow     = credentialhook.AuditRow
	Sink         = credentialhook.Sink
	Handler      = credentialhook.Handler
)

// ErrCredentialLeakBlocked is the sentinel returned by OnToolOutput
// when the configured action is ActionBlock and the scanner found a
// credential match. Wrapping callers can `errors.Is` against this
// value.
var ErrCredentialLeakBlocked = credentialhook.ErrCredentialLeakBlocked

// BuildHandlerOptions configures a handler. ProjectID and HMACKey are
// required; Sink may be nil to run the scanner without forwarding
// rows over the wire (local-only mode).
type BuildHandlerOptions struct {
	Sink      Sink
	ProjectID string
	Action    Action
	HMACKey   []byte
}

// BuildHandler constructs a credential-leak ingest handler bound to
// the embedded built_in.yaml pattern library.
//
// Validation mirrors the Python CredentialLeakHandler constructor:
// invalid Action -> error; HMACKey shorter than 16 bytes -> error.
// The handler is safe to share across goroutines and intended to be
// constructed once per Client at plugin startup, not per call.
func BuildHandler(opts BuildHandlerOptions) (*Handler, error) {
	scanner, err := credentialscanner.Default()
	if err != nil {
		return nil, err
	}
	return credentialhook.New(credentialhook.Config{
		Scanner:   scanner,
		Sink:      opts.Sink,
		ProjectID: opts.ProjectID,
		Action:    opts.Action,
		HMACKey:   opts.HMACKey,
	})
}

// OnToolOutput is the per-call entry point. Equivalent to calling
// h.Handle(ctx, in) directly; provided as a free function so
// integrations that already hold a Handler can pass it through one
// helper without re-typing the field accesses.
func OnToolOutput(ctx context.Context, h *Handler, in HandleInput) (HandleOutput, error) {
	return h.Handle(ctx, in)
}
