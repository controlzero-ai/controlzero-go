package controlzero

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Source-label canonicalisation shared across all three SDKs.
//
// #461 (epic #448). The SDK historically emits a free-form client_name
// ("claude-code", "gemini-cli", "go-sdk", ...) and the backend
// audit-ingest path (apps/control-zero-platform/backend/internal/audit/
// source.go NormalizeSource) maps it to a canonical snake_case source
// value ("claude_code", "gemini_cli", "go_sdk", ...).
//
// Doing that mapping ONLY at the gateway has two problems the issue calls
// out: concurrent SDK requests can interleave a stale source mapping, and
// customers see different audit.source values for what is the same SDK
// install. Centralising the alias -> canonical table here lets each SDK
// canonicalise the label itself with the SAME mapping the backend uses,
// so the canonical token can be sent directly and the result is
// deterministic.
//
// The alias table is the single source of truth across all three SDKs
// (Python / Node / Go). The cross-SDK fixture at
// tests/parity/source_labels.json is byte-identical to the JSON dump of
// this table; drift in any SDK breaks the parity test in each SDK
// (mirrors the T84 action_aliases pattern). The alias map mirrors the
// backend clientNameAliases exactly; when the backend table changes,
// update the fixture and all three SDK canonicalisers in the same PR.
//
// This file is pure data + a lookup; it deliberately does NOT change what
// detectClientName returns on the wire. Flipping the detector to emit
// canonical tokens directly is a separate, behaviour-changing step (it
// alters live audit attribution for existing installs and the documented
// client_name vocabulary) and is tracked as a follow-up.

// SourceUnknown is the total-function fallback the frontend renders as
// "--" (#344).
const SourceUnknown = "unknown"

// canonicalSources lists the canonical snake_case source values in the
// same order as the backend audit.Source* constant block and the parity
// fixture's "canonical" array.
var canonicalSources = []string{
	"claude_code",
	"gemini_cli",
	"codex_cli",
	"kiro_cli",
	"kiro_ide",
	"antigravity",
	"antigravity_ide",
	"antigravity_cli",
	"cursor_ide",
	"cursor_cli",
	"mcp_server",
	"python_sdk",
	"node_sdk",
	"go_sdk",
	"gateway",
	"unknown",
}

// sourceAliasPair is one alias -> canonical mapping. An ordered slice
// (rather than a bare map) so the JSON dump is deterministic and
// byte-identical to the cross-SDK fixture.
type sourceAliasPair struct {
	alias string
	canon string
}

// sourceAliases mirrors backend audit.clientNameAliases minus the two
// pure-fallback entries ("sdk" and "") which both resolve to "unknown"
// via the total-function default.
var sourceAliases = []sourceAliasPair{
	{"claude-code", "claude_code"},
	{"claude_code", "claude_code"},
	{"claudecode", "claude_code"},
	{"gemini-cli", "gemini_cli"},
	{"gemini_cli", "gemini_cli"},
	{"gemini", "gemini_cli"},
	{"codex-cli", "codex_cli"},
	{"codex_cli", "codex_cli"},
	{"codex", "codex_cli"},
	{"kiro-cli", "kiro_cli"},
	{"kiro_cli", "kiro_cli"},
	{"kiro-ide", "kiro_ide"},
	{"kiro_ide", "kiro_ide"},
	{"antigravity", "antigravity"},
	{"agy", "antigravity"},
	{"antigravity-cli", "antigravity"},
	{"antigravity_ide", "antigravity_ide"},
	{"antigravity-ide", "antigravity_ide"},
	{"antigravity_cli", "antigravity_cli"},
	{"cursor-ide", "cursor_ide"},
	{"cursor_ide", "cursor_ide"},
	{"cursor", "cursor_ide"},
	{"cursor-cli", "cursor_cli"},
	{"cursor_cli", "cursor_cli"},
	{"cursor-agent", "cursor_cli"},
	{"cursor_agent", "cursor_cli"},
	{"mcp", "mcp_server"},
	{"mcp-server", "mcp_server"},
	{"mcp_server", "mcp_server"},
	{"python", "python_sdk"},
	{"python-sdk", "python_sdk"},
	{"python_sdk", "python_sdk"},
	{"node", "node_sdk"},
	{"nodejs", "node_sdk"},
	{"node-sdk", "node_sdk"},
	{"node_sdk", "node_sdk"},
	{"go", "go_sdk"},
	{"go-sdk", "go_sdk"},
	{"go_sdk", "go_sdk"},
	{"gateway", "gateway"},
	{"cz-gateway", "gateway"},
}

// Built once at package init for O(1) lookup on the hot path.
var sourceAliasIndex map[string]string
var canonicalSourceSet map[string]struct{}

func init() {
	sourceAliasIndex = make(map[string]string, len(sourceAliases))
	for _, p := range sourceAliases {
		sourceAliasIndex[p.alias] = p.canon
	}
	canonicalSourceSet = make(map[string]struct{}, len(canonicalSources))
	for _, c := range canonicalSources {
		canonicalSourceSet[c] = struct{}{}
	}
}

// CanonicalizeSource maps a free-form source / client_name label to its
// canonical token. Total function: any input resolves to a value in
// canonicalSources. Empty / unrecognised inputs collapse to "unknown".
// Resolution mirrors the backend audit.NormalizeSource explicit /
// client_name lookups.
func CanonicalizeSource(label string) string {
	raw := strings.ToLower(strings.TrimSpace(label))
	if raw == "" {
		return SourceUnknown
	}
	// Direct alias hit on the raw (hyphen-preserving) form first.
	if canon, ok := sourceAliasIndex[raw]; ok {
		return canon
	}
	// Fold hyphen/space to underscore and retry (the lenient explicit path).
	folded := strings.ReplaceAll(strings.ReplaceAll(raw, "-", "_"), " ", "_")
	if _, ok := canonicalSourceSet[folded]; ok {
		return folded
	}
	if canon, ok := sourceAliasIndex[folded]; ok {
		return canon
	}
	return SourceUnknown
}

// IsCanonicalSource reports whether label is already a canonical source
// value.
func IsCanonicalSource(label string) bool {
	_, ok := canonicalSourceSet[label]
	return ok
}

// sourceLabelsJSON returns the canonicalisation table as deterministic
// JSON. Byte-identical to tests/parity/source_labels.json minus the
// dev-only "comment" key. The cross-SDK parity test asserts this equality
// so the Python / Node / Go tables can never drift.
//
// Hand-rolled rather than json.Marshal of a map[string]string because Go
// sorts map keys on marshal, which would not preserve the fixture's
// insertion order. We emit the same 2-space-indented shape the Python
// json.dumps(indent=2) and Node JSON.stringify(_, null, 2) produce.
func sourceLabelsJSON() string {
	var b bytes.Buffer
	b.WriteString("{\n")
	b.WriteString("  \"version\": 1,\n")
	b.WriteString("  \"canonical\": [\n")
	for i, c := range canonicalSources {
		b.WriteString("    ")
		b.Write(mustJSON(c))
		if i < len(canonicalSources)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  ],\n")
	b.WriteString("  \"aliases\": {\n")
	for i, p := range sourceAliases {
		b.WriteString("    ")
		b.Write(mustJSON(p.alias))
		b.WriteString(": ")
		b.Write(mustJSON(p.canon))
		if i < len(sourceAliases)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  }\n")
	b.WriteString("}")
	return b.String()
}

// mustJSON marshals a string to its JSON-escaped, quoted form. String
// marshalling never errors, so the error is intentionally dropped.
func mustJSON(s string) []byte {
	out, _ := json.Marshal(s)
	return out
}
