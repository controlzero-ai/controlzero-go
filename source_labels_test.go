package controlzero

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Cross-SDK source-label canonicalisation parity (#461 / epic #448).
//
// Mirrors the cross-SDK fixture at tests/parity/source_labels.json. The
// same shape of tests runs in the Python SDK (test_source_labels.py) and
// the Node SDK (sourceLabels.test.ts). Drift in any SDK breaks parity
// here.
//
// The canonicaliser maps the SDK's free-form client_name / source label to
// the canonical snake_case source value the backend audit-ingest path
// (audit.NormalizeSource) produces, so audit.source is deterministic and
// no longer depends on a race-prone gateway normalisation.

func findSourceParityFixture(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "tests", "parity", "source_labels.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("tests/parity/source_labels.json not found")
	return ""
}

// canonicalizeSourceFixture re-encodes the on-disk fixture in the SDK's
// fixed key order so the dump can be compared byte-for-byte. Go drops map
// key order on json.Unmarshal, so the canonical ordering is driven by the
// SDK's own ordered tables (canonicalSources / sourceAliases) while the
// VALUES are read from the parsed fixture -- which is what proves the SDK
// table matches the fixture content.
func canonicalizeSourceFixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(findSourceParityFixture(t))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct {
		Canonical []string          `json:"canonical"`
		Aliases   map[string]string `json:"aliases"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	// Content check 1: the fixture's canonical array equals the SDK's.
	if len(fx.Canonical) != len(canonicalSources) {
		t.Fatalf("canonical length drift: fixture %d, sdk %d", len(fx.Canonical), len(canonicalSources))
	}
	for i := range canonicalSources {
		if fx.Canonical[i] != canonicalSources[i] {
			t.Fatalf("canonical[%d] drift: fixture %q, sdk %q", i, fx.Canonical[i], canonicalSources[i])
		}
	}
	// Content check 2: every SDK alias is present in the fixture with the
	// same canonical, and the counts match (no fixture-only aliases).
	if len(fx.Aliases) != len(sourceAliases) {
		t.Fatalf("alias count drift: fixture %d, sdk %d", len(fx.Aliases), len(sourceAliases))
	}
	for _, p := range sourceAliases {
		if got, ok := fx.Aliases[p.alias]; !ok || got != p.canon {
			t.Fatalf("alias %q drift: fixture %q (present=%v), sdk %q", p.alias, got, ok, p.canon)
		}
	}

	var b []byte
	b = append(b, "{\n  \"version\": 1,\n  \"canonical\": [\n"...)
	for i, c := range canonicalSources {
		cb, _ := json.Marshal(c)
		b = append(b, "    "...)
		b = append(b, cb...)
		if i < len(canonicalSources)-1 {
			b = append(b, ',')
		}
		b = append(b, '\n')
	}
	b = append(b, "  ],\n  \"aliases\": {\n"...)
	for i, p := range sourceAliases {
		ab, _ := json.Marshal(p.alias)
		vb, _ := json.Marshal(fx.Aliases[p.alias])
		b = append(b, "    "...)
		b = append(b, ab...)
		b = append(b, ": "...)
		b = append(b, vb...)
		if i < len(sourceAliases)-1 {
			b = append(b, ',')
		}
		b = append(b, '\n')
	}
	b = append(b, "  }\n}"...)
	return string(b)
}

func TestSourceLabelParity_JSONDumpMatchesFixture(t *testing.T) {
	expected := canonicalizeSourceFixture(t)
	if got := sourceLabelsJSON(); got != expected {
		t.Fatalf("sourceLabelsJSON drift\n--- expected ---\n%s\n--- got ---\n%s\n", expected, got)
	}
}

func TestSourceLabelParity_SHA256MatchesFixture(t *testing.T) {
	expected := canonicalizeSourceFixture(t)
	want := sha256.Sum256([]byte(expected))
	got := sha256.Sum256([]byte(sourceLabelsJSON()))
	if hex.EncodeToString(want[:]) != hex.EncodeToString(got[:]) {
		t.Fatalf("source label sha256 drift: want %x got %x", want, got)
	}
}

func TestCanonicalizeSource_HyphenatedClientNames(t *testing.T) {
	cases := map[string]string{
		"claude-code":  "claude_code",
		"gemini-cli":   "gemini_cli",
		"codex-cli":    "codex_cli",
		"kiro-cli":     "kiro_cli",
		"kiro-ide":     "kiro_ide",
		"cursor":       "cursor_ide",
		"cursor-agent": "cursor_cli",
		"python-sdk":   "python_sdk",
		"node-sdk":     "node_sdk",
		"go-sdk":       "go_sdk",
		"agy":          "antigravity",
		"mcp":          "mcp_server",
	}
	for label, want := range cases {
		if got := CanonicalizeSource(label); got != want {
			t.Errorf("CanonicalizeSource(%q) = %q, want %q", label, got, want)
		}
	}
}

func TestCanonicalizeSource_AlreadyCanonicalPassthrough(t *testing.T) {
	for _, c := range canonicalSources {
		if got := CanonicalizeSource(c); got != c {
			t.Errorf("CanonicalizeSource(%q) = %q, want passthrough", c, got)
		}
	}
}

func TestCanonicalizeSource_CaseAndWhitespace(t *testing.T) {
	if got := CanonicalizeSource("  Claude-Code  "); got != "claude_code" {
		t.Errorf("trim/case = %q, want claude_code", got)
	}
	if got := CanonicalizeSource("Claude Code"); got != "claude_code" {
		t.Errorf("space-fold = %q, want claude_code", got)
	}
}

func TestCanonicalizeSource_UnknownAndEmpty(t *testing.T) {
	for _, label := range []string{"", "   ", "sdk", "totally-made-up"} {
		if got := CanonicalizeSource(label); got != SourceUnknown {
			t.Errorf("CanonicalizeSource(%q) = %q, want unknown", label, got)
		}
	}
}

func TestIsCanonicalSource(t *testing.T) {
	if !IsCanonicalSource("go_sdk") {
		t.Error("go_sdk should be canonical")
	}
	if IsCanonicalSource("go-sdk") {
		t.Error("go-sdk should NOT be canonical")
	}
}
