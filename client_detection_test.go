package controlzero

// T92 parity coverage with sdks/python/controlzero/tests/test_device.py
// and sdks/node/controlzero/tests/clientDetection.test.ts.
//
// the deny-deny incident, 2026-05-10: Cursor user got mislabeled as
// Gemini CLI because the prior detection (Node + Go used narrow
// signals; Python used a broad GEMINI_ prefix) drifted across SDKs.
// These tests assert the narrowed-signal behavior locked in across
// all three SDKs:
//   - each tool detected only via env vars it actually ships;
//   - GEMINI_API_KEY no longer mislabels SDK-direct users;
//   - Cursor wins over Gemini in the priority order;
//   - Codex CLI wins over Cursor wins over Gemini when multiple match.

import (
	"testing"
)

// All env keys the detector inspects. Used to sandbox each test from
// host environment leakage. t.Setenv("", "") would clear individually,
// but Go's testing package only restores keys that were Set, not
// keys that were already unset; sniffedKeys lets us be explicit.
var sniffedKeys = []string{
	"CONTROLZERO_CLIENT",
	"CONTROLZERO_CLIENT_NAME",
	"CLAUDECODE",
	"CLAUDE_CODE",
	"CODEX_HOME",
	"CODEX_PROFILE",
	"CODEX_CLI",
	"CURSOR_TRACE_ID",
	"CURSOR_AGENT",
	"CURSOR_USER_AGENT",
	"TERM_PROGRAM",
	"WINDSURF_AGENT",
	"WINDSURF_SESSION_ID",
	"GEMINI_CLI",
	"GEMINI_SANDBOX",
	"GEMINI_SYSTEM_MD",
	"GEMINI_API_KEY",
}

// clearSniffedEnv unsets every env var the detector sniffs, using
// t.Setenv so values are restored at test-end. Using t.Setenv("", "")
// vs os.Unsetenv ensures Go's testing harness handles cleanup even on
// panic.
func clearSniffedEnv(t *testing.T) {
	t.Helper()
	for _, k := range sniffedKeys {
		t.Setenv(k, "")
	}
}

func TestDetectClientName_DefaultIsGoSDK(t *testing.T) {
	clearSniffedEnv(t)
	if got := detectClientName(); got != "go-sdk" {
		t.Errorf("default expected go-sdk, got %q", got)
	}
}

func TestDetectClientName_ControlZeroClientWinsOverEverything(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("CONTROLZERO_CLIENT", "my-custom")
	t.Setenv("CLAUDECODE", "1") // would otherwise match
	t.Setenv("CURSOR_TRACE_ID", "trace")
	if got := detectClientName(); got != "my-custom" {
		t.Errorf("explicit override expected my-custom, got %q", got)
	}
}

func TestDetectClientName_LegacyControlZeroClientNameAliasPreserved(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("CONTROLZERO_CLIENT_NAME", "legacy-name")
	if got := detectClientName(); got != "legacy-name" {
		t.Errorf("CONTROLZERO_CLIENT_NAME expected legacy-name, got %q", got)
	}
}

func TestDetectClientName_ClaudeCode_Claudecode(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("CLAUDECODE", "1")
	if got := detectClientName(); got != "claude-code" {
		t.Errorf("CLAUDECODE expected claude-code, got %q", got)
	}
}

func TestDetectClientName_ClaudeCode_LegacyClaudeCodeFallback(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("CLAUDE_CODE", "1")
	if got := detectClientName(); got != "claude-code" {
		t.Errorf("CLAUDE_CODE legacy expected claude-code, got %q", got)
	}
}

func TestDetectClientName_CodexCLI_CodexHome(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("CODEX_HOME", "/Users/x/.codex")
	if got := detectClientName(); got != "codex-cli" {
		t.Errorf("CODEX_HOME expected codex-cli, got %q", got)
	}
}

func TestDetectClientName_CodexCLI_CodexProfile(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("CODEX_PROFILE", "work")
	if got := detectClientName(); got != "codex-cli" {
		t.Errorf("CODEX_PROFILE expected codex-cli, got %q", got)
	}
}

func TestDetectClientName_Cursor_TraceID(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("CURSOR_TRACE_ID", "abc")
	if got := detectClientName(); got != "cursor" {
		t.Errorf("CURSOR_TRACE_ID expected cursor, got %q", got)
	}
}

func TestDetectClientName_Cursor_TermProgram(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("TERM_PROGRAM", "cursor")
	if got := detectClientName(); got != "cursor" {
		t.Errorf("TERM_PROGRAM=cursor expected cursor, got %q", got)
	}
}

func TestDetectClientName_Windsurf(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("WINDSURF_AGENT", "1")
	if got := detectClientName(); got != "windsurf" {
		t.Errorf("WINDSURF_AGENT expected windsurf, got %q", got)
	}
}

func TestDetectClientName_GeminiCLI_RuntimeSignal(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("GEMINI_CLI", "1")
	if got := detectClientName(); got != "gemini-cli" {
		t.Errorf("GEMINI_CLI expected gemini-cli, got %q", got)
	}
}

func TestDetectClientName_GeminiCLI_SandboxSignal(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("GEMINI_SANDBOX", "1")
	if got := detectClientName(); got != "gemini-cli" {
		t.Errorf("GEMINI_SANDBOX expected gemini-cli, got %q", got)
	}
}

// T92 regression: the 2026-05-10-class shape. Pre-T92 in the Python SDK a
// GEMINI_API_KEY export silently mislabeled SDK-direct users as
// "gemini-cli". The Go SDK historically did NOT have this bug
// (already used narrow GEMINI_CLI check), but the test locks the
// behavior in so a future rewrite cannot regress.
func TestDetectClientName_GeminiAPIKey_DoesNOTTriggerGeminiCLI(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("GEMINI_API_KEY", "fake-google-key")
	if got := detectClientName(); got != "go-sdk" {
		t.Errorf("GEMINI_API_KEY must not trigger gemini-cli; got %q", got)
	}
}

// T92 regression: Cursor user with GEMINI_API_KEY exported for direct
// Google API access must resolve to "cursor", not "gemini-cli".
// Cursor is checked before Gemini so legitimate IDE usage is not
// stomped by an unrelated API key. the exact 2026-05-10 shape.
func TestDetectClientName_CursorBeatsGeminiAPIKey(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("CURSOR_TRACE_ID", "trace")
	t.Setenv("GEMINI_API_KEY", "fake-google-key")
	if got := detectClientName(); got != "cursor" {
		t.Errorf("Cursor must beat GEMINI_API_KEY; got %q", got)
	}
}

// Codex before Cursor before Gemini. Verify priority ordering when
// all three signals are present.
func TestDetectClientName_Priority_CodexBeatsCursorBeatsGemini(t *testing.T) {
	clearSniffedEnv(t)
	t.Setenv("CODEX_HOME", "/Users/x/.codex")
	t.Setenv("CURSOR_TRACE_ID", "trace")
	t.Setenv("GEMINI_CLI", "1")
	if got := detectClientName(); got != "codex-cli" {
		t.Errorf("Codex must beat Cursor and Gemini; got %q", got)
	}
}
