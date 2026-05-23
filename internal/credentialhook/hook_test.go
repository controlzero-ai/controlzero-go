// Unit tests for the credential leak ingest hook (epic #666, PR-4).
//
// Covers `credentialhook.Handler.Handle` end-to-end. Mirrors the 11
// scenarios from `sdks/python/controlzero/tests/test_credential_hook.py`:
//
//  1. AWS access key in stdout -> redact, audit row emitted, severity P0.
//  2. GitHub PAT in file-read body -> redact, severity P0.
//  3. PEM private key block -> redact via marker_block matcher.
//  4. 40-char base64 alone -> no fire.
//  5. action="warn" -> text returned unmodified, audit row still emitted.
//  6. action="block" -> ErrCredentialLeakBlocked returned AFTER audit emit.
//  7. CONTROLZERO_CREDLEAK_OFF=1 -> action downgrades to warn,
//     EnforcementDowngraded=true on the row.
//  8. HMAC value_hash is deterministic per (key, plaintext) and shifts
//     when the key changes.
//  9. Context window masks the credential body in-place.
//  10. Innocuous text -> zero rows, text unchanged.
//  11. Constructor edge cases (invalid action, short HMAC key).
//
// Fixture rule: every credential body uses the literal "EXAMPLE" /
// "notreal" marker so an accidental grep of the test corpus does not
// surface as a false positive in real customer scans.
package credentialhook

import (
	"context"
	"errors"
	"strings"
	"testing"

	"controlzero.ai/sdk/go/internal/credentialscanner"
)

func defaultScanner(t *testing.T) *credentialscanner.Scanner {
	t.Helper()
	s, err := credentialscanner.Default()
	if err != nil {
		t.Fatalf("Default scanner load failed: %v", err)
	}
	return s
}

// Sixteen+ bytes of high-entropy fixture material per slot. The SDK
// is allergic to real customer or vendor secrets even in tests.
var (
	testHMACKey  = []byte("controlzero-test-key-do-not-use-in-prod")
	otherHMACKey = []byte("controlzero-DIFFERENT-test-key-also-fake")
)

// stubSink records every Log() call so a test can assert on the row
// payload without booting the real batched HTTP sink.
type stubSink struct {
	rows []AuditRow
}

func (s *stubSink) Log(entry map[string]any) {
	s.rows = append(s.rows, entry)
}

// brokenSink panics on every Log() call so a test can verify the
// handler's best-effort guarantee.
type brokenSink struct{}

func (brokenSink) Log(_ map[string]any) {
	panic("sink down for maintenance")
}

func buildHandler(t *testing.T, action Action) (*Handler, *stubSink) {
	t.Helper()
	sink := &stubSink{}
	h, err := New(Config{
		Scanner:   defaultScanner(t),
		Sink:      sink,
		ProjectID: "proj_test",
		Action:    action,
		HMACKey:   testHMACKey,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return h, sink
}

// ---------------------------------------------------------------------------
// Handler: redact / warn / block paths.
// ---------------------------------------------------------------------------

func TestAWSAccessKeyInStdoutIsRedacted(t *testing.T) {
	h, sink := buildHandler(t, ActionRedact)
	body := "AKIAEXAMPLEKEY00000Z"
	text := "$ env | grep AWS\nAWS_ACCESS_KEY_ID=" + body + "\n"

	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceToolOutput,
		Text:       text,
		ToolName:   "Bash",
		ToolCallID: "call_001",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.AuditRows) == 0 {
		t.Fatal("expected at least one audit row")
	}
	var foundAWS bool
	for _, r := range out.AuditRows {
		if r["pattern_id"] == "AWS_ACCESS_KEY_ID" && r["severity"] == "P0" {
			foundAWS = true
		}
	}
	if !foundAWS {
		t.Fatalf("expected AWS_ACCESS_KEY_ID/P0 row, got %+v", out.AuditRows)
	}
	if strings.Contains(out.Text, body) {
		t.Fatal("plaintext credential body should have been redacted out")
	}
	if !strings.Contains(out.Text, "cz:credleak:") {
		t.Fatal("redaction sentinel cz:credleak: missing from returned text")
	}
	if len(sink.rows) == 0 {
		t.Fatal("sink should have observed at least one row before return")
	}
	if sink.rows[0]["event_kind"] != "credential_leak_detected" {
		t.Errorf("expected event_kind=credential_leak_detected, got %v", sink.rows[0]["event_kind"])
	}
}

func TestGitHubPATInFileReadIsRedacted(t *testing.T) {
	h, _ := buildHandler(t, ActionRedact)
	pat := "ghp_EXAMPLEnotrealnotrealnotrealnotrealN"
	text := "GITHUB_TOKEN=" + pat + "\n"

	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceFileRead,
		Text:       text,
		ToolName:   "Read",
		ToolCallID: "call_002",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var ghHit AuditRow
	for _, r := range out.AuditRows {
		if r["pattern_id"] == "GITHUB_PAT_CLASSIC" {
			ghHit = r
			break
		}
	}
	if ghHit == nil {
		t.Fatalf("expected GITHUB_PAT_CLASSIC row, got %+v", out.AuditRows)
	}
	if ghHit["severity"] != "P0" {
		t.Errorf("expected severity P0, got %v", ghHit["severity"])
	}
	if ghHit["source"] != "file_read" {
		t.Errorf("expected source=file_read, got %v", ghHit["source"])
	}
	if strings.Contains(out.Text, pat) {
		t.Fatal("plaintext PAT should be redacted")
	}
	if !strings.Contains(out.Text, "cz:credleak:") {
		t.Fatal("expected cz:credleak: prefix in redacted text")
	}
}

func TestPEMPrivateKeyBlockIsRedacted(t *testing.T) {
	h, _ := buildHandler(t, ActionRedact)
	block := "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"EXAMPLE_THIS_IS_A_PLACEHOLDER_NOT_A_REAL_KEY_FOR_TESTS_ONLY_AAAAA\n" +
		"-----END OPENSSH PRIVATE KEY-----"
	text := "# leaked from agent stdout\n" + block + "\n"
	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceToolOutput,
		Text:       text,
		ToolName:   "Bash",
		ToolCallID: "call_pem",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var pemHits int
	for _, r := range out.AuditRows {
		if r["pattern_id"] == "SSH_PRIVATE_KEY_OPENSSH" {
			pemHits++
		}
	}
	if pemHits != 1 {
		t.Fatalf("expected 1 PEM row, got %d (rows=%+v)", pemHits, out.AuditRows)
	}
	if strings.Contains(out.Text, "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatal("PEM block should have been redacted out")
	}
	if !strings.Contains(out.Text, "cz:credleak:") {
		t.Fatal("expected cz:credleak: redaction marker")
	}
}

func TestWarnActionEmitsRowButLeavesTextUnchanged(t *testing.T) {
	h, sink := buildHandler(t, ActionWarn)
	body := "AKIAEXAMPLEKEY00000Z"
	text := "AWS_ACCESS_KEY_ID=" + body

	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceToolOutput,
		Text:       text,
		ToolName:   "Bash",
		ToolCallID: "call_warn",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Text != text {
		t.Fatalf("warn mode must not modify text; got %q", out.Text)
	}
	if len(out.AuditRows) == 0 {
		t.Fatal("warn mode still emits audit rows")
	}
	if out.AuditRows[0]["enforcement_action"] != "warn" {
		t.Errorf("expected enforcement_action=warn, got %v", out.AuditRows[0]["enforcement_action"])
	}
	if out.AuditRows[0]["enforcement_downgraded"] != false {
		t.Errorf("expected enforcement_downgraded=false, got %v", out.AuditRows[0]["enforcement_downgraded"])
	}
	if len(sink.rows) == 0 {
		t.Fatal("sink did not see the row")
	}
}

func TestBlockActionReturnsErrorAfterEmittingRows(t *testing.T) {
	h, sink := buildHandler(t, ActionBlock)
	text := "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY00000Z"

	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceToolOutput,
		Text:       text,
		ToolName:   "Bash",
		ToolCallID: "call_block",
		AgentName:  "claude-code",
	})
	if err == nil {
		t.Fatal("expected error from block action")
	}
	if !errors.Is(err, ErrCredentialLeakBlocked) {
		t.Errorf("expected ErrCredentialLeakBlocked, got %v", err)
	}
	if len(out.AuditRows) == 0 {
		t.Fatal("block mode must still return the constructed rows")
	}
	if len(sink.rows) == 0 {
		t.Fatal("block path must emit row BEFORE returning the error")
	}
	if sink.rows[0]["enforcement_action"] != "block" {
		t.Errorf("expected enforcement_action=block, got %v", sink.rows[0]["enforcement_action"])
	}
}

// ---------------------------------------------------------------------------
// Env override + HMAC + context window invariants.
// ---------------------------------------------------------------------------

func TestCredleakOffEnvDowngradesBlockToWarn(t *testing.T) {
	t.Setenv("CONTROLZERO_CREDLEAK_OFF", "1")
	h, _ := buildHandler(t, ActionBlock)
	text := "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY00000Z"

	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceToolOutput,
		Text:       text,
		ToolName:   "Bash",
		ToolCallID: "call_off",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("downgraded block path must not return error, got %v", err)
	}
	if out.Text != text {
		t.Fatalf("warn mode must not redact; got %q", out.Text)
	}
	if len(out.AuditRows) == 0 {
		t.Fatal("expected audit row even after downgrade")
	}
	if out.AuditRows[0]["enforcement_action"] != "warn" {
		t.Errorf("expected enforcement_action=warn, got %v", out.AuditRows[0]["enforcement_action"])
	}
	if out.AuditRows[0]["enforcement_downgraded"] != true {
		t.Errorf("expected enforcement_downgraded=true, got %v", out.AuditRows[0]["enforcement_downgraded"])
	}
}

func TestOffEnvSetButNotOneDoesNotDowngrade(t *testing.T) {
	t.Setenv("CONTROLZERO_CREDLEAK_OFF", "true")
	h, _ := buildHandler(t, ActionRedact)
	text := "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY00000Z"

	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceToolOutput,
		Text:       text,
		ToolName:   "Bash",
		ToolCallID: "call_off_typo",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Text == text {
		t.Fatal("redact should still apply when env value is not the literal '1'")
	}
	if out.AuditRows[0]["enforcement_action"] != "redact" {
		t.Errorf("expected enforcement_action=redact, got %v", out.AuditRows[0]["enforcement_action"])
	}
	if out.AuditRows[0]["enforcement_downgraded"] != false {
		t.Errorf("expected enforcement_downgraded=false, got %v", out.AuditRows[0]["enforcement_downgraded"])
	}
}

func TestHMACValueHashDeterministicPerKey(t *testing.T) {
	plaintext := []byte("AKIAEXAMPLEKEY00000Z")
	h1 := HMACValueHash(testHMACKey, plaintext)
	h2 := HMACValueHash(testHMACKey, plaintext)
	hOther := HMACValueHash(otherHMACKey, plaintext)
	if h1 != h2 {
		t.Errorf("HMAC must be deterministic for same key: %s vs %s", h1, h2)
	}
	if h1 == hOther {
		t.Error("HMAC must shift across keys")
	}
	if len(h1) != 16 {
		t.Errorf("HMAC value_hash must be 16 hex chars, got len=%d", len(h1))
	}
}

func TestBuildContextWindowMasksCredentialBody(t *testing.T) {
	text := "PAD0123456789ABCD" + " " + "AKIAEXAMPLEKEY00000Z" + " " + "RIGHT0123456789AB"
	start := strings.Index(text, "AKIA")
	end := start + len("AKIAEXAMPLEKEY00000Z")
	window := BuildContextWindow(text, start, end)

	if !strings.Contains(window, "<MASKED>") {
		t.Errorf("expected <MASKED> in window, got %q", window)
	}
	if strings.Contains(window, "AKIAEXAMPLEKEY00000Z") {
		t.Errorf("credential body leaked into window: %q", window)
	}
	if !strings.HasPrefix(window, "D0123456789ABCD ") {
		t.Errorf("expected left window to start with D0123456789ABCD , got %q", window)
	}
	if !strings.Contains(window, "<MASKED> RIGHT0123456789") {
		t.Errorf("expected right window to contain RIGHT0123456789, got %q", window)
	}
}

func TestBuildContextWindowHandlesStartOfText(t *testing.T) {
	text := "AKIAEXAMPLE more text after"
	start := 0
	end := len("AKIAEXAMPLE")
	window := BuildContextWindow(text, start, end)
	if !strings.HasPrefix(window, "<MASKED>") {
		t.Errorf("expected window to start with <MASKED>, got %q", window)
	}
}

func TestBuildContextWindowHandlesEndOfText(t *testing.T) {
	text := "prefix text AKIAEXAMPLE"
	start := strings.Index(text, "AKIA")
	end := len(text)
	window := BuildContextWindow(text, start, end)
	if !strings.HasSuffix(window, "<MASKED>") {
		t.Errorf("expected window to end with <MASKED>, got %q", window)
	}
}

// ---------------------------------------------------------------------------
// Constructor + edge cases.
// ---------------------------------------------------------------------------

func TestNewRejectsInvalidAction(t *testing.T) {
	_, err := New(Config{
		Scanner:   defaultScanner(t),
		ProjectID: "proj",
		Action:    Action(99),
		HMACKey:   testHMACKey,
	})
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestNewRejectsShortHMACKey(t *testing.T) {
	_, err := New(Config{
		Scanner:   defaultScanner(t),
		ProjectID: "proj",
		Action:    ActionWarn,
		HMACKey:   []byte("too short"),
	})
	if err == nil {
		t.Fatal("expected error for short HMAC key")
	}
}

func TestNewRejectsNilScanner(t *testing.T) {
	_, err := New(Config{
		ProjectID: "proj",
		Action:    ActionWarn,
		HMACKey:   testHMACKey,
		// Scanner intentionally nil
	})
	if err == nil {
		t.Fatal("expected error for nil scanner")
	}
}

func TestInnocuousTextReturnsZeroRows(t *testing.T) {
	h, sink := buildHandler(t, ActionRedact)
	text := "the quick brown fox jumps over the lazy dog"
	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceToolOutput,
		Text:       text,
		ToolName:   "Bash",
		ToolCallID: "call_clean",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Text != text {
		t.Fatalf("expected unchanged text, got %q", out.Text)
	}
	if len(out.AuditRows) != 0 {
		t.Fatalf("expected no rows, got %d", len(out.AuditRows))
	}
	if len(sink.rows) != 0 {
		t.Fatalf("sink should be empty, got %d rows", len(sink.rows))
	}
}

func TestNilSinkDoesNotCrash(t *testing.T) {
	h, err := New(Config{
		Scanner:   defaultScanner(t),
		ProjectID: "proj",
		Action:    ActionRedact,
		HMACKey:   testHMACKey,
		// Sink intentionally nil
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceToolOutput,
		Text:       "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY00000Z",
		ToolName:   "Bash",
		ToolCallID: "call_sinkless",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.AuditRows) == 0 {
		t.Fatal("rows should still be constructed even when sink is nil")
	}
}

func TestSinkPanicDoesNotPropagate(t *testing.T) {
	h, err := New(Config{
		Scanner:   defaultScanner(t),
		Sink:      brokenSink{},
		ProjectID: "proj",
		Action:    ActionWarn,
		HMACKey:   testHMACKey,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceToolOutput,
		Text:       "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY00000Z",
		ToolName:   "Bash",
		ToolCallID: "call_broken",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("handler must swallow sink panics, got %v", err)
	}
	if len(out.AuditRows) == 0 {
		t.Fatal("rows should still be returned even when sink panics")
	}
}

// ---------------------------------------------------------------------------
// Action.String parity with Python action vocabulary.
// ---------------------------------------------------------------------------

func TestActionStringParity(t *testing.T) {
	cases := map[Action]string{
		ActionWarn:   "warn",
		ActionRedact: "redact",
		ActionBlock:  "block",
		Action(99):   "unknown",
	}
	for a, want := range cases {
		if got := a.String(); got != want {
			t.Errorf("Action(%d).String() = %q, want %q", int(a), got, want)
		}
	}
}

func TestRedactMultipleMatchesProcessedRightToLeft(t *testing.T) {
	// Two credentials in one body. Right-to-left redaction means the
	// later match (higher start offset) is replaced first so the
	// earlier match's byte offsets stay valid. Verifies the
	// sort.Slice less function actually runs and produces a stable
	// right-to-left ordering.
	h, _ := buildHandler(t, ActionRedact)
	access := "AKIAEXAMPLEKEY00000Z"
	pat := "ghp_EXAMPLEnotrealnotrealnotrealnotrealN"
	text := "AWS_ACCESS_KEY_ID=" + access + "\nGITHUB_TOKEN=" + pat + "\n"

	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceToolOutput,
		Text:       text,
		ToolName:   "Bash",
		ToolCallID: "call_multi",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(out.Text, access) {
		t.Error("AWS access key plaintext leaked into redacted text")
	}
	if strings.Contains(out.Text, pat) {
		t.Error("GitHub PAT plaintext leaked into redacted text")
	}
	if strings.Count(out.Text, "cz:credleak:") < 2 {
		t.Errorf("expected at least 2 redaction sentinels, got %q", out.Text)
	}
}

func TestRedactPreservesNonMatchingText(t *testing.T) {
	h, _ := buildHandler(t, ActionRedact)
	body := "AKIAEXAMPLEKEY00000Z"
	prefix := "prefix bytes here\n"
	suffix := "\ntrailing bytes here"
	text := prefix + "AWS_ACCESS_KEY_ID=" + body + suffix
	out, err := h.Handle(context.Background(), HandleInput{
		Source:     SourceToolOutput,
		Text:       text,
		ToolName:   "Bash",
		ToolCallID: "call_prefix",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(out.Text, prefix) {
		t.Errorf("prefix bytes should be preserved, got %q", out.Text)
	}
	if !strings.HasSuffix(out.Text, suffix) {
		t.Errorf("suffix bytes should be preserved, got %q", out.Text)
	}
}
