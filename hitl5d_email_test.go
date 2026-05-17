// HITL-5d Go SDK parity test (gh#537).
//
// Mirrors test_hitl_5d_email_install.py + hitl5dEmailInstall.test.ts:
//
//   - readEmailFromConfig: returns "" on missing / malformed config,
//     returns the persisted email otherwise.
//   - postBatch: stamps X-CZ-Requestor-Email when config has an email,
//     omits the header when it does not, never crashes on a malformed
//     config file.
//
// The Go SDK does not have its own `controlzero install` CLI yet;
// operators install via Python or Node and Go reads the shared
// ~/.controlzero/config.yaml that those CLIs write.

package controlzero

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setFakeHome points HOME at a fresh temp directory for the test, and
// restores the previous value on cleanup. Subsequent calls to
// os.UserHomeDir() (which is what readEmailFromConfig uses) will see
// the temp dir.
func setFakeHome(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	prev, hadHome := os.LookupEnv("HOME")
	if err := os.Setenv("HOME", tmp); err != nil {
		t.Fatalf("Setenv HOME: %v", err)
	}
	t.Cleanup(func() {
		if hadHome {
			_ = os.Setenv("HOME", prev)
		} else {
			_ = os.Unsetenv("HOME")
		}
	})
	return tmp
}

func writeConfigYAML(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".controlzero")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// -----------------------------------------------------------------------
// readEmailFromConfig
// -----------------------------------------------------------------------

func TestReadEmailFromConfig_NoFile(t *testing.T) {
	setFakeHome(t)
	if got := readEmailFromConfig(); got != "" {
		t.Errorf("expected empty string when config.yaml absent, got %q", got)
	}
}

func TestReadEmailFromConfig_HappyPath(t *testing.T) {
	home := setFakeHome(t)
	writeConfigYAML(t, home, "email: alice@acme.com\n")
	if got := readEmailFromConfig(); got != "alice@acme.com" {
		t.Errorf("expected alice@acme.com, got %q", got)
	}
}

func TestReadEmailFromConfig_PreservesOtherKeys(t *testing.T) {
	home := setFakeHome(t)
	writeConfigYAML(t, home, "api_key: cz_test_xyz\nemail: bob@acme.com\n")
	if got := readEmailFromConfig(); got != "bob@acme.com" {
		t.Errorf("expected bob@acme.com, got %q", got)
	}
}

func TestReadEmailFromConfig_MalformedReturnsEmpty(t *testing.T) {
	home := setFakeHome(t)
	writeConfigYAML(t, home, "{not yaml at all")
	if got := readEmailFromConfig(); got != "" {
		t.Errorf("expected empty string on malformed yaml, got %q", got)
	}
}

func TestReadEmailFromConfig_MissingEmailKey(t *testing.T) {
	home := setFakeHome(t)
	writeConfigYAML(t, home, "api_key: cz_test_only\n")
	if got := readEmailFromConfig(); got != "" {
		t.Errorf("expected empty string when email key absent, got %q", got)
	}
}

// -----------------------------------------------------------------------
// postBatch header path
// -----------------------------------------------------------------------

// captureSink spins up a one-shot httptest.Server, swaps in a
// BearerAuditSink pointed at it, and returns the headers the sink sent
// for the first POST. Cleans up the server + closes the sink.
func captureHeadersForPostBatch(t *testing.T) http.Header {
	t.Helper()
	var capturedHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: srv.URL,
		APIKey: "cz_test_key_123",
	})
	sink.Log(map[string]any{"tool": "Bash:ls", "decision": "allow"})

	// Force a flush via Close so the test doesn't wait 30s for the
	// background flushLoop tick.
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}
	// Defensive: give the close-driven flush a beat to write before the
	// test reads capturedHeaders. Close blocks on the flush in current
	// impl, but a small grace keeps the test robust if that changes.
	time.Sleep(20 * time.Millisecond)
	return capturedHeaders
}

func TestPostBatch_NoEmailConfig_NoHeader(t *testing.T) {
	setFakeHome(t)
	hdrs := captureHeadersForPostBatch(t)
	if hdrs == nil {
		t.Fatal("server did not receive any POST")
	}
	if got := hdrs.Get("X-CZ-Requestor-Email"); got != "" {
		t.Errorf("expected no X-CZ-Requestor-Email header, got %q", got)
	}
	if got := hdrs.Get("Authorization"); got != "Bearer cz_test_key_123" {
		t.Errorf("expected Authorization header preserved, got %q", got)
	}
}

func TestPostBatch_WithEmailConfig_StampsHeader(t *testing.T) {
	home := setFakeHome(t)
	writeConfigYAML(t, home, "email: carol@acme.com\n")
	hdrs := captureHeadersForPostBatch(t)
	if hdrs == nil {
		t.Fatal("server did not receive any POST")
	}
	if got := hdrs.Get("X-CZ-Requestor-Email"); got != "carol@acme.com" {
		t.Errorf("expected X-CZ-Requestor-Email=carol@acme.com, got %q", got)
	}
}

func TestPostBatch_MalformedConfig_NoHeaderNoCrash(t *testing.T) {
	home := setFakeHome(t)
	writeConfigYAML(t, home, "{junk}")
	hdrs := captureHeadersForPostBatch(t)
	if hdrs == nil {
		t.Fatal("server did not receive any POST")
	}
	if got := hdrs.Get("X-CZ-Requestor-Email"); got != "" {
		t.Errorf("expected no X-CZ-Requestor-Email header on malformed config, got %q", got)
	}
	if got := hdrs.Get("Authorization"); got != "Bearer cz_test_key_123" {
		t.Errorf("expected Authorization header preserved despite bad config, got %q", got)
	}
}

// Sanity: post-batch payload still parses as JSON with the entry we logged.
// This is the bare minimum guard against future header changes accidentally
// changing the body too.
func TestPostBatch_BodyStillParses(t *testing.T) {
	setFakeHome(t)
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewBearerAuditSink(BearerAuditOptions{APIURL: srv.URL, APIKey: "cz_test_xx"})
	sink.Log(map[string]any{"tool": "Bash:ls", "decision": "allow"})
	_ = sink.Close()
	time.Sleep(20 * time.Millisecond)

	var parsed struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(capturedBody, &parsed); err != nil {
		t.Fatalf("body did not parse as JSON: %v body=%q", err, string(capturedBody))
	}
	if len(parsed.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(parsed.Entries))
	}
	// toWireFormat renames the caller-facing key "tool" to "tool_name"
	// before shipping; assert on the wire shape, not the input shape.
	if parsed.Entries[0]["tool_name"] != "Bash:ls" {
		t.Errorf("expected tool_name=Bash:ls in wire entry, got %v",
			parsed.Entries[0]["tool_name"])
	}
}
