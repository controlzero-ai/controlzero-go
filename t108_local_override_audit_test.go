package controlzero

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T108 regression: LOCAL_OVERRIDE emits a governance audit event (Go).
//
// Mirror of Python's test_t108_local_override_audit.py and Node's
// localOverrideAudit.test.ts. When a user sets CONTROLZERO_LOCAL_OVERRIDE=1
// with an api_key, the SDK bypasses the hosted bundle. T108 emits a
// one-shot audit event so ops sees the bypass in the audit dashboard.
//
// Go does not run the bearer sink against a real backend in tests
// because the network is sandboxed. Instead we route the entry through
// the LocalAuditLogger fallback (which fires when bearerSink is nil)
// and read the audit.log JSON. This keeps the tests deterministic and
// hermetic.

func TestT108_LocalOverride_EmitsAuditEvent(t *testing.T) {
	cwd := setupSandboxCwd(t)
	t.Setenv("CONTROLZERO_API_KEY", "")
	t.Setenv("CONTROLZERO_LOCAL_OVERRIDE", "1")
	t.Setenv("CONTROLZERO_QUIET", "1")

	pol := filepath.Join(cwd, "controlzero.yaml")
	if err := os.WriteFile(pol, []byte("rules:\n  - allow: '*'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Build the entry directly via the unexported helper to verify the
	// envelope shape independent of the network. We construct a Client
	// in pure-local mode (no api_key) so the bearer sink is nil and the
	// local audit logger receives the event. We then set api_key on the
	// client struct after construction and invoke the helper directly,
	// asserting the entry shape that would have been posted.
	cz, err := New(WithLogPath(filepath.Join(cwd, "audit.log")))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cz.emitLocalOverrideAuditEvent("/tmp/controlzero.yaml")
	_ = cz.Close()

	raw, err := os.ReadFile(filepath.Join(cwd, "audit.log"))
	if err != nil {
		t.Fatalf("read audit.log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 {
		t.Fatalf("expected at least one audit line, got empty file")
	}
	var found map[string]any
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if rc, _ := entry["reason_code"].(string); rc == "LOCAL_OVERRIDE_ACTIVE" {
			found = entry
			break
		}
	}
	if found == nil {
		t.Fatalf("LOCAL_OVERRIDE_ACTIVE audit entry not found in:\n%s", string(raw))
	}
	if decision, _ := found["decision"].(string); decision != "audit" {
		t.Errorf("expected decision=audit, got %v", found["decision"])
	}
	if pid, _ := found["policy_id"].(string); pid != "<lifecycle>" {
		t.Errorf("expected policy_id=<lifecycle>, got %v", found["policy_id"])
	}
	if mode, _ := found["mode"].(string); mode != "lifecycle" {
		t.Errorf("expected mode=lifecycle, got %v", found["mode"])
	}
	if reason, _ := found["reason"].(string); !strings.Contains(reason, "CONTROLZERO_LOCAL_OVERRIDE") {
		t.Errorf("expected reason to mention env var, got %q", reason)
	}
}

func TestT108_LocalOverride_WireFormatCarriesReasonCode(t *testing.T) {
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "http://127.0.0.1:1",
		APIKey: "cz_test_fake",
	})
	defer sink.Close()

	wire := sink.toWireFormat(map[string]any{
		"tool":        "_lifecycle",
		"decision":    "audit",
		"reason_code": "LOCAL_OVERRIDE_ACTIVE",
		"reason":      "bypass",
		"policy_id":   "<lifecycle>",
	})
	if wire["reason_code"] != "LOCAL_OVERRIDE_ACTIVE" {
		t.Errorf("expected reason_code=LOCAL_OVERRIDE_ACTIVE, got %v", wire["reason_code"])
	}
	if wire["decision"] != "audit" {
		t.Errorf("expected decision=audit, got %v", wire["decision"])
	}
	if wire["policy_id"] != "<lifecycle>" {
		t.Errorf("expected policy_id=<lifecycle>, got %v", wire["policy_id"])
	}
}

func TestT108_NoOverride_NoEvent(t *testing.T) {
	cwd := setupSandboxCwd(t)
	t.Setenv("CONTROLZERO_API_KEY", "")
	t.Setenv("CONTROLZERO_LOCAL_OVERRIDE", "")
	t.Setenv("CONTROLZERO_QUIET", "1")

	pol := filepath.Join(cwd, "controlzero.yaml")
	if err := os.WriteFile(pol, []byte("rules:\n  - allow: '*'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cz, err := New(WithLogPath(filepath.Join(cwd, "audit.log")))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = cz.Close()

	// audit.log either doesn't exist (no calls) or has no
	// LOCAL_OVERRIDE_ACTIVE entries.
	raw, err := os.ReadFile(filepath.Join(cwd, "audit.log"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read audit.log: %v", err)
	}
	if strings.Contains(string(raw), "LOCAL_OVERRIDE_ACTIVE") {
		t.Errorf("did not expect LOCAL_OVERRIDE_ACTIVE in audit.log: %s", string(raw))
	}
}
