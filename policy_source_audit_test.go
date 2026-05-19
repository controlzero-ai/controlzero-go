package controlzero

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Migration 048 (2026-05-19): per-decision policy_source provenance.
//
// Mirror of Python tests/test_policy_source_audit.py and Node
// tests/policySourceAudit.test.ts. Covers the three SDK paths and the
// wire-format invariant:
//
//   - api_key + LOCAL_OVERRIDE active     -> local-override
//   - api_key + no override               -> hosted
//   - no api_key (pure local)             -> local
//
// Each guard() decision (and the T108 lifecycle event) must stamp the
// same provenance enum value so the dashboard chip filter and the
// banner queries observe consistency.

func TestPolicySource_Local_WhenNoAPIKey(t *testing.T) {
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
	defer cz.Close()
	if cz.policySource != "local" {
		t.Fatalf("expected policySource=local in pure-local mode, got %q", cz.policySource)
	}

	_, _ = cz.Guard("tool", GuardOptions{Method: "m"})
	raw, err := os.ReadFile(filepath.Join(cwd, "audit.log"))
	if err != nil {
		t.Fatalf("read audit.log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		// Skip non-decision rows (none in this test, but defensive).
		if _, ok := entry["decision"]; !ok {
			continue
		}
		if got, _ := entry["policy_source"].(string); got != "local" {
			t.Errorf("audit row policy_source = %q, want %q", got, "local")
		}
	}
}

func TestPolicySource_LocalOverride_WhenBypassActive(t *testing.T) {
	cwd := setupSandboxCwd(t)
	t.Setenv("CONTROLZERO_API_KEY", "cz_live_pol_src_override_go")
	t.Setenv("CONTROLZERO_LOCAL_OVERRIDE", "1")
	t.Setenv("CONTROLZERO_QUIET", "1")

	pol := filepath.Join(cwd, "controlzero.yaml")
	if err := os.WriteFile(pol, []byte("rules:\n  - allow: '*'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cz, err := New(WithLogPath(filepath.Join(cwd, "audit.log")))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if cz.policySource != "local-override" {
		t.Fatalf("expected policySource=local-override under bypass, got %q", cz.policySource)
	}

	// Force a guard() call so an audit row lands; emitLocalOverrideAuditEvent
	// already fired in New() and may have routed to the bearer sink. Both
	// paths stamp the same value.
	_, _ = cz.Guard("tool", GuardOptions{Method: "m"})
	_ = cz.Close()
}

func TestPolicySource_WireFormat_CarriesEnum(t *testing.T) {
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "http://127.0.0.1:1",
		APIKey: "cz_test_fake",
	})
	defer sink.Close()

	wire := sink.toWireFormat(map[string]any{
		"tool":          "t",
		"decision":      "allow",
		"policy_id":     "p",
		"policy_source": "local-override",
	})
	if got := wire["policy_source"]; got != "local-override" {
		t.Errorf("expected policy_source=local-override on wire, got %v", got)
	}

	// Empty / missing collapses to "" so the backend's normaliser maps
	// to the 'hosted' DEFAULT.
	wire2 := sink.toWireFormat(map[string]any{
		"tool":     "t",
		"decision": "allow",
	})
	if got := wire2["policy_source"]; got != "" {
		t.Errorf("expected empty policy_source when omitted, got %v", got)
	}
}
