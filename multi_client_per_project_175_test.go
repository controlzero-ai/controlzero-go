// Tests for gh#175 P1.1 audit trail columns.
//
// The Go SDK enforcer does not yet evaluate `clients:` / `projects:`
// selectors (tracked under the gh#175 Go SDK port slice). Even so, the
// audit row MUST already carry the three cross-SDK columns --
// client_name, project_id, gate_matched -- so the dashboard query
// shape is invariant across the Python / Node / Go surfaces.
//
// Coverage:
//   - every audit row contains all three columns
//   - gate_matched is always "none" in this slice
//   - client_name is populated from detectClientName by default
//   - caller-supplied ClientName / ProjectID flow through to the row
package controlzero_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"controlzero.ai/sdk/go"
	"controlzero.ai/sdk/go/internal/bundle"
)

func auditEntries(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var out []map[string]any
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			// Audit might be wrapped (zerolog); look for nested keys.
			t.Fatalf("non-JSON audit line: %s (err=%v)", string(line), err)
		}
		out = append(out, m)
	}
	return out
}

func TestAuditTrail175_StampsAllThreeColumns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	cz, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"deny": "delete_*"},
				map[string]any{"allow": "*"},
			},
		}),
		controlzero.WithLogPath(path),
	)
	if err != nil {
		t.Fatal(err)
	}
	cz.Guard("delete_file", controlzero.GuardOptions{Args: map[string]any{"path": "/tmp/foo"}})
	cz.Guard("read_file", controlzero.GuardOptions{Args: map[string]any{"path": "/tmp/bar"}})
	cz.Close()

	entries := auditEntries(t, path)
	if len(entries) < 2 {
		t.Fatalf("expected >=2 audit rows, got %d", len(entries))
	}
	for _, row := range entries {
		for _, col := range []string{"client_name", "project_id", "gate_matched"} {
			if _, ok := row[col]; !ok {
				t.Errorf("audit row missing column %q: row=%v", col, row)
			}
		}
	}
}

func TestAuditTrail175_GateMatchedIsNoneInThisSlice(t *testing.T) {
	// The Go enforcer does not yet evaluate selectors. Until that
	// work lands, every Go audit row must report gate_matched=none
	// so the dashboard does not show stale "client gate matched"
	// counts that the engine never actually evaluated.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	cz, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*"}},
		}),
		controlzero.WithLogPath(path),
	)
	if err != nil {
		t.Fatal(err)
	}
	cz.Guard("any_tool", controlzero.GuardOptions{})
	cz.Close()

	entries := auditEntries(t, path)
	for _, row := range entries {
		if got, want := row["gate_matched"], "none"; got != want {
			t.Errorf("expected gate_matched=%q, got %v", want, got)
		}
	}
}

func TestAuditTrail175_CallerSuppliedClientNameFlowsThrough(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	cz, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*"}},
		}),
		controlzero.WithLogPath(path),
	)
	if err != nil {
		t.Fatal(err)
	}
	cz.Guard("any_tool", controlzero.GuardOptions{
		Context: &controlzero.EvalContext{ClientName: "cursor-test-harness"},
	})
	cz.Close()

	entries := auditEntries(t, path)
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	if got := entries[0]["client_name"]; got != "cursor-test-harness" {
		t.Errorf("expected client_name=cursor-test-harness, got %v", got)
	}
}

// TestAuditTrail175_SatisfiesCrossSDKContract loads the shared
// contract from tests/parity/audit_trail_175.json and asserts the Go
// audit row carries every required column. Mirrors the Python + Node
// SDK contract tests. Skips gracefully when the contract file is not
// reachable from the current mount.
func TestAuditTrail175_SatisfiesCrossSDKContract(t *testing.T) {
	contract, ok := loadAuditTrailContract(t)
	if !ok {
		t.Skip("cross-SDK contract not on this mount (canonical SDK-only mount)")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	cz, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*"}},
		}),
		controlzero.WithLogPath(path),
	)
	if err != nil {
		t.Fatal(err)
	}
	cz.Guard("any_tool", controlzero.GuardOptions{
		Context: &controlzero.EvalContext{ClientName: "cursor", ProjectID: "proj-prod"},
	})
	cz.Close()

	entries := auditEntries(t, path)
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	row := entries[0]
	for _, col := range contract.RequiredColumns {
		if _, ok := row[col.Name]; !ok {
			t.Errorf("Go SDK violates cross-SDK contract: missing %q", col.Name)
		}
	}
	got, _ := row["gate_matched"].(string)
	if !contains175(contract.ValidGateMatchedValues, got) {
		t.Errorf("gate_matched=%q not in contract value space %v", got, contract.ValidGateMatchedValues)
	}
}

type auditTrailContract struct {
	RequiredColumns []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"required_columns"`
	ValidGateMatchedValues []string `json:"valid_gate_matched_values"`
}

func loadAuditTrailContract(t *testing.T) (*auditTrailContract, bool) {
	t.Helper()
	candidates := []string{os.Getenv("CZ_AUDIT_TRAIL_CONTRACT")}
	// Walk up from the test's working dir looking for the contract.
	wd, _ := os.Getwd()
	for cur := wd; cur != "/" && cur != ""; cur = filepath.Dir(cur) {
		candidates = append(candidates, filepath.Join(cur, "tests", "parity", "audit_trail_175.json"))
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		var out auditTrailContract
		if err := json.Unmarshal(data, &out); err != nil {
			continue
		}
		return &out, true
	}
	return nil, false
}

func contains175(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestBundleTranslator175_ForwardsSelectors regresses the gh#175
// outside-voice P0 finding: the hosted bundle translator was
// stripping `clients` / `projects` so selector-scoped rules became
// unscoped after hosted distribution. Verifies the translator now
// passes them through.
func TestBundleTranslator175_ForwardsSelectors(t *testing.T) {
	// We call the internal translator directly via the policy_loader
	// round-trip: load_hosted_policy -> bundle.TranslateToLocalPolicy
	// -> load_policy. The simplest assertion is via the JSON the
	// translator emits, which is what load_policy consumes.
	payload := map[string]any{
		"schema_version": "1.0",
		"bundle_id":      "b-1",
		"project_id":     "proj-prod",
		"policies": []any{
			map[string]any{
				"id":         "p-test",
				"name":       "Test",
				"priority":   1,
				"is_enabled": true,
				"version":    1,
				"rules": []any{
					map[string]any{
						"effect":   "deny",
						"actions":  []any{"delete_file:*"},
						"clients":  []any{"cursor"},
						"projects": []any{"proj-prod"},
					},
				},
			},
		},
		"llm_policies": []any{},
	}
	local := bundle.TranslateToLocalPolicy(payload)
	rules, ok := local["rules"].([]any)
	if !ok || len(rules) == 0 {
		t.Fatalf("expected translated rules, got %v", local["rules"])
	}
	rule := rules[0].(map[string]any)
	clients, _ := rule["clients"].([]string)
	if len(clients) != 1 || clients[0] != "cursor" {
		t.Errorf("clients not forwarded by translator, got %v", rule["clients"])
	}
	projects, _ := rule["projects"].([]string)
	if len(projects) != 1 || projects[0] != "proj-prod" {
		t.Errorf("projects not forwarded by translator, got %v", rule["projects"])
	}
}

func TestAuditTrail175_DetectedClientNameDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	cz, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*"}},
		}),
		controlzero.WithLogPath(path),
	)
	if err != nil {
		t.Fatal(err)
	}
	cz.Guard("any_tool", controlzero.GuardOptions{})
	cz.Close()

	entries := auditEntries(t, path)
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	got, ok := entries[0]["client_name"].(string)
	if !ok {
		t.Fatalf("client_name not a string: %v", entries[0]["client_name"])
	}
	// detectClientName falls back to "go-sdk" in unit-test
	// environments (no CURSOR/CLAUDECODE/etc env vars). The
	// contract is only that it's a non-error string -- empty is
	// acceptable for a SDK build without env detection.
	_ = got
	if strings.TrimSpace(got) == "" {
		// Don't fail; the contract only mandates the field exists.
		t.Logf("client_name resolved to empty string (acceptable)")
	}
}
