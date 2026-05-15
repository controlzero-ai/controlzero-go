package controlzero

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Cross-SDK action alias parity (T84 / GitHub #389).
//
// Mirrors the cross-SDK fixture at tests/parity/action_aliases.json
// (vendored copy at sdks/go/controlzero/tests/parity/...). The same
// shape of tests runs in the Python SDK (test_action_aliases.py) and
// Node SDK (actionAliases.test.ts). Drift in any SDK breaks parity here.
//
// Mandate: NO BREAKING CHANGES. Pre-#350 customer rules using legacy
// database action names (database:query, database:DROP, ...) MUST keep
// matching even after the SDK started emitting canonical SQL classes.

func legacyToClass() map[string]string {
	return map[string]string{
		"query": "read", "SELECT": "read", "EXPLAIN": "read", "SHOW": "read",
		"DESCRIBE": "read", "FETCH": "read", "READ": "read",
		"UPDATE": "write", "INSERT": "write", "DELETE": "write",
		"MERGE": "write", "UPSERT": "write", "REPLACE": "write",
		"DROP": "admin", "CREATE": "admin", "TRUNCATE": "admin",
		"ALTER": "admin", "GRANT": "admin", "REVOKE": "admin", "RENAME": "admin",
		"execute": "exec", "EXECUTE": "exec", "EXEC": "exec", "CALL": "exec", "do": "exec",
	}
}

// findParityFixture walks up the directory tree looking for
// tests/parity/action_aliases.json. Mirrors the locator used in the
// Python and Node parity tests.
func findParityFixture(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "tests", "parity", "action_aliases.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("tests/parity/action_aliases.json not found")
	return ""
}

func canonicalizeFixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(findParityFixture(t))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx map[string]any
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	delete(fx, "comment")

	// Re-encode in the canonical fixed-key order to match
	// AliasTableJSON()'s output. Key order matters for byte-for-byte
	// equality, so this builder mirrors the SDK's manual marshaller.
	tool, _ := fx["tool"].(string)
	classesAny, _ := fx["classes"].(map[string]any)
	ambAny, _ := fx["ambiguous_aliases"].(map[string]any)

	type classEntry struct {
		Canonical string   `json:"canonical"`
		Aliases   []string `json:"aliases"`
	}

	out := "{\n"
	out += "  \"version\": 1,\n"
	tb, _ := json.Marshal(tool)
	out += "  \"tool\": " + string(tb) + ",\n"
	out += "  \"classes\": {\n"
	clsOrder := []string{"read", "write", "admin", "exec"}
	for i, cls := range clsOrder {
		entryAny, _ := classesAny[cls].(map[string]any)
		canon, _ := entryAny["canonical"].(string)
		aliasesRaw, _ := entryAny["aliases"].([]any)
		aliases := make([]string, len(aliasesRaw))
		for j, a := range aliasesRaw {
			aliases[j] = a.(string)
		}
		entry := classEntry{Canonical: canon, Aliases: aliases}
		eb, _ := json.MarshalIndent(entry, "    ", "  ")
		out += "    \"" + cls + "\": " + string(eb)
		if i < len(clsOrder)-1 {
			out += ","
		}
		out += "\n"
	}
	out += "  },\n"
	out += "  \"ambiguous_aliases\": {\n"
	ambOrder := []string{"delete"}
	for i, a := range ambOrder {
		valRaw, _ := ambAny[a].([]any)
		vals := make([]string, len(valRaw))
		for j, v := range valRaw {
			vals[j] = v.(string)
		}
		vb, _ := json.Marshal(vals)
		out += "    \"" + a + "\": " + string(vb)
		if i < len(ambOrder)-1 {
			out += ","
		}
		out += "\n"
	}
	out += "  }\n"
	out += "}"
	return out
}

func TestAliasTableParity_JSONDumpMatchesFixture(t *testing.T) {
	expected := canonicalizeFixture(t)
	if got := AliasTableJSON(); got != expected {
		t.Fatalf("AliasTableJSON drift\n--- expected ---\n%s\n--- got ---\n%s\n", expected, got)
	}
}

func TestAliasTableParity_SHA256MatchesFixture(t *testing.T) {
	expected := canonicalizeFixture(t)
	want := sha256.Sum256([]byte(expected))
	got := sha256.Sum256([]byte(AliasTableJSON()))
	if hex.EncodeToString(want[:]) != hex.EncodeToString(got[:]) {
		t.Fatalf("alias table sha256 drift: want %x got %x", want, got)
	}
}

func contains(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

func TestExpandCandidateActions_LegacyToCanonical(t *testing.T) {
	out := ExpandCandidateActions([]string{"database:query"})
	if out[0] != "database:query" {
		t.Fatalf("original action must be first; got %v", out)
	}
	if !contains(out, "database:read") {
		t.Fatalf("expected database:read in expansion; got %v", out)
	}
}

func TestExpandCandidateActions_CanonicalToLegacy(t *testing.T) {
	out := ExpandCandidateActions([]string{"database:read"})
	for _, alias := range []string{"query", "SELECT", "EXPLAIN", "SHOW", "DESCRIBE", "FETCH", "READ"} {
		if !contains(out, "database:"+alias) {
			t.Fatalf("expected database:%s in expansion; got %v", alias, out)
		}
	}
}

func TestExpandCandidateActions_AmbiguousDelete(t *testing.T) {
	out := ExpandCandidateActions([]string{"database:delete"})
	if !contains(out, "database:write") {
		t.Fatalf("expected database:write for ambiguous delete; got %v", out)
	}
	if !contains(out, "database:admin") {
		t.Fatalf("expected database:admin for ambiguous delete; got %v", out)
	}
}

func TestExpandCandidateActions_NonDatabasePassthrough(t *testing.T) {
	out := ExpandCandidateActions([]string{"github:open_issue"})
	if len(out) != 1 || out[0] != "github:open_issue" {
		t.Fatalf("expected passthrough for github tool; got %v", out)
	}
}

func TestExpandCandidateActions_UnknownDatabaseMethodPassthrough(t *testing.T) {
	out := ExpandCandidateActions([]string{"database:VACUUM"})
	if len(out) != 1 || out[0] != "database:VACUUM" {
		t.Fatalf("expected passthrough for unknown method; got %v", out)
	}
}

func TestExpandCandidateActions_EmptyInput(t *testing.T) {
	out := ExpandCandidateActions([]string{})
	if len(out) != 0 {
		t.Fatalf("expected empty output for empty input; got %v", out)
	}
}

func TestExpandCandidateActions_DedupesRepeats(t *testing.T) {
	out := ExpandCandidateActions([]string{"database:query", "database:query"})
	count := 0
	for _, a := range out {
		if a == "database:query" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected dedup; got %v", out)
	}
}

func TestExpandCandidateActions_MalformedSkipped(t *testing.T) {
	out := ExpandCandidateActions([]string{"no_colon"})
	if len(out) != 1 || out[0] != "no_colon" {
		t.Fatalf("expected passthrough for malformed; got %v", out)
	}
}

func allowRule(action string) PolicyRule {
	return PolicyRule{
		ID:        "r1",
		Name:      "r1",
		Effect:    "allow",
		Actions:   []string{action},
		Resources: []string{"*"},
		Reason:    "alias-roundtrip",
	}
}

func TestEnforcerRoundtrip_LegacyCallMatchesCanonicalRule(t *testing.T) {
	for legacy, cls := range legacyToClass() {
		t.Run(legacy+"_to_"+cls, func(t *testing.T) {
			ev := NewPolicyEvaluator([]PolicyRule{allowRule("database:" + cls)})
			d := ev.Evaluate("database", legacy, nil)
			if d.Effect != "allow" {
				t.Fatalf("legacy %s did not match canonical rule database:%s; got %s (%s)",
					legacy, cls, d.Effect, d.Reason)
			}
		})
	}
}

func TestEnforcerRoundtrip_CanonicalCallMatchesLegacyRule(t *testing.T) {
	for legacy, cls := range legacyToClass() {
		t.Run(cls+"_to_"+legacy, func(t *testing.T) {
			ev := NewPolicyEvaluator([]PolicyRule{allowRule("database:" + legacy)})
			d := ev.Evaluate("database", cls, nil)
			if d.Effect != "allow" {
				t.Fatalf("canonical %s did not match legacy rule database:%s; got %s (%s)",
					cls, legacy, d.Effect, d.Reason)
			}
		})
	}
}

func TestEnforcerRoundtrip_AmbiguousDeleteMatchesBoth(t *testing.T) {
	for _, cls := range []string{"write", "admin"} {
		ev := NewPolicyEvaluator([]PolicyRule{allowRule("database:" + cls)})
		d := ev.Evaluate("database", "delete", nil)
		if d.Effect != "allow" {
			t.Fatalf("legacy delete did not match canonical rule database:%s; got %s",
				cls, d.Effect)
		}
	}
}

func TestEnforcerRoundtrip_NoCrossToolFalsePositive(t *testing.T) {
	ev := NewPolicyEvaluator([]PolicyRule{allowRule("database:read")})
	d := ev.Evaluate("github", "SELECT", nil)
	if d.Effect != "deny" {
		t.Fatalf("database rule should not match github tool; got %s", d.Effect)
	}
}

func TestEnforcerRoundtrip_NoCrossClassFalsePositive(t *testing.T) {
	ev := NewPolicyEvaluator([]PolicyRule{allowRule("database:read")})
	d := ev.Evaluate("database", "INSERT", nil)
	if d.Effect != "deny" {
		t.Fatalf("read rule should not match write call (INSERT); got %s", d.Effect)
	}
}

func TestEnforcerRoundtrip_UnknownMethodNoFalseMatch(t *testing.T) {
	ev := NewPolicyEvaluator([]PolicyRule{allowRule("database:read")})
	d := ev.Evaluate("database", "VACUUM", nil)
	if d.Effect != "deny" {
		t.Fatalf("unknown method must not match any class rule; got %s", d.Effect)
	}
}
