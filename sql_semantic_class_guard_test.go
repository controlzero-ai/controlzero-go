package controlzero_test

import (
	"os"
	"path/filepath"
	"testing"

	controlzero "controlzero.ai/sdk/go"
)

// #350 / #362: the Go SDK's Guard() must honour the portable SQL
// semantic-class layer. A single `database:read` rule should cover every
// read-shaped statement (SELECT / EXPLAIN / SHOW / CTE / DESCRIBE) without
// enumerating the dialect-specific keyword, and a `deny database:admin`
// rule must catch a `SELECT 1; DROP TABLE x` piggyback. Mirrors the
// behaviour the Python + Node SDKs ship.

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "controlzero.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return p
}

func newClient(t *testing.T, policyBody string) *controlzero.Client {
	t.Helper()
	p := writePolicy(t, policyBody)
	cz, err := controlzero.New(controlzero.WithPolicyFile(p))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = cz.Close() })
	return cz
}

func TestGuardSemanticClassReadRuleCoversDialects(t *testing.T) {
	// One portable allow rule; default deny.
	policy := `
default_action: deny
rules:
  - id: allow-reads
    effect: allow
    actions: ["database:read"]
`
	cz := newClient(t, policy)

	readSQL := []string{
		"SELECT * FROM users",
		"EXPLAIN SELECT * FROM users",
		"SHOW TABLES",
		"WITH x AS (SELECT 1) SELECT * FROM x",
		"DESCRIBE users",
	}
	for _, sql := range readSQL {
		d, _ := cz.Guard("database", controlzero.GuardOptions{Args: map[string]any{"sql": sql}})
		if !d.Allowed() {
			t.Errorf("read SQL %q: effect=%q, want allow (semantic_class=%q)", sql, d.Effect, d.SemanticClass)
		}
		if d.SemanticClass != "read" {
			t.Errorf("read SQL %q: semantic_class=%q, want read", sql, d.SemanticClass)
		}
	}

	// A write must NOT slip through the read-only allow rule -> default deny.
	d, _ := cz.Guard("database", controlzero.GuardOptions{Args: map[string]any{"sql": "DELETE FROM users"}})
	if !d.Denied() {
		t.Errorf("DELETE: effect=%q, want deny (semantic_class=%q)", d.Effect, d.SemanticClass)
	}
	if d.SemanticClass != "write" {
		t.Errorf("DELETE: semantic_class=%q, want write", d.SemanticClass)
	}
}

func TestGuardSemanticClassAdminCatchesPiggyback(t *testing.T) {
	policy := `
default_action: allow
rules:
  - id: deny-admin
    effect: deny
    actions: ["database:admin"]
`
	cz := newClient(t, policy)

	// SELECT 1; DROP TABLE x must resolve to admin and be denied even
	// though the leading statement is a read.
	d, _ := cz.Guard("database", controlzero.GuardOptions{
		Args: map[string]any{"sql": "SELECT 1; DROP TABLE users"},
	})
	if !d.Denied() {
		t.Errorf("piggyback: effect=%q, want deny (semantic_class=%q)", d.Effect, d.SemanticClass)
	}
	if d.SemanticClass != "admin" {
		t.Errorf("piggyback: semantic_class=%q, want admin", d.SemanticClass)
	}
}

func TestGuardPerKeywordRuleStillFires(t *testing.T) {
	// NO BREAKING CHANGES: a legacy per-keyword rule must keep working
	// alongside the new class layer.
	policy := `
default_action: allow
rules:
  - id: deny-drop
    effect: deny
    actions: ["database:DROP"]
`
	cz := newClient(t, policy)
	d, _ := cz.Guard("database", controlzero.GuardOptions{
		Args: map[string]any{"sql": "DROP TABLE users"},
	})
	if !d.Denied() {
		t.Errorf("database:DROP rule: effect=%q, want deny", d.Effect)
	}
}

func TestGuardNonSQLHasNoSemanticClass(t *testing.T) {
	policy := `
default_action: allow
rules:
  - id: allow-ls
    effect: allow
    actions: ["Bash:ls"]
`
	cz := newClient(t, policy)
	d, _ := cz.Guard("Bash", controlzero.GuardOptions{
		Args:   map[string]any{"command": "ls"},
		Method: "ls",
	})
	if d.SemanticClass != "" {
		t.Errorf("Bash call: semantic_class=%q, want empty", d.SemanticClass)
	}
}

func TestGuardSemanticClassViaPrecomputedClass(t *testing.T) {
	// #362 P1-1 parity: when an alias like "PostgreSQL" is the host tool
	// name, alias resolution + class derivation happen in the hook-check
	// layer (mirroring the Python CLI: resolve canonical_tool, derive the
	// class, then guard with the CANONICAL tool + a precomputed
	// action_semantic_class). The evaluator core honours that precomputed
	// class via EvalContext.ActionSemanticClass -- byte-identical to the
	// Python/Node `context["action_semantic_class"]` input. This is the
	// path an alias actually travels; the in-core derivation only fires
	// for the literal "database" tool (see
	// TestGuardRawAliasMatchesPythonNode below).
	policy := `
default_action: deny
rules:
  - id: allow-reads
    effect: allow
    actions: ["database:read"]
`
	cz := newClient(t, policy)
	// The hook-check layer resolved PostgreSQL -> database and derived the
	// class; it guards with the canonical tool + the precomputed class.
	d, _ := cz.Guard("database", controlzero.GuardOptions{
		Args:    map[string]any{"sql": "SELECT 1"},
		Context: &controlzero.EvalContext{ActionSemanticClass: "database:read"},
	})
	if !d.Allowed() {
		t.Errorf("precomputed database:read: effect=%q, want allow (semantic_class=%q)", d.Effect, d.SemanticClass)
	}
	if d.SemanticClass != "read" {
		t.Errorf("precomputed database:read: semantic_class=%q, want read", d.SemanticClass)
	}
}

func TestGuardPrecomputedClassWinsOverArgsDerivedViaGuard(t *testing.T) {
	// #362 P1-1 precedence, exercised through the PUBLIC Guard surface with
	// CONFLICTING inputs:
	//   - args.sql = "SELECT 1"  -> args-derivation alone yields database:read
	//   - ActionSemanticClass    = "database:admin" (what the hook-check layer
	//                              resolved, e.g. for a multi-statement payload
	//                              or a dialect the caller already classified)
	//   - rule: deny database:admin
	//
	// The explicit precomputed class MUST win, so the call is DENIED. This
	// proves Client.Guard plumbs EvalContext.ActionSemanticClass all the way
	// into the evaluator core (buildEvalContext must copy it). It FAILS CLOSED
	// if ActionSemanticClass is ever dropped on the Guard path again: with it
	// dropped, the core re-derives "read" from args.sql, the deny:admin rule
	// no longer matches, and default_action=allow would let the call through.
	// Mirrors Python/Node, which spread the whole caller context dict so
	// context["action_semantic_class"] reaches their evaluators.
	policy := `
default_action: allow
rules:
  - id: deny-admin
    effect: deny
    actions: ["database:admin"]
`
	cz := newClient(t, policy)
	d, _ := cz.Guard("database", controlzero.GuardOptions{
		Args:    map[string]any{"sql": "SELECT 1"},
		Context: &controlzero.EvalContext{ActionSemanticClass: "database:admin"},
	})
	if !d.Denied() {
		t.Errorf("precomputed database:admin via Guard: effect=%q, want deny "+
			"(explicit class must win over args-derived read; ActionSemanticClass "+
			"was dropped on the Guard path?)", d.Effect)
	}
	if d.SemanticClass != "admin" {
		t.Errorf("precomputed database:admin via Guard: semantic_class=%q, want admin", d.SemanticClass)
	}
	if d.PolicyID != "deny-admin" {
		t.Errorf("precomputed database:admin via Guard: policy_id=%q, want deny-admin", d.PolicyID)
	}
}

func TestGuardRawAliasMatchesPythonNode(t *testing.T) {
	// #362 P1-1 parity: the evaluator CORE derives the SQL semantic class
	// from args["sql"] ONLY for the literal "database" tool, exactly as the
	// Python and Node enforcers do (`tool == "database"`). A raw alias
	// guard like Guard("PostgreSQL", sql=...) does NOT alias-resolve at the
	// SDK guard layer -- it falls through to default_action, which is what
	// Python `cz.guard("PostgreSQL", ...)` and the Node equivalent do
	// (verified on the build server: both DENY via NO_RULE_MATCH). Locking
	// this in prevents the Go SDK from re-introducing a per-surface
	// superset behaviour that diverges from the other two runtimes.
	policy := `
default_action: deny
rules:
  - id: allow-reads
    effect: allow
    actions: ["database:read"]
`
	cz := newClient(t, policy)
	d, _ := cz.Guard("PostgreSQL", controlzero.GuardOptions{
		Args: map[string]any{"sql": "SELECT 1"},
	})
	if !d.Denied() {
		t.Errorf("raw PostgreSQL SELECT: effect=%q, want deny (parity with Python/Node no-alias-resolution at guard layer)", d.Effect)
	}
	if d.SemanticClass != "" {
		t.Errorf("raw PostgreSQL SELECT: semantic_class=%q, want empty (no in-core derivation for non-database tool)", d.SemanticClass)
	}

	// The literal "database" tool DOES derive in the core.
	d2, _ := cz.Guard("database", controlzero.GuardOptions{
		Args: map[string]any{"sql": "SELECT 1"},
	})
	if !d2.Allowed() {
		t.Errorf("literal database SELECT: effect=%q, want allow (in-core derivation)", d2.Effect)
	}
	if d2.SemanticClass != "read" {
		t.Errorf("literal database SELECT: semantic_class=%q, want read", d2.SemanticClass)
	}
}
