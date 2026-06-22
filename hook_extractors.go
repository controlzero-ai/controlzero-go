package controlzero

import "controlzero.ai/sdk/go/internal/hookextractors"

// Public canonical-tool + SQL-semantic-class surface for the Go SDK
// (GitHub #362, epic #80). These thin wrappers re-export the internal
// hookextractors package so consumers wiring the Go SDK into a coding-agent
// PreToolUse hook can turn a host-agent tool payload into the same
// canonical (tool, method) action string -- and the same database:<class>
// semantic class -- the Python and Node SDKs already emit.
//
// Cross-SDK parity is enforced by the shared fixtures at
// tests/fixtures/enforcement-spec/extractors/parity-cases.json (run by the
// Go parity test in internal/hookextractors, the Python
// test_hook_extractors.py / test_sql_semantic_class.py, and the Node
// hookExtractors.test.ts / sqlSemanticClass.test.ts). The same canonical
// spec ships byte-identical in all three SDKs, drift-checked by
// scripts/ci/check-extractor-spec-drift.sh.

// ResolveCanonicalTool resolves a host-agent tool name (e.g. "PostgreSQL",
// "run_shell_command", "view_file") to its canonical name ("database",
// "Bash", "file_read"). Unknown tools pass through unchanged.
func ResolveCanonicalTool(toolName string) string {
	return hookextractors.ResolveCanonicalTool(toolName)
}

// ExtractMethod resolves a PreToolUse payload into a canonical
// (tool, method) pair per the #341 extractor spec. Unknown / unparseable
// inputs fall back to method "*" so the call still reaches the policy
// engine's default_action (fail-closed). See the package docs for the
// resolution algorithm.
func ExtractMethod(toolName string, args map[string]any) (canonicalTool, method string) {
	return hookextractors.ExtractMethod(toolName, args)
}

// BuildAction returns the canonical "{tool}:{method}" action string for a
// PreToolUse payload. Equivalent to joining ExtractMethod's results with a
// colon. A user-typed rule `action: Bash:rm` therefore matches whether the
// agent runs in Claude Code, Gemini CLI, Codex CLI, Antigravity, or
// PowerShell.
func BuildAction(toolName string, args map[string]any) string {
	return hookextractors.BuildAction(toolName, args)
}

// SQLSemanticClass returns the portable canonical SQL class
// (read|write|admin|exec) for a SQL string, or "" when no recognized
// keyword is found (#350). Multi-statement piggyback like
// "SELECT 1; DROP TABLE x" resolves to "admin" so a deny:database:admin
// rule catches it.
func SQLSemanticClass(sql string) string {
	return hookextractors.SQLSemanticClass(sql)
}

// MostDangerousSQLKeyword returns the most dangerous SQL keyword across
// every statement (uppercased), or "" when none is recognized (#341).
func MostDangerousSQLKeyword(sql string) string {
	return hookextractors.MostDangerousSQLKeyword(sql)
}

// MostDangerousShellCommand returns the most dangerous shell command
// across every segment of a compound command, basenamed (#341). Closes the
// "echo ok && rm -rf /" piggyback class.
func MostDangerousShellCommand(cmd string) string {
	return hookextractors.MostDangerousShellCommand(cmd)
}

// NOTE (#362 P1-1): the surface-side databaseSemanticClass helper was
// removed. The #350 SQL semantic-class is now derived INSIDE the shared
// evaluator CORE (PolicyEvaluator.EvaluateWithArgs -> deriveSemanticClass
// in enforcer.go), byte-identical to the Python + Node enforcers, so no
// caller has to precompute the class and the direct PolicyEvaluator API is
// self-sufficient.
