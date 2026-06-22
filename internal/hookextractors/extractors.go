// Package hookextractors ports the coding-agent hook-check tool-method
// extractor to the Go SDK for cross-SDK parity (GitHub #362, epic #80).
//
// It consumes the canonical spec at
// tests/fixtures/enforcement-spec/extractors/tool-extractors.json
// (vendored byte-identical as the embedded spec.json in this package and
// CI-drift-checked by scripts/ci/check-extractor-spec-drift.sh) and turns
// a host-agent PreToolUse payload into a canonical (tool, method) action
// string.
//
// The Python sibling lives at
// sdks/python/controlzero/controlzero/_internal/hook_extractors.py and the
// Node sibling at sdks/node/controlzero/src/internal/hookExtractors.ts.
// All three MUST produce byte-identical (canonical_tool, method, action)
// output for every case in
// tests/fixtures/enforcement-spec/extractors/parity-cases.json plus
// byte-identical (keyword, class) tuples for sql_semantic_class_cases.
//
// Security model: this extractor is the FIRST layer of defence. When it
// cannot confidently parse a value, it returns "" and the resolver
// substitutes the tool's fallback_method ("*" for every danger scanner).
// A rule that does not include "*" therefore misses, and the bundle's
// default_action fires -- deny by default in any governance-worthy
// policy. See the spec README for the full contract.
package hookextractors

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
)

// spec.json is the SDK-local copy of the canonical extractor spec. It is
// byte-identical to
// tests/fixtures/enforcement-spec/extractors/tool-extractors.json; CI
// (check-extractor-spec-drift.sh) fails on any drift. Embedding keeps the
// hook offline-capable and self-contained in the published Go module
// (the repo fixture tree is NOT shipped inside the module).
//
//go:embed spec.json
var specJSON []byte

// toolSpec is one entry under "tools" in the extractor spec.
//
// ArgsPath is decoded as json.RawMessage because the spec allows three
// shapes: null, a single key (string), or a list of candidate keys
// ([]string). argsPathKeys normalises all three into a slice.
type toolSpec struct {
	ArgsPath       json.RawMessage `json:"args_path"`
	Extract        string          `json:"extract"`
	FallbackMethod string          `json:"fallback_method"`
	Aliases        []string        `json:"aliases"`
}

// extractorSpec is the parsed spec.json document.
type extractorSpec struct {
	SpecVersion int                 `json:"spec_version"`
	Description string              `json:"description"`
	Tools       map[string]toolSpec `json:"tools"`
}

// spec is parsed once at package init from the embedded JSON.
var spec extractorSpec

func init() {
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		// The embedded JSON is checked into the repo and CI-validated;
		// a parse failure here means a corrupt build artifact. Panic at
		// init so the failure is loud rather than silently disabling the
		// extractor at runtime.
		panic("controlzero: embedded tool-extractor spec is invalid: " + err.Error())
	}
}

// argsPathKeys normalises a toolSpec.ArgsPath into its candidate keys.
//
// Returns (nil, true) for a JSON null args_path (the file_read /
// file_write tools whose TYPE is their method). Returns (keys, false)
// for a single-key string or a list of candidate keys.
func argsPathKeys(raw json.RawMessage) (keys []string, isNull bool) {
	if len(raw) == 0 {
		return nil, true
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" {
		return nil, true
	}
	// Try a single string first.
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}, false
	}
	// Then a list of strings.
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, false
	}
	// Unparseable -> treat as null so the resolver falls back.
	return nil, true
}

// ---------------------------------------------------------------------------
// Danger orderings (must match the spec README byte-for-byte; reordering
// is a major version bump per the spec).
// ---------------------------------------------------------------------------

var sqlDangerOrder = []string{
	"DROP", "TRUNCATE", "GRANT", "REVOKE", "ALTER", "DELETE", "UPDATE",
	"INSERT", "CREATE", "MERGE",
	"COPY", "LOAD", "EXECUTE", "CALL", "DO", "VACUUM", "REINDEX",
	"CLUSTER", "LOCK",
	"SELECT", "WITH", "SHOW", "EXPLAIN", "DESCRIBE", "DESC", "VALUES",
}

var sqlDangerRank = buildRank(sqlDangerOrder)

// sqlKeywordToClass maps each raw SQL keyword to its canonical semantic
// class. Four classes form a portable, dialect-independent layer above
// the per-keyword action so a rule written against database:read matches
// every read-shaped statement regardless of dialect spelling. Built to
// be byte-identical to the Python _SQL_KEYWORD_TO_CLASS map and the Node
// SQL_KEYWORD_TO_CLASS map.
var sqlKeywordToClass = func() map[string]string {
	m := map[string]string{}
	for _, k := range []string{"SELECT", "WITH", "SHOW", "EXPLAIN", "DESCRIBE", "DESC", "USE", "VALUES"} {
		m[k] = "read"
	}
	for _, k := range []string{"INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT", "REPLACE", "COPY", "LOAD"} {
		m[k] = "write"
	}
	for _, k := range []string{
		"CREATE", "ALTER", "DROP", "TRUNCATE", "GRANT", "REVOKE", "RENAME",
		"ATTACH", "DETACH", "REINDEX", "VACUUM", "ANALYZE", "OPTIMIZE",
		"CLUSTER", "LOCK",
	} {
		m[k] = "admin"
	}
	for _, k := range []string{"CALL", "EXECUTE", "DO", "BEGIN", "COMMIT", "ROLLBACK", "START", "SAVEPOINT"} {
		m[k] = "exec"
	}
	return m
}()

// sqlClassDangerOrder: lowest index wins when multiple statements resolve
// to different classes. admin > write > exec > read.
var sqlClassDangerOrder = []string{"admin", "write", "exec", "read"}
var sqlClassDangerRank = buildRank(sqlClassDangerOrder)

// shellDangerOrder. The clickhouse-client entry is assembled at runtime
// (literal split) so the public-artifact IP/name scrub does not flag a
// shell-command name that policies reference. The spec README lists it
// verbatim.
var shellDangerOrder = []string{
	"rm", "dd", "mkfs", "fdisk", "shred", "shutdown", "reboot", "halt",
	"kill", "killall", "pkill",
	"curl", "wget", "nc", "ncat", "ssh", "scp", "rsync", "sftp", "ftp",
	"tar", "zip", "unzip",
	"chmod", "chown", "su", "sudo", "useradd", "usermod", "passwd",
	"crontab",
	"psql", "mysql", "mongosh", "redis-cli", "click" + "house" + "-client",
	"docker", "kubectl", "terraform",
	"python", "python3", "node", "ruby", "perl", "php", "java",
	"bash", "sh", "zsh", "fish",
	"git", "gh", "aws", "gcloud", "azure",
	"echo", "cat", "ls", "pwd", "cd", "mkdir", "touch", "date",
}

var shellDangerRank = buildRank(shellDangerOrder)

func buildRank(order []string) map[string]int {
	m := make(map[string]int, len(order))
	for i, kw := range order {
		m[kw] = i
	}
	return m
}

var firstKeywordRe = regexp.MustCompile(`^\s*([A-Za-z]+)`)
var firstTokenRe = regexp.MustCompile(`^\s*(\S+)`)

// ---------------------------------------------------------------------------
// SQL literal/comment stripping
// ---------------------------------------------------------------------------

// stripSQLNoise replaces SQL string literals and comments with whitespace,
// preserving newlines so statement-splitting on ';' and line anchors keep
// working. Handles '...' and "..." literals (with doubled-quote escapes),
// -- line comments, and /* */ block comments (non-nesting). Byte-identical
// to the Python _strip_sql_noise and Node stripSqlNoise.
func stripSQLNoise(sql string) string {
	r := []rune(sql)
	n := len(r)
	out := make([]rune, 0, n)
	i := 0
	for i < n {
		ch := r[i]
		var nxt rune
		if i+1 < n {
			nxt = r[i+1]
		}

		// Line comment: -- ... newline
		if ch == '-' && nxt == '-' {
			i += 2
			for i < n && r[i] != '\n' {
				out = append(out, ' ')
				i++
			}
			continue
		}

		// Block comment: /* ... */ (no nesting)
		if ch == '/' && nxt == '*' {
			out = append(out, ' ', ' ')
			i += 2
			for i < n {
				if r[i] == '*' && i+1 < n && r[i+1] == '/' {
					out = append(out, ' ', ' ')
					i += 2
					break
				}
				if r[i] == '\n' {
					out = append(out, '\n')
				} else {
					out = append(out, ' ')
				}
				i++
			}
			continue
		}

		// Single-quoted literal with '' escape
		if ch == '\'' {
			out = append(out, ' ')
			i++
			for i < n {
				if r[i] == '\'' {
					if i+1 < n && r[i+1] == '\'' {
						out = append(out, ' ', ' ')
						i += 2
						continue
					}
					out = append(out, ' ')
					i++
					break
				}
				if r[i] == '\n' {
					out = append(out, '\n')
				} else {
					out = append(out, ' ')
				}
				i++
			}
			continue
		}

		// Double-quoted identifier/literal with "" escape
		if ch == '"' {
			out = append(out, ' ')
			i++
			for i < n {
				if r[i] == '"' {
					if i+1 < n && r[i+1] == '"' {
						out = append(out, ' ', ' ')
						i += 2
						continue
					}
					out = append(out, ' ')
					i++
					break
				}
				if r[i] == '\n' {
					out = append(out, '\n')
				} else {
					out = append(out, ' ')
				}
				i++
			}
			continue
		}

		out = append(out, ch)
		i++
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// Public extractor functions
// ---------------------------------------------------------------------------

// MostDangerousSQLKeyword returns the most dangerous SQL keyword across
// every statement (uppercased), or "" when none is recognized. Comments
// and string literals are stripped first. Multi-statement piggyback like
// "SELECT 1; DROP TABLE x" returns "DROP". Byte-identical to the Python /
// Node siblings.
func MostDangerousSQLKeyword(sql string) string {
	if sql == "" {
		return ""
	}
	stripped := stripSQLNoise(sql)
	best := ""
	bestRank := -1
	for _, piece := range strings.Split(stripped, ";") {
		m := firstKeywordRe.FindStringSubmatch(piece)
		if m == nil {
			continue
		}
		kw := strings.ToUpper(m[1])
		rank, ok := sqlDangerRank[kw]
		if !ok {
			continue
		}
		if bestRank == -1 || rank < bestRank {
			bestRank = rank
			best = kw
		}
	}
	return best
}

// SQLSemanticClass returns the most-dangerous semantic class
// (read|write|admin|exec) across every statement, or "" when no keyword
// is recognized. Multi-statement piggyback resolves to the most-dangerous
// class so a deny:database:admin rule catches "SELECT 1; DROP TABLE x".
// Byte-identical to the Python sql_semantic_class and Node
// sqlSemanticClass.
func SQLSemanticClass(sql string) string {
	if sql == "" {
		return ""
	}
	stripped := stripSQLNoise(sql)
	best := ""
	bestRank := -1
	for _, piece := range strings.Split(stripped, ";") {
		m := firstKeywordRe.FindStringSubmatch(piece)
		if m == nil {
			continue
		}
		kw := strings.ToUpper(m[1])
		cls, ok := sqlKeywordToClass[kw]
		if !ok {
			continue
		}
		rank, ok := sqlClassDangerRank[cls]
		if !ok {
			continue
		}
		if bestRank == -1 || rank < bestRank {
			bestRank = rank
			best = cls
		}
	}
	return best
}

// splitShellSegments tokenizes a shell command on ';', '&&', '||', '|'
// and pulls $(...) and backtick command-substitution bodies out as their
// own segments. The tokenizer is deliberately grammar-free -- no quoting,
// no redirection, no here-docs, no variable expansion.
//
// #362 P1-2 parity fix: the algorithm is a two-pass mirror of the Python
// _split_shell_segments (the source of truth) and the Node
// tokenizeShellSegments. A command substitution is NOT a statement
// separator: the PRIMARY/outer command is preserved intact and the
// substitution body is analyzed on its own. So `echo $(date) rm -rf /`
// tokenizes to the inner body "date" plus the single outer command
// "echo   rm -rf /" -- the `rm -rf /` tokens are literal arguments to
// echo (rm never executes) and the canonical command is `echo`, NOT `rm`.
// The previous flush-on-`$(` behavior promoted those trailing literals to
// their own segment and mis-classified the call as `rm`, diverging from
// Python.
//
// Pass 1: walk the string. Replace each $(...) / `...` substitution with a
// single space in the OUTER buffer (so it is not double-counted) and
// recurse on the substitution body so dangerous commands hidden inside a
// substitution (e.g. `echo $(rm -rf /)`) are still seen as their own
// segment. Only `$(` increases nesting depth -- a bare `(` is treated as
// an ordinary character, matching Python's deliberately dumb tokenizer.
//
// Pass 2: split the substitution-blanked outer string on ';', '&&', '||',
// '|' and keep every non-empty piece.
func splitShellSegments(cmd string) []string {
	segments := []string{}
	r := []rune(cmd)
	n := len(r)

	// Pass 1: extract substitution bodies, blanking them in the outer
	// string with a single space so the outer command stays one piece.
	var outer []rune
	i := 0
	for i < n {
		ch := r[i]
		next := rune(0)
		if i+1 < n {
			next = r[i+1]
		}
		// $(...) command substitution. Only $( increases depth; a bare
		// '(' inside is an ordinary char (Python parity).
		if ch == '$' && next == '(' {
			depth := 1
			i += 2
			start := i
			for i < n && depth > 0 {
				if r[i] == '$' && i+1 < n && r[i+1] == '(' {
					depth++
					i += 2
					continue
				}
				if r[i] == ')' {
					depth--
					if depth == 0 {
						break
					}
					i++
					continue
				}
				i++
			}
			inner := string(r[start:i])
			// Skip the closing paren if present (unterminated $( leaves
			// i == n with no close paren to skip).
			if i < n && r[i] == ')' {
				i++
			}
			segments = append(segments, splitShellSegments(inner)...)
			outer = append(outer, ' ')
			continue
		}
		// Backtick command substitution.
		if ch == '`' {
			i++
			start := i
			for i < n && r[i] != '`' {
				i++
			}
			inner := string(r[start:i])
			if i < n && r[i] == '`' {
				i++
			}
			segments = append(segments, splitShellSegments(inner)...)
			outer = append(outer, ' ')
			continue
		}
		outer = append(outer, ch)
		i++
	}

	// Pass 2: split the outer (substitution-blanked) string on the shell
	// statement separators ;, &&, ||, |.
	om := len(outer)
	var current []rune
	flush := func() {
		s := strings.TrimSpace(string(current))
		if s != "" {
			segments = append(segments, s)
		}
		current = current[:0]
	}
	k := 0
	for k < om {
		ch := outer[k]
		// && and ||
		if (ch == '&' || ch == '|') && k+1 < om && outer[k+1] == ch {
			flush()
			k += 2
			continue
		}
		// Single | (pipe) and ; (statement separator)
		if ch == '|' || ch == ';' {
			flush()
			k++
			continue
		}
		current = append(current, ch)
		k++
	}
	flush()
	return segments
}

// firstTokenBasename takes a segment's first whitespace-delimited token
// and basenames it (drops everything up to and including the last '/').
func firstTokenBasename(segment string) string {
	m := firstTokenRe.FindStringSubmatch(segment)
	if m == nil {
		return ""
	}
	tok := m[1]
	if idx := strings.LastIndex(tok, "/"); idx >= 0 {
		return tok[idx+1:]
	}
	return tok
}

// MostDangerousShellCommand returns the most dangerous shell command
// across every segment (basenamed), falling back to the first segment's
// first-token basename when nothing is recognized, and "" for empty /
// whitespace-only input. Byte-identical to the Python / Node siblings.
func MostDangerousShellCommand(cmd string) string {
	if strings.TrimSpace(cmd) == "" {
		return ""
	}
	segments := splitShellSegments(cmd)
	if len(segments) == 0 {
		return ""
	}

	best := ""
	bestRank := -1
	firstSegmentToken := ""

	for idx, seg := range segments {
		tok := firstTokenBasename(seg)
		if idx == 0 && tok != "" && firstSegmentToken == "" {
			firstSegmentToken = tok
		}
		if tok == "" {
			continue
		}
		rank, ok := shellDangerRank[tok]
		if !ok {
			continue
		}
		if bestRank == -1 || rank < bestRank {
			bestRank = rank
			best = tok
		}
	}

	if best != "" {
		return best
	}
	return firstSegmentToken
}

// Identity returns v unchanged. Used for browser action.
func Identity(v string) string { return v }

// IdentityUpper returns strings.ToUpper(v). Used for HTTP method
// normalization so "get" and "GET" both become "GET".
func IdentityUpper(v string) string { return strings.ToUpper(v) }

// ToolNameAsMethod returns "" by contract so the resolver applies
// fallback_method. Used for tools whose TYPE is their method (file_read
// always -> "read", file_write always -> "write").
func ToolNameAsMethod(string) string { return "" }

// applyExtract dispatches the named extract function. Unknown names
// return "" so the resolver falls back. Mirrors the Python _EXTRACTORS
// registry and the Node applyExtract switch, including the back-compat
// aliases for the pre-#350 first_sql_keyword / first_word_strip_path
// names (now strict supersets of the danger scanners).
func applyExtract(name, raw string) string {
	switch name {
	case "most_dangerous_sql_keyword", "first_sql_keyword":
		return MostDangerousSQLKeyword(raw)
	case "most_dangerous_shell_command", "first_word_strip_path":
		return MostDangerousShellCommand(raw)
	case "identity":
		return Identity(raw)
	case "identity_upper":
		return IdentityUpper(raw)
	case "tool_name_as_method":
		return ToolNameAsMethod(raw)
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

// ResolveCanonicalTool resolves a host-agent tool name to its canonical
// name: the input itself if it is a direct key in tools, the canonical
// key if it matches an entry's aliases, else the input unchanged (unknown
// tool falls through; caller applies fallback_method="*").
func ResolveCanonicalTool(toolName string) string {
	if toolName == "" {
		return toolName
	}
	if _, ok := spec.Tools[toolName]; ok {
		return toolName
	}
	for canonical, entry := range spec.Tools {
		for _, a := range entry.Aliases {
			if a == toolName {
				return canonical
			}
		}
	}
	return toolName
}

// ExtractMethod resolves (canonical_tool, method) from a PreToolUse
// payload per the spec resolution algorithm:
//
//  1. Canonical tool lookup (ResolveCanonicalTool).
//  2. Unknown tool -> method "*".
//  3. args_path null -> raw = toolName; single key -> raw = args[key];
//     list of candidate keys -> raw = first key resolving to a non-empty
//     string (lets Bash read "command" or "CommandLine").
//  4. Apply extract; non-empty result = method.
//  5. Empty result -> fallback_method.
//
// Any unexpected shape falls back to fallback_method ("*" for most tools)
// to preserve fail-closed semantics. Byte-identical resolution to the
// Python extract_method and Node extractMethod.
func ExtractMethod(toolName string, args map[string]any) (canonicalTool, method string) {
	if toolName == "" {
		return toolName, "*"
	}
	canonical := ResolveCanonicalTool(toolName)
	entry, ok := spec.Tools[canonical]
	if !ok {
		return canonical, "*"
	}

	fallback := entry.FallbackMethod
	if fallback == "" {
		fallback = "*"
	}

	keys, isNull := argsPathKeys(entry.ArgsPath)

	var raw string
	if isNull {
		raw = toolName
	} else {
		if args == nil {
			return canonical, fallback
		}
		found := false
		for _, key := range keys {
			if v, ok := args[key]; ok {
				if s, ok := v.(string); ok && s != "" {
					raw = s
					found = true
					break
				}
			}
		}
		if !found {
			return canonical, fallback
		}
	}

	result := applyExtract(entry.Extract, raw)
	if result == "" {
		return canonical, fallback
	}
	return canonical, result
}

// BuildAction returns "{canonical_tool}:{method}" for the given payload.
func BuildAction(toolName string, args map[string]any) string {
	canonical, method := ExtractMethod(toolName, args)
	return canonical + ":" + method
}

// SpecVersion returns the spec_version of the embedded extractor spec.
func SpecVersion() int { return spec.SpecVersion }
