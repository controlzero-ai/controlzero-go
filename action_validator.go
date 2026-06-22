package controlzero

// T86 / GitHub #391 -- unknown-action validator (warn-only at SDK load).
//
// Pairs with the backend validator at
// apps/control-zero-platform/backend/internal/policy/action_aliases.go.
// The backend BLOCKS publish on unknown actions (422); the SDK
// WARNS at load time so a customer running local-policy mode (no
// backend) still sees the typo before the rule silently never fires.

import (
	"sort"
	"strings"
)

// canonicalToolsForValidator mirrors the canonical tool set + host
// aliases the extractors accept. Source of truth is
// sdks/python/controlzero/controlzero/_internal/tool_extractors.json;
// update both files together when adding a new client / tool.
var canonicalToolsForValidator = map[string]bool{
	"Bash":              true,
	"database":          true,
	"http":              true,
	"web_search":        true,
	"browser":           true,
	"file_read":         true,
	"file_write":        true,
	"file_search":       true,
	"task":              true,
	"sql":               true,
	"Database":          true,
	"PostgreSQL":        true,
	"MySQL":             true,
	"postgres":          true,
	"sqlite":            true,
	"bash":              true,
	"shell":             true,
	"ShellTool":         true,
	"run_shell_command": true,
	"PowerShell":        true,
	"powershell":        true,
	"Shell":             true,
	"fetch":             true,
	"web_fetch":         true,
	"WebFetch":          true,
	"HTTPRequest":       true,
	"request":           true,
	"WebSearch":         true,
	"google_web_search": true,
	"SearchTool":        true,
	"playwright":        true,
	"Puppeteer":         true,
	"read_file":         true,
	"Read":              true,
	"ReadFile":          true,
	"read_many_files":   true,
	"write_file":        true,
	"Write":             true,
	"WriteFile":         true,
	"edit_file":         true,
	"Edit":              true,
	"replace":           true,
	"apply_patch":       true,
	"Grep":              true,
	"grep_search":       true,
	"Glob":              true,
	"glob":              true,
	"ListDir":           true,
	"Task":              true,
	"Agent":             true,
	"subagent":          true,
	"spawn_agent":       true,
	// #341/#362 Antigravity (run_command / view_file / write_to_file /
	// replace_file_content) host aliases added in spec_version 2. Kept in
	// lockstep with the embedded extractor spec; the
	// TestValidatorCoversSpecAliases guard fails if the spec adds an alias
	// this map does not recognise.
	"run_command":          true,
	"view_file":            true,
	"write_to_file":        true,
	"replace_file_content": true,
}

var databaseToolAliasesForValidator = map[string]bool{
	"database":   true,
	"sql":        true,
	"Database":   true,
	"PostgreSQL": true,
	"MySQL":      true,
	"postgres":   true,
	"sqlite":     true,
}

// knownDatabaseMethodsForValidator is the union of the canonical SQL
// semantic classes plus every legacy alias from the T84 alias table
// plus the ambiguous "delete". Built at init from the existing alias
// tables in action_aliases.go so the validator and the shim stay in
// lockstep.
var knownDatabaseMethodsForValidator map[string]bool

func init() {
	knownDatabaseMethodsForValidator = map[string]bool{"*": true}
	for cls, aliases := range classes {
		knownDatabaseMethodsForValidator[cls] = true
		for _, a := range aliases {
			knownDatabaseMethodsForValidator[a] = true
		}
	}
	for alias := range ambiguous {
		knownDatabaseMethodsForValidator[alias] = true
	}
}

// IsKnownAction reports whether the given canonical action string
// (in <tool>:<method> form, OR a bare "*" universal pattern, OR a
// "<tool>:*" wildcard, OR a "*:<method>" wildcard) is recognised by
// the SDK extractors / alias table.
func IsKnownAction(action string) bool {
	if action == "" {
		return false
	}
	if action == "*" {
		return true
	}
	idx := strings.Index(action, ":")
	if idx < 0 {
		return canonicalToolsForValidator[action]
	}
	tool := action[:idx]
	method := action[idx+1:]
	if tool == "*" {
		return true
	}
	if !canonicalToolsForValidator[tool] {
		return false
	}
	if method == "*" || method == "" {
		return true
	}
	if databaseToolAliasesForValidator[tool] {
		return knownDatabaseMethodsForValidator[method]
	}
	return true
}

func levenshteinValidator(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := d
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func sharesToolPrefixValidator(a, b string) bool {
	ai := strings.Index(a, ":")
	bi := strings.Index(b, ":")
	if ai < 0 || bi < 0 {
		return false
	}
	if a[:ai] != b[:bi] {
		return false
	}
	am := a[ai+1:]
	bm := b[bi+1:]
	if am == "" || bm == "" {
		return false
	}
	short := len(am)
	if len(bm) < short {
		short = len(bm)
	}
	overlap := 0
	for i := 0; i < short; i++ {
		if strings.ToLower(string(am[i])) != strings.ToLower(string(bm[i])) {
			break
		}
		overlap++
	}
	return overlap*2 >= short
}

type validatorCandidate struct {
	name   string
	legacy bool
}

func validatorCandidates() []validatorCandidate {
	var out []validatorCandidate
	for _, cls := range classOrder {
		out = append(out, validatorCandidate{name: AliasTool + ":" + cls, legacy: false})
	}
	for _, cls := range classOrder {
		for _, a := range classes[cls] {
			out = append(out, validatorCandidate{name: AliasTool + ":" + a, legacy: true})
		}
	}
	for _, alias := range ambiguousOrder {
		out = append(out, validatorCandidate{name: AliasTool + ":" + alias, legacy: true})
	}
	for tool := range canonicalToolsForValidator {
		out = append(out, validatorCandidate{name: tool + ":*", legacy: false})
	}
	return out
}

// SuggestForAction returns up to maxSuggestions did-you-mean
// candidates for an unknown action.
func SuggestForAction(action string) []string {
	const maxSuggestions = 3
	const maxDistance = 3
	cands := validatorCandidates()
	type scored struct {
		name   string
		dist   int
		legacy bool
	}
	var hits []scored
	for _, c := range cands {
		d := levenshteinValidator(action, c.name)
		if d > maxDistance && !sharesToolPrefixValidator(action, c.name) {
			continue
		}
		hits = append(hits, scored{name: c.name, dist: d, legacy: c.legacy})
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].dist != hits[j].dist {
			return hits[i].dist < hits[j].dist
		}
		if hits[i].legacy != hits[j].legacy {
			return !hits[i].legacy
		}
		return hits[i].name < hits[j].name
	})
	if len(hits) > maxSuggestions {
		hits = hits[:maxSuggestions]
	}
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		if h.legacy {
			out = append(out, h.name+" (legacy)")
		} else {
			out = append(out, h.name)
		}
	}
	return out
}

// ValidateActionsT86 returns the slice of unknown actions plus a
// suggestion map keyed by the offending action. Exported under the
// T86 suffix to avoid colliding with the alias-shim's existing
// ExpandCandidateActions helper.
func ValidateActionsT86(actions []string) (unknown []string, suggestions map[string][]string) {
	suggestions = map[string][]string{}
	seen := map[string]bool{}
	for _, a := range actions {
		if IsKnownAction(a) {
			continue
		}
		if seen[a] {
			continue
		}
		seen[a] = true
		unknown = append(unknown, a)
		suggestions[a] = SuggestForAction(a)
	}
	return unknown, suggestions
}
