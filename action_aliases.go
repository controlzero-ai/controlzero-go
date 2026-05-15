package controlzero

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// T84 / GitHub #389. Mandate: NO BREAKING CHANGES.
//
// Pre-#350 customer rules used legacy database action names directly: a
// rule with actions: ["database:query"] or actions: ["database:DROP"]
// matched a guard call where the SDK passed method="query" /
// method="DROP". Starting with #345/#350 the SDK emits canonical SQL
// semantic classes instead (database:read, database:write,
// database:admin, database:exec).
//
// Without an alias shim, that change broke every pre-#350 rule on the
// day a customer upgraded the SDK. This file is the single source of
// truth across all three SDKs (Python / Node / Go); the cross-SDK
// fixture at tests/parity/action_aliases.json is byte-identical to
// the JSON dump of this table (modulo the dev-only "comment" key).
//
// The legacy database:delete action is intentionally ambiguous: older
// policies used it for both row-level DELETE and table-level DROP. We
// map it to BOTH database:write AND database:admin so neither modern
// intent is silently broken.

// AliasTool is the only tool covered by this alias table today. Other
// tools were added post-#350 and always emitted canonical names.
const AliasTool = "database"

// classOrder fixes the iteration order so the JSON dump is
// deterministic across runs / platforms / Go versions.
var classOrder = []string{"read", "write", "admin", "exec"}

// classes maps each canonical class to its ordered list of legacy
// aliases. Order matters because the JSON dump compares against the
// on-disk parity fixture.
var classes = map[string][]string{
	"read":  {"query", "SELECT", "EXPLAIN", "SHOW", "DESCRIBE", "FETCH", "READ"},
	"write": {"UPDATE", "INSERT", "DELETE", "MERGE", "UPSERT", "REPLACE"},
	"admin": {"DROP", "CREATE", "TRUNCATE", "ALTER", "GRANT", "REVOKE", "RENAME"},
	"exec":  {"execute", "EXECUTE", "EXEC", "CALL", "do"},
}

// ambiguous lists legacy aliases that map to MORE THAN ONE canonical
// class. A rule written against the legacy ambiguous name keeps firing
// on either modern intent.
var ambiguousOrder = []string{"delete"}
var ambiguous = map[string][]string{
	"delete": {"write", "admin"},
}

func canonical(method string) string { return AliasTool + ":" + method }

// Pre-built indexes. Built once at package init so guard() stays cheap
// on the hot path.
var legacyToCanonical map[string]map[string]struct{}
var canonicalToLegacy map[string]map[string]struct{}

func init() {
	legacyToCanonical = make(map[string]map[string]struct{})
	canonicalToLegacy = make(map[string]map[string]struct{})
	for _, cls := range classOrder {
		canon := canonical(cls)
		set := make(map[string]struct{})
		for _, alias := range classes[cls] {
			if legacyToCanonical[alias] == nil {
				legacyToCanonical[alias] = make(map[string]struct{})
			}
			legacyToCanonical[alias][canon] = struct{}{}
			set[canonical(alias)] = struct{}{}
		}
		canonicalToLegacy[canon] = set
	}
	for _, alias := range ambiguousOrder {
		if legacyToCanonical[alias] == nil {
			legacyToCanonical[alias] = make(map[string]struct{})
		}
		for _, cls := range ambiguous[alias] {
			legacyToCanonical[alias][canonical(cls)] = struct{}{}
		}
	}
}

// ExpandCandidateActions expands an input slice of candidate actions
// to include every known alias in both directions (legacy ->
// canonical AND canonical -> legacy). Originals stay first in stable
// input order; expansions follow in deterministic order.
func ExpandCandidateActions(actions []string) []string {
	seen := make(map[string]struct{}, len(actions)*4)
	out := make([]string, 0, len(actions)*4)

	for _, a := range actions {
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}

	originals := append([]string(nil), out...)
	for _, action := range originals {
		idx := strings.Index(action, ":")
		if idx < 0 {
			continue
		}
		tool := action[:idx]
		method := action[idx+1:]
		if tool != AliasTool {
			continue
		}

		// Legacy method -> canonical(s). Sorted for determinism.
		if cans := legacyToCanonical[method]; cans != nil {
			keys := make([]string, 0, len(cans))
			for k := range cans {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if _, ok := seen[k]; !ok {
					seen[k] = struct{}{}
					out = append(out, k)
				}
			}
		}

		// Canonical action -> legacy aliases. Sorted for determinism.
		if legs := canonicalToLegacy[action]; legs != nil {
			keys := make([]string, 0, len(legs))
			for k := range legs {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if _, ok := seen[k]; !ok {
					seen[k] = struct{}{}
					out = append(out, k)
				}
			}
		}
	}

	return out
}

// AliasTableJSON returns a deterministic JSON dump of the alias table
// for parity testing against the cross-SDK fixture. Excludes the dev-
// only "comment" key from the on-disk fixture so each SDK's hash
// check compares apples to apples.
func AliasTableJSON() string {
	type classEntry struct {
		Canonical string   `json:"canonical"`
		Aliases   []string `json:"aliases"`
	}

	// Manual marshalling to guarantee ordered keys (Go maps are
	// randomized; encoding/json sorts struct field order by source
	// declaration but maps are sorted alphabetically). We need a
	// specific class iteration order, so build the JSON by hand.
	var buf bytes.Buffer
	buf.WriteString("{\n")
	buf.WriteString("  \"version\": 1,\n")
	buf.WriteString("  \"tool\": ")
	tb, _ := json.Marshal(AliasTool)
	buf.Write(tb)
	buf.WriteString(",\n")

	buf.WriteString("  \"classes\": {\n")
	for i, cls := range classOrder {
		entry := classEntry{
			Canonical: canonical(cls),
			Aliases:   classes[cls],
		}
		eb, _ := json.MarshalIndent(entry, "    ", "  ")
		buf.WriteString("    \"")
		buf.WriteString(cls)
		buf.WriteString("\": ")
		buf.Write(eb)
		if i < len(classOrder)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("  },\n")

	buf.WriteString("  \"ambiguous_aliases\": {\n")
	for i, alias := range ambiguousOrder {
		ab, _ := json.Marshal(ambiguous[alias])
		buf.WriteString("    \"")
		buf.WriteString(alias)
		buf.WriteString("\": ")
		buf.Write(ab)
		if i < len(ambiguousOrder)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("  }\n")
	buf.WriteString("}")
	return buf.String()
}
