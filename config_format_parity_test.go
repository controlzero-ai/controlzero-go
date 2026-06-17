package controlzero

// JSON+YAML policy-config parity (#1303 follow-up, #67). The same policy
// authored as YAML and as JSON must parse to an identical rule set. JSON is a
// first-class policy-config format, not an incidental side effect of the YAML
// parser (LoadPolicy dispatches on the file extension: .yaml/.yml -> YAML,
// .json -> JSON). The Client cwd auto-discovery already covers all three
// extensions (see t103_precedence_test.go); this locks the loader parity.

import (
	"os"
	"path/filepath"
	"testing"
)

const parityYAML = `version: '1'
rules:
  - deny: 'delete_*'
  - allow: 'read_*'
  - effect: deny
    action: shell_exec
    id: no-shell
`

const parityJSON = `{
  "version": "1",
  "rules": [
    {"deny": "delete_*"},
    {"allow": "read_*"},
    {"effect": "deny", "action": "shell_exec", "id": "no-shell"}
  ]
}`

func TestYAMLAndJSONParseToIdenticalRules(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "controlzero.yaml")
	jsonPath := filepath.Join(dir, "controlzero.json")
	if err := os.WriteFile(yamlPath, []byte(parityYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonPath, []byte(parityJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	yamlRules, err := LoadPolicy(yamlPath)
	if err != nil {
		t.Fatalf("LoadPolicy(yaml): %v", err)
	}
	jsonRules, err := LoadPolicy(jsonPath)
	if err != nil {
		t.Fatalf("LoadPolicy(json): %v", err)
	}

	if len(yamlRules) != len(jsonRules) {
		t.Fatalf("rule count mismatch: yaml=%d json=%d", len(yamlRules), len(jsonRules))
	}
	for i := range yamlRules {
		y, j := yamlRules[i], jsonRules[i]
		if y.Effect != j.Effect {
			t.Errorf("rule %d effect: yaml=%q json=%q", i, y.Effect, j.Effect)
		}
		if y.ID != j.ID {
			t.Errorf("rule %d id: yaml=%q json=%q", i, y.ID, j.ID)
		}
		if len(y.Actions) != len(j.Actions) {
			t.Errorf("rule %d action count: yaml=%v json=%v", i, y.Actions, j.Actions)
			continue
		}
		for k := range y.Actions {
			if y.Actions[k] != j.Actions[k] {
				t.Errorf("rule %d action %d: yaml=%q json=%q", i, k, y.Actions[k], j.Actions[k])
			}
		}
	}
}

// The validate CLI command's no-arg path auto-discovers the same extension
// set. firstExistingPolicyFile lives in cmd/controlzero; here we assert the
// loader half (extension dispatch) rejects an unknown extension, which is the
// contract the CLI relies on.
func TestLoadPolicyRejectsUnknownExtension(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "controlzero.txt")
	if err := os.WriteFile(p, []byte(parityJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(p); err == nil {
		t.Fatal("expected error for unsupported .txt extension, got nil")
	}
}
