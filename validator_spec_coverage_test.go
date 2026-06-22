package controlzero_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	controlzero "controlzero.ai/sdk/go"
)

// #341/#362 drift guard: every canonical tool name and every host alias
// in the extractor spec MUST be recognised by the SDK's unknown-action
// validator (action_validator.go). Otherwise a customer authoring a rule
// against, say, `run_command:*` (a valid Antigravity host alias) would be
// warned it is unknown even though the extractor canonicalises it. This
// test fails loudly when the spec adds an alias the validator map missed,
// the way the Go SDK fell behind Python/Node before this port.

func loadSpecForCoverage(t *testing.T) map[string]any {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	var path string
	for i := 0; i < 12; i++ {
		c := filepath.Join(dir, "tests", "fixtures", "enforcement-spec",
			"extractors", "tool-extractors.json")
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			path = c
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if path == "" {
		t.Skip("canonical spec not found above this source (packaged module)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	return doc
}

func TestValidatorCoversSpecAliases(t *testing.T) {
	doc := loadSpecForCoverage(t)
	tools, _ := doc["tools"].(map[string]any)
	if len(tools) == 0 {
		t.Fatalf("spec has no tools")
	}
	for canonical, raw := range tools {
		entry, _ := raw.(map[string]any)
		// Canonical tool name itself must validate as <tool>:*.
		if !controlzero.IsKnownAction(canonical + ":*") {
			t.Errorf("validator does not recognise canonical tool %q (%q:*)", canonical, canonical)
		}
		aliases, _ := entry["aliases"].([]any)
		for _, a := range aliases {
			alias, _ := a.(string)
			if alias == "" {
				continue
			}
			if !controlzero.IsKnownAction(alias + ":*") {
				t.Errorf("validator does not recognise spec alias %q (%q:*); add it to canonicalToolsForValidator", alias, alias)
			}
		}
	}
}
