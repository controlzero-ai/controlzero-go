package hookextractors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Cross-SDK parity for the coding-agent tool-extractor spec (#362, #350,
// #341). The fixture at
// tests/fixtures/enforcement-spec/extractors/parity-cases.json is the
// shared contract: the Python (test_hook_extractors.py /
// test_sql_semantic_class.py) and Node (hookExtractors.test.ts /
// sqlSemanticClass.test.ts) SDKs run the SAME cases. The Go SDK MUST
// produce byte-identical (canonical_tool, method, action) tuples plus
// byte-identical (keyword, class) tuples or it has drifted from the other
// two runtimes.
//
// The fixture lives in the monorepo tree, NOT inside the published Go
// module, so we walk up from this source file to find it and skip (rather
// than fail) when it is absent -- matching spec_compliance_test.go and the
// Python/Node sibling tests, which also skip when run from a packaged
// artifact that does not carry the fixture.

type parityCase struct {
	Name                  string         `json:"name"`
	ToolNameFromHost      string         `json:"tool_name_from_host"`
	Args                  map[string]any `json:"args"`
	ExpectedCanonicalTool string         `json:"expected_canonical_tool"`
	ExpectedMethod        string         `json:"expected_method"`
	ExpectedAction        string         `json:"expected_action"`
}

type sqlSemanticClassCase struct {
	Name            string `json:"name"`
	SQL             string `json:"sql"`
	ExpectedKeyword string `json:"expected_keyword"`
	ExpectedClass   string `json:"expected_class"`
}

type parityFixture struct {
	SpecVersion           int                    `json:"spec_version"`
	Cases                 []parityCase           `json:"cases"`
	SQLSemanticClassCases []sqlSemanticClassCase `json:"sql_semantic_class_cases"`
}

// findParityFixture walks up from this source file to locate the shared
// parity-cases.json fixture. Returns "" if not found.
func findParityFixture() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	dir := filepath.Dir(thisFile)
	for i := 0; i < 12; i++ {
		candidate := filepath.Join(dir, "tests", "fixtures", "enforcement-spec",
			"extractors", "parity-cases.json")
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func loadParityFixture(t *testing.T) *parityFixture {
	t.Helper()
	path := findParityFixture()
	if path == "" {
		t.Skip("parity fixture tests/fixtures/enforcement-spec/extractors/parity-cases.json not found above this source (packaged module); skipping")
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read parity fixture %s: %v", path, err)
	}
	var fx parityFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("parse parity fixture %s: %v", path, err)
	}
	return &fx
}

// TestParityCases asserts every (tool, args) -> (canonical_tool, method,
// action) case in the shared fixture matches the Go extractor, proving the
// Go SDK is byte-identical to Python + Node.
func TestParityCases(t *testing.T) {
	fx := loadParityFixture(t)
	if fx == nil {
		return
	}
	if len(fx.Cases) == 0 {
		t.Fatalf("parity fixture has zero cases; expected the shared corpus")
	}
	for _, c := range fx.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			canonical, method := ExtractMethod(c.ToolNameFromHost, c.Args)
			if canonical != c.ExpectedCanonicalTool {
				t.Errorf("%s: canonical_tool = %q, want %q", c.Name, canonical, c.ExpectedCanonicalTool)
			}
			if method != c.ExpectedMethod {
				t.Errorf("%s: method = %q, want %q", c.Name, method, c.ExpectedMethod)
			}
			action := BuildAction(c.ToolNameFromHost, c.Args)
			if action != c.ExpectedAction {
				t.Errorf("%s: action = %q, want %q", c.Name, action, c.ExpectedAction)
			}
		})
	}
}

// TestSQLSemanticClassParity asserts every (sql) -> (keyword, class) case
// in the shared fixture matches the Go extractor. This is the #350
// portable-class layer: a Go consumer running hook-check against a CTE /
// EXPLAIN / SHOW gets database:read.
func TestSQLSemanticClassParity(t *testing.T) {
	fx := loadParityFixture(t)
	if fx == nil {
		return
	}
	if len(fx.SQLSemanticClassCases) == 0 {
		t.Fatalf("parity fixture has zero sql_semantic_class_cases; expected the #350 corpus")
	}
	for _, c := range fx.SQLSemanticClassCases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			kw := MostDangerousSQLKeyword(c.SQL)
			if kw != c.ExpectedKeyword {
				t.Errorf("%s: keyword = %q, want %q (sql=%q)", c.Name, kw, c.ExpectedKeyword, c.SQL)
			}
			cls := SQLSemanticClass(c.SQL)
			if cls != c.ExpectedClass {
				t.Errorf("%s: class = %q, want %q (sql=%q)", c.Name, cls, c.ExpectedClass, c.SQL)
			}
		})
	}
}

// TestEmbeddedSpecMatchesFixture asserts the embedded spec.json is
// byte-identical to the canonical tool-extractors.json fixture. This is
// the in-test mirror of scripts/ci/check-extractor-spec-drift.sh so a
// drift is caught by `go test` too, not only by the shell drift gate.
func TestEmbeddedSpecMatchesFixture(t *testing.T) {
	path := findCanonicalSpec()
	if path == "" {
		t.Skip("canonical tool-extractors.json not found above this source (packaged module); skipping drift check")
		return
	}
	canonical, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read canonical spec %s: %v", path, err)
	}
	if string(canonical) != string(specJSON) {
		t.Fatalf("embedded spec.json has drifted from canonical %s; "+
			"re-copy the fixture over sdks/go/controlzero/internal/hookextractors/spec.json", path)
	}
}

func findCanonicalSpec() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	dir := filepath.Dir(thisFile)
	for i := 0; i < 12; i++ {
		candidate := filepath.Join(dir, "tests", "fixtures", "enforcement-spec",
			"extractors", "tool-extractors.json")
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// TestSpecVersionIsV2 guards the #341 spec_version: 2 bump (web_search,
// file_search, task canonicals + extended Bash/file aliases).
func TestSpecVersionIsV2(t *testing.T) {
	if SpecVersion() != 2 {
		t.Fatalf("embedded spec_version = %d, want 2 (the #341 alias-map bump)", SpecVersion())
	}
}
