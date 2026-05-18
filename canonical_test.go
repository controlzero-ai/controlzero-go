// Phase 1A: Go SDK RFC 8785 CanonicalJSON + ArgsHash unit tests +
// cross-SDK parity (#450).
//
// Loads tests/parity/jcs_args_hash_vectors.json (canonical at repo
// root tests/parity/, vendored copy at sdks/go/controlzero/tests/parity/)
// and asserts byte-identical SHA-256 hex over the canonical bytes for
// every vector. Mirrors the Python and Node parity tests; the same
// fixture is consumed by all three SDKs.

package controlzero

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type jcsVector struct {
	Name        string      `json:"name"`
	Input       interface{} `json:"input"`
	ExpectedHex string      `json:"expected_hex"`
}

type jcsFixture struct {
	Vectors []jcsVector `json:"vectors"`
}

// locateJCSFixture walks up from the test cwd looking for
// `<dir>/tests/parity/jcs_args_hash_vectors.json`. The walk finds
// EITHER:
//
//   - the vendored Go copy at sdks/go/controlzero/tests/parity/... when
//     the test runs from inside the SDK directory (Dockerfile.test
//     mount), OR
//   - the canonical repo-root copy at <repo>/tests/parity/... when the
//     test runs against a full workspace checkout.
//
// Both targets share the same `tests/parity/<fixture>` relative path,
// so a single stat-loop catches both. Earlier revisions of this helper
// built two identical candidates and looped them, which read like
// dead-code; reviewers flagged it on PR #463. Drift between vendored
// and canonical copies is the job of
// scripts/ci/check-extractor-spec-drift.sh, not this locator.
func locateJCSFixture(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for dir := wd; ; {
		candidate := filepath.Join(dir, "tests", "parity", "jcs_args_hash_vectors.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("jcs_args_hash_vectors.json not visible from this test mount")
	return ""
}

func loadJCSVectors(t *testing.T) []jcsVector {
	path := locateJCSFixture(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f jcsFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return f.Vectors
}

// ---- unit ----

func TestCanonicalJSON_SortsKeys(t *testing.T) {
	a, err := CanonicalJSON(map[string]interface{}{"z": 1, "a": 2})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	b, err := CanonicalJSON(map[string]interface{}{"a": 2, "z": 1})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("expected byte-identical canonical bytes, got %q vs %q", a, b)
	}
}

func TestCanonicalJSON_PreservesUnicode(t *testing.T) {
	out, err := CanonicalJSON(map[string]interface{}{"name": "café"})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if !strings.Contains(string(out), "café") {
		t.Fatalf("expected literal café in canonical bytes, got %q", out)
	}
	if strings.Contains(string(out), "\\u00e9") {
		t.Fatalf("JCS must not \\uXXXX-escape, got %q", out)
	}
}

func TestArgsHash_Format(t *testing.T) {
	h := ArgsHash(map[string]interface{}{"command": "rm"})
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %q", h)
	}
	if len(h) != 7+64 {
		t.Fatalf("expected sha256:<64 hex chars>, got %q (len=%d)", h, len(h))
	}
}

func TestArgsHash_NilEqualsEmpty(t *testing.T) {
	if got, want := ArgsHash(nil), ArgsHash(map[string]interface{}{}); got != want {
		t.Fatalf("nil != empty: got=%q want=%q", got, want)
	}
}

func TestArgsHash_Deterministic(t *testing.T) {
	args := map[string]interface{}{"command": "rm -rf /tmp/x", "cwd": "/tmp"}
	if a, b := ArgsHash(args), ArgsHash(args); a != b {
		t.Fatalf("expected deterministic hash, got %q vs %q", a, b)
	}
}

// ---- cross-SDK parity ----

func TestJCSParityVectors(t *testing.T) {
	vectors := loadJCSVectors(t)
	if len(vectors) == 0 {
		t.Skip("no vectors loaded")
	}
	for _, vec := range vectors {
		vec := vec
		t.Run(vec.Name, func(t *testing.T) {
			if strings.HasPrefix(vec.ExpectedHex, "TBD") {
				t.Skipf("placeholder hex; regenerate first")
			}
			canonical, err := CanonicalJSON(vec.Input)
			if err != nil {
				t.Fatalf("CanonicalJSON(%v): %v", vec.Input, err)
			}
			sum := sha256.Sum256(canonical)
			got := hex.EncodeToString(sum[:])
			if got != vec.ExpectedHex {
				t.Fatalf("JCS drift on %q: got %q expected %q (canonical bytes: %q)",
					vec.Name, got, vec.ExpectedHex, canonical)
			}
		})
	}
}

// PR #463 final coverage push (100% mandate on touched files):
// CanonicalJSON returns the json.Marshal error when the input contains
// values json.Marshal refuses (NaN, +Inf, channels, etc.). ArgsHash
// catches the same and returns the empty-string sentinel, firing the
// one-shot stderr warning on the first occurrence.

func TestCanonicalJSON_ReturnsMarshalErrorOnNaN(t *testing.T) {
	_, err := CanonicalJSON(map[string]interface{}{"x": math.NaN()})
	if err == nil {
		t.Fatal("expected json.Marshal error on NaN, got nil")
	}
	if !strings.Contains(err.Error(), "json.Marshal") {
		t.Fatalf("expected json.Marshal in error message, got %q", err.Error())
	}
}

func TestCanonicalJSON_ReturnsMarshalErrorOnChan(t *testing.T) {
	ch := make(chan int)
	_, err := CanonicalJSON(map[string]interface{}{"x": ch})
	if err == nil {
		t.Fatal("expected json.Marshal error on chan, got nil")
	}
}

func TestArgsHash_ReturnsEmptyOnMarshalError(t *testing.T) {
	// NaN through json.Marshal is the deterministic-error path that
	// exercises the ArgsHash warn-once branch. Use a fresh sync.Once
	// is not possible here, but the first call in any test run hits
	// the warn path; later calls fall through silently. We assert the
	// return-value contract: empty string on encoding error.
	h := ArgsHash(map[string]interface{}{"x": math.Inf(1)})
	if h != "" {
		t.Fatalf("expected empty string for +Inf input, got %q", h)
	}
}

func TestCanonicalJSONBytes_WrapsTransformError(t *testing.T) {
	// Internal helper. Public CanonicalJSON never feeds invalid bytes
	// to jcs.Transform because json.Marshal validates its output. We
	// still want the jcs.Transform error-wrap branch covered so a
	// future library change that starts rejecting valid Go values
	// surfaces here instead of silently producing empty hashes in
	// production.
	cases := [][]byte{
		[]byte("not json"),
		[]byte(`{"x":`),
		[]byte(""),
	}
	for _, raw := range cases {
		_, err := canonicalJSONBytes(raw)
		if err == nil {
			t.Fatalf("expected jcs.Transform error for input %q, got nil", raw)
		}
		if !strings.Contains(err.Error(), "jcs.Transform") {
			t.Fatalf("expected jcs.Transform in error message, got %q", err.Error())
		}
	}
}
