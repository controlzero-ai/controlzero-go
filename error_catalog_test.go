// Cross-language conformance for the shared E#### error catalog (#893).
//
// error_catalog.go is generated from the language-neutral manifest
// sdks/error-catalog/error_codes.yaml. This test asserts the generated
// Go catalog matches the shared golden
// (sdks/error-catalog/error_codes.golden.json) byte-for-byte. The Python
// and Node SDKs assert the same golden, so a green run across all three
// proves the catalogs are identical: a given E#### code carries the same
// title, fix, and doc URL in every client.

package controlzero

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type goldenRecord struct {
	Code  string `json:"code"`
	Title string `json:"title"`
	What  string `json:"what"`
	Fix   string `json:"fix"`
	Doc   string `json:"doc"`
}

// findGoldenPath walks up from the test's working directory to locate the
// shared golden fixture. Mirrors findVectorPath in conformance_test.go.
func findGoldenPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 12; i++ {
		for _, rel := range []string{
			filepath.Join("error-catalog", "error_codes.golden.json"),
			filepath.Join("sdks", "error-catalog", "error_codes.golden.json"),
		} {
			candidate := filepath.Join(dir, rel)
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("sdks/error-catalog/error_codes.golden.json not found")
	return ""
}

func loadGolden(t *testing.T) map[string]goldenRecord {
	t.Helper()
	data, err := os.ReadFile(findGoldenPath(t))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var golden map[string]goldenRecord
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	return golden
}

func TestErrorCatalogMatchesGolden(t *testing.T) {
	golden := loadGolden(t)

	// Same code set.
	got := AllErrorCodes()
	gotSorted := append([]string(nil), got...)
	sort.Strings(gotSorted)
	wantSorted := make([]string, 0, len(golden))
	for code := range golden {
		wantSorted = append(wantSorted, code)
	}
	sort.Strings(wantSorted)
	if len(gotSorted) != len(wantSorted) {
		t.Fatalf("code count mismatch: catalog has %d, golden has %d", len(gotSorted), len(wantSorted))
	}
	for i := range gotSorted {
		if gotSorted[i] != wantSorted[i] {
			t.Fatalf("code set mismatch at %d: catalog=%q golden=%q", i, gotSorted[i], wantSorted[i])
		}
	}

	// Same field values for every code.
	for code, want := range golden {
		rec, ok := GetErrorCode(code)
		if !ok {
			t.Errorf("%s: present in golden but missing from catalog", code)
			continue
		}
		if rec.Code != want.Code {
			t.Errorf("%s.code: catalog=%q golden=%q", code, rec.Code, want.Code)
		}
		if rec.Title != want.Title {
			t.Errorf("%s.title: catalog=%q golden=%q", code, rec.Title, want.Title)
		}
		if rec.What != want.What {
			t.Errorf("%s.what: catalog=%q golden=%q", code, rec.What, want.What)
		}
		if rec.Fix != want.Fix {
			t.Errorf("%s.fix: catalog=%q golden=%q", code, rec.Fix, want.Fix)
		}
		if rec.Doc != want.Doc {
			t.Errorf("%s.doc: catalog=%q golden=%q", code, rec.Doc, want.Doc)
		}
	}
}

func TestGetErrorCodeKnownReturnsFullRecord(t *testing.T) {
	rec, ok := GetErrorCode("E1001")
	if !ok {
		t.Fatal("E1001 missing from catalog")
	}
	if rec.Code != "E1001" {
		t.Errorf("code = %q, want E1001", rec.Code)
	}
	if rec.Title != "API key found in agent settings file" {
		t.Errorf("unexpected title: %q", rec.Title)
	}
	if rec.Doc != "E1001-api-key-in-settings" {
		t.Errorf("unexpected doc: %q", rec.Doc)
	}
	if rec.What == "" || rec.Fix == "" {
		t.Error("what/fix should be non-empty")
	}
}

func TestGetErrorCodeUnknownIsNotOK(t *testing.T) {
	if _, ok := GetErrorCode("E9999"); ok {
		t.Error("E9999 should not be in the catalog")
	}
}

func TestErrorDocURL(t *testing.T) {
	got := ErrorDocURL("E1001")
	want := "https://docs.controlzero.ai/errors/E1001-api-key-in-settings"
	if got != want {
		t.Errorf("ErrorDocURL = %q, want %q", got, want)
	}
	if ErrorDocURL("E9999") != "" {
		t.Error("unknown code should yield empty docs URL")
	}
}

// The Go SDK's typed errors advertise stable E#### codes. Every advertised
// code must resolve in the shared catalog so cross-SDK consumers see the
// same record.
func TestTypedErrorCodesResolveInCatalog(t *testing.T) {
	golden := loadGolden(t)
	codes := []string{
		ECodeBundleRequiresNewerSDK, // E1712
		ECodeCredentialLeakBlocked,  // E2001
	}
	for _, code := range codes {
		if _, ok := golden[code]; !ok {
			t.Errorf("typed-error code %q missing from shared golden", code)
		}
		if _, ok := GetErrorCode(code); !ok {
			t.Errorf("typed-error code %q missing from generated catalog", code)
		}
	}
}
