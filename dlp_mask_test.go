package controlzero

import (
	"strings"
	"testing"
)

// These tests guard the Go-SDK DLP mask path. Before it existed, a DLP rule
// with action="mask" found matches but nothing redacted -- the raw secret was
// forwarded under an allow (a silent leak). Each test below FAILS if that
// regression returns.

func maskOnlyScanner(pattern, category string) *DLPScanner {
	s := NewDLPScannerNoBuiltins()
	s.AddRules([]map[string]interface{}{
		{"id": "test-mask", "name": "Test mask", "pattern": pattern, "category": category, "action": "mask"},
	})
	return s
}

func TestMaskPlaceholder_ByteIdenticalFormat(t *testing.T) {
	if got := MaskPlaceholder("test-mask"); got != "[REDACTED-TEST-MASK]" {
		t.Errorf("MaskPlaceholder(test-mask) = %q, want [REDACTED-TEST-MASK]", got)
	}
	if got := MaskPlaceholder("my rule"); got != "[REDACTED-MY_RULE]" {
		t.Errorf("space->underscore failed: %q", got)
	}
	if got := MaskPlaceholder(""); got != "[REDACTED-PII]" {
		t.Errorf("empty id = %q, want [REDACTED-PII]", got)
	}
}

func TestMaskArgs_StringLeaf_NoLeak(t *testing.T) {
	s := maskOnlyScanner(`\d{3}-\d{2}-\d{4}`, "pii")
	args := map[string]interface{}{"note": "patient SSN 123-45-6789 on file"}
	maskedAny, matches := s.MaskArgs(args)
	masked, ok := maskedAny.(map[string]interface{})
	if !ok {
		t.Fatalf("MaskArgs did not return a map, got %T", maskedAny)
	}
	got, _ := masked["note"].(string)
	if strings.Contains(got, "123-45-6789") {
		t.Fatalf("SECRET LEAKED: masked output still contains the SSN: %q", got)
	}
	if !strings.Contains(got, "[REDACTED-TEST-MASK]") {
		t.Errorf("expected redaction token, got %q", got)
	}
	if !HasMaskMatch(matches) {
		t.Errorf("expected a mask match in returned matches")
	}
}

func TestMaskArgs_NumberLeaf_NoLeak(t *testing.T) {
	// A JSON NUMBER that matches a mask rule must be redacted, not forwarded
	// raw (the Korean card/RRN/account-as-number leak class).
	s := maskOnlyScanner(`\d{16}`, "financial")
	args := map[string]interface{}{"card": 4111111111111111}
	maskedAny, _ := s.MaskArgs(args)
	masked := maskedAny.(map[string]interface{})
	got := masked["card"]
	gotStr, isStr := got.(string)
	if !isStr || strings.Contains(gotStr, "4111111111111111") {
		t.Fatalf("NUMBER SECRET LEAKED (not masked to a string): %v (%T)", got, got)
	}
	if !strings.Contains(gotStr, "[REDACTED-") {
		t.Errorf("expected redaction token, got %q", gotStr)
	}
}

func TestMaskText_CoalescesOverlap_NoCorruptLeak(t *testing.T) {
	// Two overlapping mask spans must merge into one clean placeholder; a naive
	// right-to-left splice would corrupt offsets and leak tail bytes.
	matches := []DLPMatch{
		{RuleID: "a", Action: "mask", Offset: 0, Length: 6},
		{RuleID: "b", Action: "mask", Offset: 2, Length: 3},
	}
	out := MaskText("ABCDEFGH", matches)
	if strings.Contains(out, "ABCDEF") {
		t.Fatalf("overlap leak: original span survived: %q", out)
	}
	if out != "[REDACTED-A]GH" {
		t.Errorf("MaskText overlap = %q, want [REDACTED-A]GH", out)
	}
}

func TestMaskText_NoMaskMatches_Unchanged(t *testing.T) {
	// detect/block matches must NOT be spliced by MaskText.
	matches := []DLPMatch{{RuleID: "d", Action: "detect", Offset: 0, Length: 3}}
	if out := MaskText("hello", matches); out != "hello" {
		t.Errorf("detect-only MaskText mutated text: %q", out)
	}
}
