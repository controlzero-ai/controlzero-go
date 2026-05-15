package controlzero

import (
	"strings"
	"testing"
)

func TestFindKeyLeaks_FullLiveKey(t *testing.T) {
	text := "CONTROLZERO_API_KEY=cz_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa controlzero hook-check"
	matches := FindKeyLeaks(text)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	expected := "cz_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if matches[0].Key != expected {
		t.Errorf("expected key %q, got %q", expected, matches[0].Key)
	}
	if matches[0].LineNumber != 1 {
		t.Errorf("expected line 1, got %d", matches[0].LineNumber)
	}
}

func TestFindKeyLeaks_TestKey(t *testing.T) {
	matches := FindKeyLeaks("key: cz_test_localdev_000000000000000000000000")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestFindKeyLeaks_LineNumberIs1Indexed(t *testing.T) {
	text := "line1\nline2\ncz_live_abcd1234567890"
	matches := FindKeyLeaks(text)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].LineNumber != 3 {
		t.Errorf("expected line 3, got %d", matches[0].LineNumber)
	}
}

func TestFindKeyLeaks_MultipleKeys(t *testing.T) {
	text := "a CONTROLZERO_API_KEY=cz_live_aaaaaaaaaaaaaaaa b\n" +
		"c CONTROLZERO_API_KEY=cz_test_bbbbbbbbbbbbbbbb d"
	matches := FindKeyLeaks(text)
	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}
}

func TestFindKeyLeaks_DoesNotMatchUsername(t *testing.T) {
	if len(FindKeyLeaks("cz_user = 'bob'")) != 0 {
		t.Error("expected no matches for cz_user")
	}
}

func TestFindKeyLeaks_DoesNotMatchDocPlaceholder(t *testing.T) {
	if len(FindKeyLeaks("Set CONTROLZERO_API_KEY=cz_live_xxx")) != 0 {
		t.Error("expected no matches for cz_live_xxx placeholder")
	}
}

func TestFindKeyLeaks_EmptyInput(t *testing.T) {
	if FindKeyLeaks("") != nil {
		t.Error("expected nil for empty input")
	}
}

func TestRedactKey_LiveKey(t *testing.T) {
	got := RedactKey("cz_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if got != "cz_live_***aaaaa" {
		t.Errorf("expected cz_live_***aaaaa, got %q", got)
	}
}

func TestRedactKey_TestKey(t *testing.T) {
	got := RedactKey("cz_test_localdev_000000000000000000000000")
	if got != "cz_test_***00000" {
		t.Errorf("expected cz_test_***00000, got %q", got)
	}
}

func TestRedactKey_NonKeyReturnedVerbatim(t *testing.T) {
	if RedactKey("not a key") != "not a key" {
		t.Error("expected non-key input returned verbatim")
	}
	if RedactKey("") != "" {
		t.Error("expected empty -> empty")
	}
}

func TestRedactKey_WhitespaceStripped(t *testing.T) {
	got := RedactKey("  cz_live_abcd1234567890  ")
	if got != "cz_live_***67890" {
		t.Errorf("expected cz_live_***67890, got %q", got)
	}
}

func TestRedactText_ReplacesAll(t *testing.T) {
	text := "key1=cz_live_aaaaaaaaaaaaaa\nkey2=cz_test_bbbbbbbbbbbbbb"
	out := RedactText(text)
	if strings.Contains(out, "cz_live_aaaa") || strings.Contains(out, "cz_test_bbbb") {
		t.Errorf("raw keys still present: %q", out)
	}
	if !strings.Contains(out, "cz_live_***") || !strings.Contains(out, "cz_test_***") {
		t.Errorf("redactions missing: %q", out)
	}
}

func TestRedactText_Idempotent(t *testing.T) {
	text := "key=cz_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	once := RedactText(text)
	twice := RedactText(once)
	if once != twice {
		t.Errorf("redactText not idempotent: %q vs %q", once, twice)
	}
}
