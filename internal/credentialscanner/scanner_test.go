// Tests for the credential leak scanner (epic #666, PR-4).
//
// Mirrors the scanner-level scenarios from
// `sdks/python/controlzero/tests/test_credential_hook.py` so the Go
// port keeps byte parity with the Python port and the Rust scanner.
//
// Fixture rule: every credential body uses the literal "EXAMPLE" /
// "notreal" marker so an accidental grep of the test corpus does not
// surface as a false positive in real customer scans.
package credentialscanner

import (
	"errors"
	"strings"
	"testing"
)

// loadDefault is a tiny test helper that fails the test when the
// embedded built_in.yaml refuses to compile. Lets every scenario use
// a one-liner setup.
func loadDefault(t *testing.T) *Scanner {
	t.Helper()
	s, err := Default()
	if err != nil {
		t.Fatalf("Default() returned error: %v", err)
	}
	return s
}

func TestDefaultLoadsEmbeddedLibrary(t *testing.T) {
	s := loadDefault(t)
	if s == nil {
		t.Fatal("Default() returned nil")
	}
	if len(s.regexRecords) == 0 && len(s.markerRecords) == 0 {
		t.Fatal("Default() produced empty scanner")
	}
}

func TestInnocuousTextYieldsNoMatches(t *testing.T) {
	s := loadDefault(t)
	matches := s.Scan("the quick brown fox jumps over the lazy dog. no secrets here.")
	if len(matches) != 0 {
		t.Fatalf("expected zero matches, got %d: %+v", len(matches), matches)
	}
}

func TestAWSAccessKeyFires(t *testing.T) {
	s := loadDefault(t)
	body := "AKIAEXAMPLEKEY00000Z"
	matches := s.Scan("AWS_ACCESS_KEY_ID=" + body)
	var found bool
	for _, m := range matches {
		if m.PatternID == "AWS_ACCESS_KEY_ID" && m.Severity == "P0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected AWS_ACCESS_KEY_ID/P0 hit, got %+v", matches)
	}
}

func TestGitHubPATClassicFires(t *testing.T) {
	s := loadDefault(t)
	pat := "ghp_EXAMPLEnotrealnotrealnotrealnotrealN"
	matches := s.Scan("GITHUB_TOKEN=" + pat)
	var found bool
	for _, m := range matches {
		if m.PatternID == "GITHUB_PAT_CLASSIC" && m.Severity == "P0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected GITHUB_PAT_CLASSIC/P0 hit, got %+v", matches)
	}
}

func TestLoremDoesNotFire(t *testing.T) {
	s := loadDefault(t)
	matches := s.Scan("lorem ipsum dolor sit amet consectetur adipiscing elit")
	if len(matches) != 0 {
		t.Fatalf("lorem prose fired %d matches: %+v", len(matches), matches)
	}
}

func TestEntropyRejectsLowEntropyBody(t *testing.T) {
	// AWS_SECRET_ACCESS_KEY is regex_with_paired_token; a 40-char
	// body with no paired AWS_ACCESS_KEY_ID nearby AND no label MUST
	// NOT fire. Mirrors the Python negative case.
	s := loadDefault(t)
	body := "aB3dEfG7hIjK1lMnOpQrStUvWxYz0123456789AB"
	matches := s.Scan("unrelated value: " + body)
	for _, m := range matches {
		if m.PatternID == "AWS_SECRET_ACCESS_KEY" {
			t.Fatalf("unexpected AWS_SECRET_ACCESS_KEY hit: %+v", matches)
		}
	}
}

func TestPairedTokenResolution(t *testing.T) {
	// A 40-char base64-shaped body within 256 bytes of an
	// AWS_ACCESS_KEY_ID fires the AWS_SECRET_ACCESS_KEY pattern.
	s := loadDefault(t)
	access := "AKIAEXAMPLEKEY00000Z"
	secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	text := "config:\n  access = " + access + "\n  body   = " + secret + "\n"
	matches := s.Scan(text)
	pids := map[string]bool{}
	for _, m := range matches {
		pids[m.PatternID] = true
	}
	if !pids["AWS_ACCESS_KEY_ID"] {
		t.Errorf("missing AWS_ACCESS_KEY_ID match: %+v", matches)
	}
	if !pids["AWS_SECRET_ACCESS_KEY"] {
		t.Errorf("missing AWS_SECRET_ACCESS_KEY match: %+v", matches)
	}
}

func TestMarkerBlockPEMFires(t *testing.T) {
	s := loadDefault(t)
	block := "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"EXAMPLE_THIS_IS_A_PLACEHOLDER_NOT_A_REAL_KEY_FOR_TESTS_ONLY_AAAAA\n" +
		"-----END OPENSSH PRIVATE KEY-----"
	text := "# leaked from agent stdout\n" + block + "\n"
	matches := s.Scan(text)
	var hit bool
	for _, m := range matches {
		if m.PatternID == "SSH_PRIVATE_KEY_OPENSSH" {
			hit = true
			if !strings.HasPrefix(text[m.Start:], "-----BEGIN") {
				t.Errorf("expected match to start at BEGIN marker, start=%d", m.Start)
			}
		}
	}
	if !hit {
		t.Fatalf("expected SSH_PRIVATE_KEY_OPENSSH hit, got %+v", matches)
	}
}

func TestMarkerBlockSkipsUnterminated(t *testing.T) {
	s := loadDefault(t)
	text := "-----BEGIN OPENSSH PRIVATE KEY-----\nstuff but no end marker\n"
	matches := s.Scan(text)
	for _, m := range matches {
		if m.PatternID == "SSH_PRIVATE_KEY_OPENSSH" {
			t.Fatalf("unterminated marker block should be silently skipped, got %+v", matches)
		}
	}
}

// ---------------------------------------------------------------------------
// Library compile edge cases (mirrors Python YAML-level tests).
// ---------------------------------------------------------------------------

func TestFromYAMLBytes_RejectsNonMapping(t *testing.T) {
	_, err := FromYAMLBytes([]byte("- not_a_mapping\n"))
	if err == nil {
		t.Fatal("expected error for non-mapping YAML")
	}
}

func TestFromYAMLBytes_RejectsMissingPatterns(t *testing.T) {
	_, err := FromYAMLBytes([]byte("version: 1\n"))
	if err == nil {
		t.Fatal("expected error for missing patterns key")
	}
}

func TestFromYAMLBytes_RejectsUnparseable(t *testing.T) {
	// Mismatched indent / tab inside a sequence is rejected.
	_, err := FromYAMLBytes([]byte("patterns:\n\t- id: BAD\n"))
	if err == nil {
		t.Fatal("expected error for unparseable YAML")
	}
}

func TestFromYAMLBytes_RejectsUnknownPairedWith(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: FOO_SECRET\n" +
		"    strategy: regex_with_paired_token\n" +
		"    regex: '([A-Za-z0-9]{40})'\n" +
		"    paired_with: NO_SUCH_PARTNER\n" +
		"    paired_max_byte_distance: 64\n" +
		"    severity: P0\n" +
		"    description: 'test fixture'\n"
	_, err := FromYAMLBytes([]byte(yamlText))
	if err == nil {
		t.Fatal("expected error for unknown paired_with")
	}
	if !errors.Is(err, ErrUnknownPairedPattern) {
		t.Errorf("expected ErrUnknownPairedPattern, got %v", err)
	}
}

func TestFromYAMLBytes_SkipsMarkerBlockWithEmptyMarkers(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: EMPTY_BLOCK\n" +
		"    strategy: marker_block\n" +
		"    begin_marker: ''\n" +
		"    end_marker: 'END'\n" +
		"    severity: P2\n" +
		"    description: 'empty begin marker'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.markerRecords) != 0 || len(s.regexRecords) != 0 {
		t.Fatalf("expected zero records, got regex=%d marker=%d", len(s.regexRecords), len(s.markerRecords))
	}
}

func TestFromYAMLBytes_SkipsEntriesMissingID(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - strategy: regex\n" +
		"    regex: '([A-Z]{4})'\n" +
		"    severity: P2\n" +
		"    description: 'no id field'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.regexRecords) != 0 || len(s.markerRecords) != 0 {
		t.Fatalf("expected zero records when id is missing, got regex=%d marker=%d",
			len(s.regexRecords), len(s.markerRecords))
	}
}

func TestFromYAMLBytes_DropsMarkerBlockMissingEndMarker(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: NO_END\n" +
		"    strategy: marker_block\n" +
		"    begin_marker: 'BEGIN'\n" +
		"    severity: P2\n" +
		"    description: 'no end marker'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.markerRecords) != 0 {
		t.Fatalf("expected zero marker records, got %d", len(s.markerRecords))
	}
}

func TestFromYAMLBytes_DropsRegexRowWithEmptyBody(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: EMPTY_BODY\n" +
		"    strategy: regex\n" +
		"    regex: ''\n" +
		"    severity: P2\n" +
		"    description: 'empty regex'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.regexRecords) != 0 {
		t.Fatalf("expected zero regex records, got %d", len(s.regexRecords))
	}
}

func TestFromYAMLBytes_SurfacesBadRegexWithPatternID(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: BAD_REGEX\n" +
		"    strategy: regex\n" +
		"    regex: '([unterminated'\n" +
		"    severity: P2\n" +
		"    description: 'malformed body'\n"
	_, err := FromYAMLBytes([]byte(yamlText))
	if err == nil {
		t.Fatal("expected error for malformed regex")
	}
	if !strings.Contains(err.Error(), "BAD_REGEX") {
		t.Errorf("error should mention pattern id, got %v", err)
	}
}

func TestFromYAMLBytes_PartnerBadRegex(t *testing.T) {
	// Partner regex is malformed but is referenced by paired_with.
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: BAD_PARTNER\n" +
		"    strategy: regex\n" +
		"    regex: '([unterminated'\n" +
		"    severity: P0\n" +
		"    description: 'partner with bad body'\n" +
		"  - id: CHILD\n" +
		"    strategy: regex_with_paired_token\n" +
		"    regex: '(SECRET[0-9]{4})'\n" +
		"    paired_with: BAD_PARTNER\n" +
		"    paired_max_byte_distance: 8\n" +
		"    severity: P0\n" +
		"    description: 'child paired with bad partner'\n"
	_, err := FromYAMLBytes([]byte(yamlText))
	if err == nil {
		t.Fatal("expected error from malformed partner regex")
	}
}

// ---------------------------------------------------------------------------
// Shannon entropy + paired-token gate.
// ---------------------------------------------------------------------------

func TestShannonEntropyZeroEmpty(t *testing.T) {
	if got := ShannonEntropy(nil); got != 0.0 {
		t.Errorf("nil input: expected 0.0, got %v", got)
	}
	if got := ShannonEntropy([]byte{}); got != 0.0 {
		t.Errorf("empty slice: expected 0.0, got %v", got)
	}
}

func TestShannonEntropyZeroConstant(t *testing.T) {
	if got := ShannonEntropy([]byte("aaaaaaaaaaaaaaaa")); got != 0.0 {
		t.Errorf("constant string: expected 0.0, got %v", got)
	}
}

func TestShannonEntropyNonZeroMixed(t *testing.T) {
	// Two distinct symbols at 50/50 -> 1.0 bits.
	got := ShannonEntropy([]byte("abababab"))
	if got <= 0.9 || got >= 1.1 {
		t.Errorf("mixed 50/50 input: expected ~1.0, got %v", got)
	}
}

func TestPairedConditionByteDistance(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: PARTNER\n" +
		"    strategy: regex\n" +
		"    regex: '(KEY[0-9]{4})'\n" +
		"    severity: P0\n" +
		"    description: 'partner'\n" +
		"  - id: CHILD\n" +
		"    strategy: regex_with_paired_token\n" +
		"    regex: '(SECRET[0-9]{4})'\n" +
		"    paired_with: PARTNER\n" +
		"    paired_max_byte_distance: 8\n" +
		"    severity: P0\n" +
		"    description: 'child paired with partner'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	// Distant partner -> gate fails -> no CHILD match.
	farText := "SECRET0001" + strings.Repeat(" ", 90) + "KEY9999"
	farMatches := s.Scan(farText)
	for _, m := range farMatches {
		if m.PatternID == "CHILD" {
			t.Fatalf("expected no CHILD match with far partner, got %+v", farMatches)
		}
	}

	// Close partner -> gate accepts.
	closeText := "    KEY9999SECRET0001"
	closeMatches := s.Scan(closeText)
	var childHit bool
	for _, m := range closeMatches {
		if m.PatternID == "CHILD" {
			childHit = true
		}
	}
	if !childHit {
		t.Fatalf("expected CHILD match with close partner, got %+v", closeMatches)
	}
}

func TestPairedConditionLabelWindow(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: LABEL_PARTNER\n" +
		"    strategy: regex\n" +
		"    regex: '(NEVER_FIRES)'\n" +
		"    severity: P0\n" +
		"    description: 'partner regex that does not occur'\n" +
		"  - id: LABEL_CHILD\n" +
		"    strategy: regex_with_paired_token\n" +
		"    regex: '(SECRET[0-9]{4})'\n" +
		"    paired_with: LABEL_PARTNER\n" +
		"    paired_max_byte_distance: 4\n" +
		"    label_required: ['my_secret']\n" +
		"    label_byte_window: 16\n" +
		"    severity: P1\n" +
		"    description: 'label fallback'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	// Label appears inside the byte window -> gate accepts.
	text := "my_secret=SECRET0001"
	matches := s.Scan(text)
	var hit bool
	for _, m := range matches {
		if m.PatternID == "LABEL_CHILD" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected LABEL_CHILD hit when label is in window, got %+v", matches)
	}

	// Label far away -> gate rejects.
	farText := strings.Repeat("z", 200) + "SECRET0001"
	farMatches := s.Scan(farText)
	for _, m := range farMatches {
		if m.PatternID == "LABEL_CHILD" {
			t.Fatalf("label outside window should not fire, got %+v", farMatches)
		}
	}
}

func TestScanMarkerBlockWithTinyBlockCap(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: TINY_BLOCK\n" +
		"    strategy: marker_block\n" +
		"    begin_marker: 'BEGIN_TOKEN'\n" +
		"    end_marker: 'END_TOKEN'\n" +
		"    max_block_bytes: 5\n" +
		"    severity: P2\n" +
		"    description: 'cap smaller than begin marker'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	if len(s.markerRecords) != 1 {
		t.Fatalf("expected 1 marker record, got %d", len(s.markerRecords))
	}
	// Begin marker is 11 chars; cap is 5. The defensive branch
	// advances past the begin marker without emitting a match.
	out := s.Scan("BEGIN_TOKEN..end..END_TOKEN")
	if len(out) != 0 {
		t.Fatalf("expected no match with tiny cap, got %+v", out)
	}
}

func TestScanRegexNoCaptureGroupSkipped(t *testing.T) {
	// A regex body without a capture group is treated as an authoring
	// bug and silently skipped. Matches the Python behaviour.
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: NO_CAPTURE\n" +
		"    strategy: regex\n" +
		"    regex: 'HELLO_WORLD'\n" +
		"    severity: P2\n" +
		"    description: 'no capture group'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	out := s.Scan("HELLO_WORLD")
	if len(out) != 0 {
		t.Fatalf("expected no match for no-capture body, got %+v", out)
	}
}

func TestFromYAMLBytes_DefaultsEmptyStrategyToRegex(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: NO_STRATEGY\n" +
		"    regex: '(HELLO[0-9]{4})'\n" +
		"    severity: P2\n" +
		"    description: 'strategy omitted'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	if len(s.regexRecords) != 1 {
		t.Fatalf("expected 1 regex record, got %d", len(s.regexRecords))
	}
	out := s.Scan("HELLO1234")
	if len(out) != 1 || out[0].PatternID != "NO_STRATEGY" {
		t.Fatalf("expected NO_STRATEGY match, got %+v", out)
	}
}

func TestFromYAMLBytes_DefaultsEmptySeverityToP2(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: NO_SEVERITY\n" +
		"    strategy: regex\n" +
		"    regex: '(WIDGET[0-9]{4})'\n" +
		"    description: 'severity omitted'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	out := s.Scan("WIDGET0001")
	if len(out) != 1 || out[0].Severity != "P2" {
		t.Fatalf("expected severity P2 default, got %+v", out)
	}
}

func TestFromYAMLBytes_PartnerRegexCompilesFailsThroughMarkerBlockPartner(t *testing.T) {
	// Partner pattern is a marker_block (so the main loop skips
	// regex compile), but it carries a malformed `regex:` value
	// that lands in idToBody. When the child paired_with rebuilds
	// the partner regex, the second compile fails -- exercising the
	// "partner of X: bad regex" branch of FromYAMLBytes.
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: BAD_PARTNER_MB\n" +
		"    strategy: marker_block\n" +
		"    begin_marker: 'BEGIN_X'\n" +
		"    end_marker: 'END_X'\n" +
		"    regex: '([unterminated'\n" +
		"    severity: P0\n" +
		"    description: 'marker_block partner with bad regex stash'\n" +
		"  - id: CHILD_PR\n" +
		"    strategy: regex_with_paired_token\n" +
		"    regex: '(SECRET[0-9]{4})'\n" +
		"    paired_with: BAD_PARTNER_MB\n" +
		"    paired_max_byte_distance: 8\n" +
		"    severity: P0\n" +
		"    description: 'child paired with marker_block partner stash'\n"
	_, err := FromYAMLBytes([]byte(yamlText))
	if err == nil {
		t.Fatal("expected error from malformed partner regex stash")
	}
	if !strings.Contains(err.Error(), "BAD_PARTNER_MB") {
		t.Errorf("error should mention partner id, got %v", err)
	}
}

func TestScanMinLengthGateFiltersShortMatches(t *testing.T) {
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: LONG_TOKEN\n" +
		"    strategy: regex_with_entropy\n" +
		"    regex: '([A-Za-z0-9]+)'\n" +
		"    min_length: 32\n" +
		"    entropy_min: 0.0\n" +
		"    severity: P2\n" +
		"    description: 'min_length only'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	// 5-char body -- below min_length 32 -- should be filtered.
	out := s.Scan("short")
	if len(out) != 0 {
		t.Fatalf("expected min_length gate to filter, got %+v", out)
	}
}

func TestScanCaptureGroupDidNotParticipate(t *testing.T) {
	// `(?:foo|bar(rest))` -- when "foo" matches, group 1 ("rest")
	// did not participate; FindAllStringSubmatchIndex reports
	// m[2]=-1 for that group. The scanner must skip silently.
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: OPTIONAL_GROUP\n" +
		"    strategy: regex\n" +
		"    regex: '(?:foo|bar(rest))'\n" +
		"    severity: P2\n" +
		"    description: 'group 1 may not participate'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	out := s.Scan("foo")
	if len(out) != 0 {
		t.Fatalf("expected non-participating group to be skipped, got %+v", out)
	}
	// Sanity: when bar matches, group 1 fires and the match is kept.
	out2 := s.Scan("barrest")
	if len(out2) != 1 {
		t.Fatalf("expected one match for participating group, got %+v", out2)
	}
}

func TestPairedConditionPartnerOptionalGroupSkipped(t *testing.T) {
	// Partner regex with optional capture group: when "ZZZ" matches
	// the partner alternation but group 1 did not participate, the
	// gate skips that partner instance and falls through to the
	// label fallback (which we leave unset so the gate returns
	// false).
	yamlText := "" +
		"version: 1\n" +
		"patterns:\n" +
		"  - id: OPTIONAL_PARTNER\n" +
		"    strategy: regex\n" +
		"    regex: '(?:ZZZ|YY(real))'\n" +
		"    severity: P0\n" +
		"    description: 'partner with optional group'\n" +
		"  - id: OPTIONAL_CHILD\n" +
		"    strategy: regex_with_paired_token\n" +
		"    regex: '(SECRET[0-9]{4})'\n" +
		"    paired_with: OPTIONAL_PARTNER\n" +
		"    paired_max_byte_distance: 8\n" +
		"    severity: P0\n" +
		"    description: 'child gated on optional partner group'\n"
	s, err := FromYAMLBytes([]byte(yamlText))
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	// "ZZZ" present, group 1 did not participate -> gate fails.
	// SECRET0001 should not fire.
	out := s.Scan("ZZZ SECRET0001")
	for _, m := range out {
		if m.PatternID == "OPTIONAL_CHILD" {
			t.Fatalf("expected gate to reject non-participating partner group, got %+v", out)
		}
	}
}

func TestScanIsPureAndRepeatable(t *testing.T) {
	s := loadDefault(t)
	text := "GITHUB_TOKEN=ghp_EXAMPLEnotrealnotrealnotrealnotrealN"
	first := s.Scan(text)
	second := s.Scan(text)
	if len(first) != len(second) {
		t.Fatalf("scan not deterministic: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("scan diff at %d: %+v vs %+v", i, first[i], second[i])
		}
	}
}
