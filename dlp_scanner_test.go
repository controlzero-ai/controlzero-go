package controlzero

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// US SSN detection
// ---------------------------------------------------------------------------

func TestScanDetectsUSSSN(t *testing.T) {
	scanner := NewDLPScanner()
	matches := scanner.Scan("My SSN is 123-45-6789 and nothing else.")
	found := filterByRuleID(matches, "builtin-us-ssn")
	if len(found) == 0 {
		t.Fatal("expected US SSN match, got none")
	}
	if found[0].MatchedText != "123-45-6789" {
		t.Fatalf("expected matched text '123-45-6789', got %q", found[0].MatchedText)
	}
	if found[0].Category != "pii" {
		t.Fatalf("expected category 'pii', got %q", found[0].Category)
	}
}

func TestScanDoesNotMatchInvalidSSN(t *testing.T) {
	scanner := NewDLPScanner()
	matches := scanner.Scan("Not an SSN: 123-456-789")
	found := filterByRuleID(matches, "builtin-us-ssn")
	if len(found) != 0 {
		t.Fatalf("expected no US SSN match for invalid format, got %d", len(found))
	}
}

// ---------------------------------------------------------------------------
// Credit card detection
// ---------------------------------------------------------------------------

func TestScanDetectsVisaCreditCard(t *testing.T) {
	scanner := NewDLPScanner()
	matches := scanner.Scan("Card: 4111-1111-1111-1111")
	found := filterByRuleID(matches, "builtin-credit-card")
	if len(found) == 0 {
		t.Fatal("expected credit card match, got none")
	}
	if !strings.Contains(found[0].MatchedText, "4111") {
		t.Fatalf("expected match to contain '4111', got %q", found[0].MatchedText)
	}
	if found[0].Category != "financial" {
		t.Fatalf("expected category 'financial', got %q", found[0].Category)
	}
}

func TestScanDetectsMastercardCreditCard(t *testing.T) {
	scanner := NewDLPScanner()
	matches := scanner.Scan("Card: 5200 1234 5678 9012")
	found := filterByRuleID(matches, "builtin-credit-card")
	if len(found) == 0 {
		t.Fatal("expected Mastercard match, got none")
	}
}

func TestScanDetectsAmexCreditCard(t *testing.T) {
	scanner := NewDLPScanner()
	// Amex in the 4-4-4-3 format the regex expects.
	matches := scanner.Scan("Card: 3782-8224-6310-005")
	found := filterByRuleID(matches, "builtin-credit-card")
	if len(found) == 0 {
		t.Fatal("expected Amex match, got none")
	}
}

// ---------------------------------------------------------------------------
// API key detection (AWS, GitHub, OpenAI)
// ---------------------------------------------------------------------------

func TestScanDetectsAWSAccessKey(t *testing.T) {
	scanner := NewDLPScanner()
	matches := scanner.Scan("key=AKIAIOSFODNN7EXAMPLE")
	found := filterByRuleID(matches, "builtin-aws-access-key")
	if len(found) == 0 {
		t.Fatal("expected AWS access key match, got none")
	}
	if found[0].Category != "secret" {
		t.Fatalf("expected category 'secret', got %q", found[0].Category)
	}
}

func TestScanDetectsGitHubPAT(t *testing.T) {
	scanner := NewDLPScanner()
	token := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12"
	matches := scanner.Scan("token=" + token)
	found := filterByRuleID(matches, "builtin-github-pat")
	if len(found) == 0 {
		t.Fatal("expected GitHub PAT match, got none")
	}
}

func TestScanDetectsOpenAIKey(t *testing.T) {
	scanner := NewDLPScanner()
	key := "sk-proj-abcdefghijklmnopqrstuvwxyz"
	matches := scanner.Scan("apikey=" + key)
	found := filterByRuleID(matches, "builtin-openai-key")
	if len(found) == 0 {
		t.Fatal("expected OpenAI key match, got none")
	}
}

// ---------------------------------------------------------------------------
// Korean RRN detection
// ---------------------------------------------------------------------------

func TestScanDetectsKoreanRRN(t *testing.T) {
	scanner := NewDLPScanner()
	matches := scanner.Scan("RRN: 880101-1234567")
	found := filterByRuleID(matches, "builtin-kr-rrn")
	if len(found) == 0 {
		t.Fatal("expected Korean RRN match, got none")
	}
	if found[0].MatchedText != "880101-1234567" {
		t.Fatalf("expected matched text '880101-1234567', got %q", found[0].MatchedText)
	}
	if found[0].Category != "pii" {
		t.Fatalf("expected category 'pii', got %q", found[0].Category)
	}
}

func TestScanRejectsInvalidKoreanRRN(t *testing.T) {
	scanner := NewDLPScanner()
	// Gender digit must be 1-4
	matches := scanner.Scan("RRN: 880101-5234567")
	found := filterByRuleID(matches, "builtin-kr-rrn")
	if len(found) != 0 {
		t.Fatalf("expected no Korean RRN match for gender digit 5, got %d", len(found))
	}
}

// ---------------------------------------------------------------------------
// Secret hashing: secrets are hashed, not stored plaintext
// ---------------------------------------------------------------------------

func TestSecretMatchesAreHashed(t *testing.T) {
	scanner := NewDLPScanner()
	secret := "AKIAIOSFODNN7EXAMPLE"
	matches := scanner.Scan("key=" + secret)
	found := filterByRuleID(matches, "builtin-aws-access-key")
	if len(found) == 0 {
		t.Fatal("expected AWS access key match, got none")
	}

	// The matched text must be a SHA-256 hex digest, not the raw secret.
	if found[0].MatchedText == secret {
		t.Fatal("secret matched text must be hashed, not plaintext")
	}

	expectedHash := sha256.Sum256([]byte(secret))
	expectedHex := hex.EncodeToString(expectedHash[:])
	if found[0].MatchedText != expectedHex {
		t.Fatalf("expected SHA-256 hash %q, got %q", expectedHex, found[0].MatchedText)
	}
}

func TestNonSecretMatchesArePlaintext(t *testing.T) {
	scanner := NewDLPScanner()
	ssn := "123-45-6789"
	matches := scanner.Scan("SSN: " + ssn)
	found := filterByRuleID(matches, "builtin-us-ssn")
	if len(found) == 0 {
		t.Fatal("expected US SSN match")
	}
	if found[0].MatchedText != ssn {
		t.Fatalf("expected plaintext SSN %q, got %q", ssn, found[0].MatchedText)
	}
}

// ---------------------------------------------------------------------------
// Blocking vs detect-only matches
// ---------------------------------------------------------------------------

func TestHasBlockingMatchWithDetectOnly(t *testing.T) {
	scanner := NewDLPScanner()
	matches := scanner.Scan("SSN: 123-45-6789")
	if HasBlockingMatch(matches) {
		t.Fatal("built-in rules are detect-only, HasBlockingMatch should be false")
	}
}

func TestHasBlockingMatchWithBlockRule(t *testing.T) {
	scanner := NewDLPScannerNoBuiltins()
	scanner.AddRules([]map[string]interface{}{
		{
			"id":       "custom-block-ssn",
			"name":     "Block SSN",
			"pattern":  `\b\d{3}-\d{2}-\d{4}\b`,
			"category": "pii",
			"action":   "block",
		},
	})
	matches := scanner.Scan("SSN: 123-45-6789")
	if !HasBlockingMatch(matches) {
		t.Fatal("expected HasBlockingMatch=true for block rule")
	}
}

func TestHasBlockingMatchEmptySlice(t *testing.T) {
	if HasBlockingMatch(nil) {
		t.Fatal("HasBlockingMatch(nil) should return false")
	}
	if HasBlockingMatch([]DLPMatch{}) {
		t.Fatal("HasBlockingMatch(empty) should return false")
	}
}

// ---------------------------------------------------------------------------
// Custom rules
// ---------------------------------------------------------------------------

func TestAddCustomRules(t *testing.T) {
	scanner := NewDLPScannerNoBuiltins()
	scanner.AddRules([]map[string]interface{}{
		{
			"id":       "custom-internal-id",
			"name":     "Internal Employee ID",
			"pattern":  `\bEMP-\d{6}\b`,
			"category": "pii",
			"action":   "block",
			"region":   "global",
		},
	})

	if scanner.RuleCount() != 1 {
		t.Fatalf("expected 1 rule, got %d", scanner.RuleCount())
	}

	matches := scanner.Scan("Employee: EMP-123456")
	if len(matches) == 0 {
		t.Fatal("expected match for custom rule")
	}
	if matches[0].RuleID != "custom-internal-id" {
		t.Fatalf("expected rule ID 'custom-internal-id', got %q", matches[0].RuleID)
	}
	if matches[0].Action != "block" {
		t.Fatalf("expected action 'block', got %q", matches[0].Action)
	}
}

func TestAddRulesSkipsInvalidRegex(t *testing.T) {
	scanner := NewDLPScannerNoBuiltins()
	scanner.AddRules([]map[string]interface{}{
		{
			"id":      "bad-regex",
			"pattern": `[invalid`,
		},
		{
			"id":      "good-rule",
			"pattern": `\bOK\b`,
		},
	})
	if scanner.RuleCount() != 1 {
		t.Fatalf("expected 1 rule (bad regex should be skipped), got %d", scanner.RuleCount())
	}
}

func TestAddRulesSkipsMissingPattern(t *testing.T) {
	scanner := NewDLPScannerNoBuiltins()
	scanner.AddRules([]map[string]interface{}{
		{"id": "no-pattern"},
	})
	if scanner.RuleCount() != 0 {
		t.Fatalf("expected 0 rules (missing pattern), got %d", scanner.RuleCount())
	}
}

func TestCustomRulesAddedOnTopOfBuiltins(t *testing.T) {
	builtinCount := NewDLPScanner().RuleCount()
	scanner := NewDLPScannerWithRules([]map[string]interface{}{
		{
			"id":      "custom-one",
			"pattern": `\bFOO\b`,
		},
	})
	if scanner.RuleCount() != builtinCount+1 {
		t.Fatalf("expected %d rules (builtins+1), got %d", builtinCount+1, scanner.RuleCount())
	}
}

// ---------------------------------------------------------------------------
// GetFindingsForAudit
// ---------------------------------------------------------------------------

func TestGetFindingsForAuditExcludesSecretText(t *testing.T) {
	matches := []DLPMatch{
		{
			RuleID:      "builtin-aws-access-key",
			Category:    "secret",
			Action:      "detect",
			MatchedText: "somehash",
			Count:       1,
		},
		{
			RuleID:      "builtin-us-ssn",
			Category:    "pii",
			Action:      "detect",
			MatchedText: "123-45-6789",
			Count:       1,
		},
	}

	findings := GetFindingsForAudit(matches)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Secret finding should NOT have matched_text.
	if _, has := findings[0]["matched_text"]; has {
		t.Fatal("secret finding should not include matched_text")
	}

	// PII finding should have matched_text.
	if v, has := findings[1]["matched_text"]; !has {
		t.Fatal("PII finding should include matched_text")
	} else if v != "123-45-6789" {
		t.Fatalf("expected matched_text '123-45-6789', got %q", v)
	}
}

// ---------------------------------------------------------------------------
// ExtractTextFromArgs
// ---------------------------------------------------------------------------

func TestExtractTextFromArgs(t *testing.T) {
	args := map[string]interface{}{
		"command": "echo hello",
		"nested": map[string]interface{}{
			"path": "/etc/passwd",
		},
		"list": []interface{}{"a", "b"},
	}
	text := ExtractTextFromArgs(args)
	if !strings.Contains(text, "echo hello") {
		t.Fatal("expected extracted text to contain 'echo hello'")
	}
	if !strings.Contains(text, "/etc/passwd") {
		t.Fatal("expected extracted text to contain '/etc/passwd'")
	}
	if !strings.Contains(text, "a") || !strings.Contains(text, "b") {
		t.Fatal("expected extracted text to contain list items")
	}
}

func TestExtractTextFromArgsNil(t *testing.T) {
	text := ExtractTextFromArgs(nil)
	if text != "" {
		t.Fatalf("expected empty string for nil args, got %q", text)
	}
}

// ---------------------------------------------------------------------------
// Scan on empty text
// ---------------------------------------------------------------------------

func TestScanEmptyText(t *testing.T) {
	scanner := NewDLPScanner()
	matches := scanner.Scan("")
	if matches != nil {
		t.Fatalf("expected nil for empty text, got %d matches", len(matches))
	}
}

func TestScanNoRules(t *testing.T) {
	scanner := NewDLPScannerNoBuiltins()
	matches := scanner.Scan("SSN: 123-45-6789")
	if matches != nil {
		t.Fatalf("expected nil with no rules, got %d matches", len(matches))
	}
}

// ---------------------------------------------------------------------------
// LoadDLPRulesFromPolicy
// ---------------------------------------------------------------------------

func TestLoadDLPRulesFromPolicy(t *testing.T) {
	policy := map[string]interface{}{
		"dlp_rules": []interface{}{
			map[string]interface{}{
				"id":       "custom-ssn-block",
				"pattern":  `\b\d{3}-\d{2}-\d{4}\b`,
				"category": "pii",
				"action":   "block",
			},
		},
	}

	rules := LoadDLPRulesFromPolicy(policy)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestLoadDLPRulesFromPolicyMissing(t *testing.T) {
	rules := LoadDLPRulesFromPolicy(map[string]interface{}{})
	if rules != nil {
		t.Fatalf("expected nil for missing dlp_rules, got %d", len(rules))
	}
}

func TestLoadDLPRulesFromPolicyScopeFilter(t *testing.T) {
	policy := map[string]interface{}{
		"dlp_rules": []interface{}{
			map[string]interface{}{
				"id":      "browser-only",
				"pattern": `\btest\b`,
				"scopes":  []interface{}{"browser"},
			},
			map[string]interface{}{
				"id":      "sdk-scoped",
				"pattern": `\btest2\b`,
				"scopes":  []interface{}{"sdk", "browser"},
			},
		},
	}
	rules := LoadDLPRulesFromPolicy(policy)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (browser-only filtered out), got %d", len(rules))
	}
	if rules[0]["id"] != "sdk-scoped" {
		t.Fatalf("expected sdk-scoped rule, got %q", rules[0]["id"])
	}
}

// ---------------------------------------------------------------------------
// Multiple matches in same text
// ---------------------------------------------------------------------------

func TestMultipleMatchesSameRule(t *testing.T) {
	scanner := NewDLPScannerNoBuiltins()
	scanner.AddRules([]map[string]interface{}{
		{
			"id":       "test-ssn",
			"pattern":  `\b\d{3}-\d{2}-\d{4}\b`,
			"category": "pii",
			"action":   "detect",
		},
	})
	matches := scanner.Scan("SSN1: 123-45-6789 and SSN2: 987-65-4321")
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
}

// ---------------------------------------------------------------------------
// Connection string detection
// ---------------------------------------------------------------------------

func TestScanDetectsPostgresURL(t *testing.T) {
	scanner := NewDLPScanner()
	matches := scanner.Scan("db=postgresql://user:pass@host:5432/db")
	found := filterByRuleID(matches, "builtin-postgres-url")
	if len(found) == 0 {
		t.Fatal("expected PostgreSQL connection string match, got none")
	}
	if found[0].Category != "secret" {
		t.Fatalf("expected category 'secret', got %q", found[0].Category)
	}
}

func TestScanDetectsSSHPrivateKey(t *testing.T) {
	scanner := NewDLPScanner()
	matches := scanner.Scan("-----BEGIN RSA PRIVATE KEY-----")
	found := filterByRuleID(matches, "builtin-ssh-private-key")
	if len(found) == 0 {
		t.Fatal("expected SSH private key match, got none")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// filterByRuleID returns only matches with the given rule ID.
func filterByRuleID(matches []DLPMatch, ruleID string) []DLPMatch {
	var out []DLPMatch
	for _, m := range matches {
		if m.RuleID == ruleID {
			out = append(out, m)
		}
	}
	return out
}
