package controlzero

// T86 / GitHub #391 -- Go SDK unknown-action validator.
//
// Pairs with the backend validator at
// apps/control-zero-platform/backend/internal/policy/action_aliases.go.
// Backend BLOCKS publish on unknown actions; Go SDK WARNS at load
// time so customers running local-policy mode see the typo before
// the rule silently never fires.

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestT86_IsKnownAction_Canonical(t *testing.T) {
	cases := []string{
		"database:read",
		"database:write",
		"database:admin",
		"database:exec",
		"database:query",
		"database:DROP",
		"database:delete",
		"Bash:rm",
		"Bash:any-arbitrary-cmd",
		"http:GET",
		"http:WHATEVER",
		"file_read:*",
		"task:spawn",
		"*",
		"*:read",
		"database:*",
	}
	for _, a := range cases {
		if !IsKnownAction(a) {
			t.Errorf("expected %q to be known, got false", a)
		}
	}
}

func TestT86_IsKnownAction_Unknown(t *testing.T) {
	cases := []string{
		"database:queryy",
		"database:made_up",
		"db:read",
		"BashTool:rm",
		"",
	}
	for _, a := range cases {
		if IsKnownAction(a) {
			t.Errorf("expected %q to be unknown, got true", a)
		}
	}
}

func TestT86_SuggestForAction_PrefersCanonical(t *testing.T) {
	got := SuggestForAction("database:reaq")
	if len(got) == 0 {
		t.Fatalf("expected suggestions, got none")
	}
	if got[0] != "database:read" {
		t.Errorf("expected first suggestion to be canonical database:read, got %q (full %v)", got[0], got)
	}
}

func TestT86_SuggestForAction_TypoReturnsLegacyMatch(t *testing.T) {
	got := SuggestForAction("database:queryy")
	hasQuery := false
	for _, s := range got {
		if strings.Contains(s, "database:query") {
			hasQuery = true
		}
	}
	if !hasQuery {
		t.Errorf("expected database:query in suggestions for database:queryy, got %v", got)
	}
}

func TestT86_ValidateActions_DedupesAndReturnsSuggestions(t *testing.T) {
	unknown, suggestions := ValidateActionsT86([]string{
		"database:queryy", "database:queryy", "database:read",
	})
	if len(unknown) != 1 || unknown[0] != "database:queryy" {
		t.Fatalf("expected [database:queryy], got %v", unknown)
	}
	if len(suggestions["database:queryy"]) == 0 {
		t.Errorf("expected non-empty suggestions, got %v", suggestions)
	}
}

func TestT86_LoadPolicyFull_WarnsOnUnknownAction(t *testing.T) {
	// Capture stderr log output.
	var buf bytes.Buffer
	originalOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(originalOutput)

	policy := map[string]any{
		"version": "1",
		"rules": []any{
			map[string]any{"id": "good", "allow": "database:read"},
			map[string]any{"id": "typo", "deny": "database:queryy"},
		},
	}
	parsed, err := LoadPolicyFull(policy)
	if err != nil {
		t.Fatalf("expected load to succeed (warn-not-block), got %v", err)
	}
	if len(parsed.Rules) != 2 {
		t.Errorf("expected 2 rules parsed, got %d", len(parsed.Rules))
	}
	out := buf.String()
	if !strings.Contains(out, "queryy") || !strings.Contains(out, "Did you mean") {
		t.Errorf("expected warn log to mention typo and 'Did you mean', got: %s", out)
	}
	if !strings.Contains(out, "database:query") {
		t.Errorf("expected suggestion to include database:query, got: %s", out)
	}
}

func TestT86_LoadPolicyFull_NoWarnOnCanonical(t *testing.T) {
	var buf bytes.Buffer
	originalOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(originalOutput)

	policy := map[string]any{
		"version": "1",
		"rules": []any{
			map[string]any{"id": "good", "allow": "database:read"},
			map[string]any{"id": "good2", "deny": "Bash:rm"},
		},
	}
	if _, err := LoadPolicyFull(policy); err != nil {
		t.Fatalf("expected load to succeed, got %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "Did you mean") {
		t.Errorf("expected no validator warning for clean canonical policy, got: %s", out)
	}
}
