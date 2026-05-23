// Smoke tests for the public hooks package (epic #666, PR-4).
//
// The package is a thin re-export over internal/credentialhook +
// internal/credentialscanner. These tests assert the public surface
// stays callable from outside the internal/ tree, validate that the
// embedded YAML loads through BuildHandler, and exercise the
// OnToolOutput convenience wrapper.
package hooks_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"controlzero.ai/sdk/go/hooks"
)

var testHMACKey = []byte("controlzero-test-key-do-not-use-in-prod")

type recordingSink struct {
	rows []hooks.AuditRow
}

func (s *recordingSink) Log(entry map[string]any) {
	s.rows = append(s.rows, entry)
}

func TestBuildHandler_ReturnsUsableHandler(t *testing.T) {
	sink := &recordingSink{}
	h, err := hooks.BuildHandler(hooks.BuildHandlerOptions{
		Sink:      sink,
		ProjectID: "proj_hooks_test",
		Action:    hooks.ActionRedact,
		HMACKey:   testHMACKey,
	})
	if err != nil {
		t.Fatalf("BuildHandler returned error: %v", err)
	}
	if h == nil {
		t.Fatal("BuildHandler returned nil handler")
	}
}

func TestBuildHandler_ValidatesAction(t *testing.T) {
	_, err := hooks.BuildHandler(hooks.BuildHandlerOptions{
		ProjectID: "proj",
		Action:    hooks.Action(99),
		HMACKey:   testHMACKey,
	})
	if err == nil {
		t.Fatal("expected validation error for invalid action")
	}
}

func TestBuildHandler_ValidatesHMACKey(t *testing.T) {
	_, err := hooks.BuildHandler(hooks.BuildHandlerOptions{
		ProjectID: "proj",
		Action:    hooks.ActionWarn,
		HMACKey:   []byte("short"),
	})
	if err == nil {
		t.Fatal("expected validation error for short HMAC key")
	}
}

func TestOnToolOutput_RedactsAWSKey(t *testing.T) {
	sink := &recordingSink{}
	h, err := hooks.BuildHandler(hooks.BuildHandlerOptions{
		Sink:      sink,
		ProjectID: "proj_e2e",
		Action:    hooks.ActionRedact,
		HMACKey:   testHMACKey,
	})
	if err != nil {
		t.Fatalf("BuildHandler: %v", err)
	}

	body := "AKIAEXAMPLEKEY00000Z"
	text := "AWS_ACCESS_KEY_ID=" + body
	out, err := hooks.OnToolOutput(context.Background(), h, hooks.HandleInput{
		Source:     hooks.SourceToolOutput,
		Text:       text,
		ToolName:   "Bash",
		ToolCallID: "call_001",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("OnToolOutput: %v", err)
	}
	if strings.Contains(out.Text, body) {
		t.Fatal("plaintext should have been redacted")
	}
	if !strings.Contains(out.Text, "cz:credleak:") {
		t.Fatal("expected cz:credleak: redaction sentinel")
	}
	if len(sink.rows) == 0 {
		t.Fatal("sink should have received at least one row")
	}
}

func TestOnToolOutput_BlockReturnsSentinelError(t *testing.T) {
	sink := &recordingSink{}
	h, err := hooks.BuildHandler(hooks.BuildHandlerOptions{
		Sink:      sink,
		ProjectID: "proj_block",
		Action:    hooks.ActionBlock,
		HMACKey:   testHMACKey,
	})
	if err != nil {
		t.Fatalf("BuildHandler: %v", err)
	}
	_, err = hooks.OnToolOutput(context.Background(), h, hooks.HandleInput{
		Source:     hooks.SourceToolOutput,
		Text:       "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY00000Z",
		ToolName:   "Bash",
		ToolCallID: "call_block",
		AgentName:  "claude-code",
	})
	if err == nil {
		t.Fatal("expected block to return error")
	}
	if !errors.Is(err, hooks.ErrCredentialLeakBlocked) {
		t.Errorf("expected ErrCredentialLeakBlocked, got %v", err)
	}
}

func TestOnToolOutput_InnocuousInputReturnsUnchanged(t *testing.T) {
	h, err := hooks.BuildHandler(hooks.BuildHandlerOptions{
		ProjectID: "proj_innocuous",
		Action:    hooks.ActionRedact,
		HMACKey:   testHMACKey,
	})
	if err != nil {
		t.Fatalf("BuildHandler: %v", err)
	}
	text := "just a regular log line, nothing to see"
	out, err := hooks.OnToolOutput(context.Background(), h, hooks.HandleInput{
		Source:     hooks.SourceToolOutput,
		Text:       text,
		ToolName:   "Bash",
		ToolCallID: "call_clean",
		AgentName:  "claude-code",
	})
	if err != nil {
		t.Fatalf("OnToolOutput: %v", err)
	}
	if out.Text != text {
		t.Fatalf("expected unchanged text, got %q", out.Text)
	}
	if len(out.AuditRows) != 0 {
		t.Fatalf("expected zero rows, got %d", len(out.AuditRows))
	}
}
