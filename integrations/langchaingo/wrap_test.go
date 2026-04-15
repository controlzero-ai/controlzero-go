package langchaingo

import (
	"context"
	"errors"
	"testing"

	controlzero "controlzero.ai/sdk/go"
	"github.com/tmc/langchaingo/tools"
)

// fakeTool is a minimal tools.Tool implementation for tests.
type fakeTool struct {
	name        string
	description string
	callCount   int
	callErr     error
	callOut     string
}

func (f *fakeTool) Name() string        { return f.name }
func (f *fakeTool) Description() string { return f.description }
func (f *fakeTool) Call(ctx context.Context, input string) (string, error) {
	f.callCount++
	return f.callOut, f.callErr
}

// Compile-time check.
var _ tools.Tool = (*fakeTool)(nil)

func allowClient(t *testing.T, toolName string) *controlzero.Client {
	t.Helper()
	c, err := controlzero.New(controlzero.WithPolicy(map[string]any{
		"rules": []any{
			map[string]any{"allow": toolName + ":call", "reason": "fixture"},
		},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func denyClient(t *testing.T, toolName string) *controlzero.Client {
	t.Helper()
	c, err := controlzero.New(controlzero.WithPolicy(map[string]any{
		"rules": []any{
			map[string]any{"deny": toolName + ":call", "reason": "fixture"},
		},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestWrapTool_AllowDelegates(t *testing.T) {
	cz := allowClient(t, "web_search")
	inner := &fakeTool{name: "web_search", callOut: "results"}

	wrapped := WrapTool(inner, cz)
	out, err := wrapped.Call(context.Background(), "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "results" {
		t.Fatalf("expected results, got %q", out)
	}
	if inner.callCount != 1 {
		t.Fatalf("expected inner called once, got %d", inner.callCount)
	}
}

func TestWrapTool_DenyShortCircuits(t *testing.T) {
	cz := denyClient(t, "web_search")
	inner := &fakeTool{name: "web_search", callOut: "should-not-run"}

	wrapped := WrapTool(inner, cz)
	_, err := wrapped.Call(context.Background(), "bad")
	if err == nil {
		t.Fatalf("expected denial error, got nil")
	}
	var denied *controlzero.PolicyDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *PolicyDeniedError, got %T: %v", err, err)
	}
	if inner.callCount != 0 {
		t.Fatalf("expected inner never called on deny, got %d", inner.callCount)
	}
}

func TestWrapTool_NamePassThrough(t *testing.T) {
	cz := allowClient(t, "x")
	inner := &fakeTool{name: "x", description: "y"}
	wrapped := WrapTool(inner, cz)
	if got := wrapped.Name(); got != "x" {
		t.Fatalf("expected x, got %q", got)
	}
	if got := wrapped.Description(); got != "y" {
		t.Fatalf("expected y, got %q", got)
	}
}

func TestWrapTool_InnerErrorPropagates(t *testing.T) {
	cz := allowClient(t, "w")
	inner := &fakeTool{name: "w", callErr: errors.New("upstream 500")}

	wrapped := WrapTool(inner, cz)
	_, err := wrapped.Call(context.Background(), "x")
	if err == nil {
		t.Fatalf("expected upstream error, got nil")
	}
	if err.Error() != "upstream 500" {
		t.Fatalf("expected upstream 500, got %v", err)
	}
}

func TestWrapTools_Batch(t *testing.T) {
	c, err := controlzero.New(controlzero.WithPolicy(map[string]any{
		"rules": []any{
			map[string]any{"allow": "a:call", "reason": "fixture"},
			map[string]any{"allow": "b:call", "reason": "fixture"},
		},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	a := &fakeTool{name: "a", callOut: "A"}
	b := &fakeTool{name: "b", callOut: "B"}
	wrapped := WrapTools([]tools.Tool{a, b}, c)

	if len(wrapped) != 2 {
		t.Fatalf("expected 2 wrapped tools, got %d", len(wrapped))
	}
	if out, err := wrapped[0].Call(context.Background(), "x"); err != nil || out != "A" {
		t.Fatalf("tool[0]: out=%q err=%v", out, err)
	}
	if out, err := wrapped[1].Call(context.Background(), "x"); err != nil || out != "B" {
		t.Fatalf("tool[1]: out=%q err=%v", out, err)
	}
}
