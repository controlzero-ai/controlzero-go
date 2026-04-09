package controlzero_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"controlzero.ai/sdk/go"
)

func TestAuditLogWritesToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	cz, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"deny": "delete_*"},
				map[string]any{"allow": "*"},
			},
		}),
		controlzero.WithLogPath(path),
	)
	cz.Guard("delete_file", controlzero.GuardOptions{Args: map[string]any{"path": "/tmp/foo"}})
	cz.Guard("read_file", controlzero.GuardOptions{Args: map[string]any{"path": "/tmp/bar"}})
	cz.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"delete_file", "read_file", "deny", "allow"} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in audit log, got: %s", want, text)
		}
	}
}

func TestAuditLogJSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	cz, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*"}},
		}),
		controlzero.WithLogPath(path),
	)
	cz.Guard("test_tool", controlzero.GuardOptions{Args: map[string]any{"k": "v"}})
	cz.Close()

	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		t.Errorf("expected JSON format, got: %s", string(data))
	}
}

func TestAuditLogPrettyFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	cz, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*"}},
		}),
		controlzero.WithLogPath(path),
		controlzero.WithLogFormat("pretty"),
	)
	cz.Guard("test_tool", controlzero.GuardOptions{})
	cz.Close()

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), " | ") {
		t.Errorf("expected pretty format with pipe separators, got: %s", string(data))
	}
}

func TestAuditSinkIsolation(t *testing.T) {
	dir := t.TempDir()
	path1 := filepath.Join(dir, "client1.log")
	path2 := filepath.Join(dir, "client2.log")

	cz1, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*"}},
		}),
		controlzero.WithLogPath(path1),
	)
	cz2, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"deny": "*"}},
		}),
		controlzero.WithLogPath(path2),
	)

	cz1.Guard("tool_a", controlzero.GuardOptions{Args: map[string]any{"x": 1}})
	cz2.Guard("tool_b", controlzero.GuardOptions{Args: map[string]any{"y": 2}})

	cz1.Close()
	cz2.Close()

	t1, _ := os.ReadFile(path1)
	t2, _ := os.ReadFile(path2)

	if !strings.Contains(string(t1), "tool_a") || strings.Contains(string(t1), "tool_b") {
		t.Errorf("client1 log should contain only tool_a, got: %s", string(t1))
	}
	if !strings.Contains(string(t2), "tool_b") || strings.Contains(string(t2), "tool_a") {
		t.Errorf("client2 log should contain only tool_b, got: %s", string(t2))
	}
}
