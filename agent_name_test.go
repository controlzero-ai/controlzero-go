package controlzero

import (
	"os"
	"testing"
)

// Coverage for the agentName / CZ_AGENT_NAME / CZ_DEBUG env-var contract.
//
// Resolution order (per docs):
//   WithAgentName option > CZ_AGENT_NAME env > "default-agent"
//
// CZ_DEBUG in {1, true, yes, on} (case-insensitive) sets CONTROLZERO_DEBUG=1
// so other packages in this SDK can pick it up cheaply via os.Getenv.

func newLocalClientT(t *testing.T, opts ...Option) *Client {
	t.Helper()
	all := append([]Option{WithPolicy(map[string]any{"rules": []any{map[string]any{"allow": "*", "reason": "test fixture"}}})}, opts...)
	c, err := New(all...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestAgentName_DefaultWhenUnset(t *testing.T) {
	t.Setenv("CZ_AGENT_NAME", "")
	os.Unsetenv("CZ_AGENT_NAME")
	c := newLocalClientT(t)
	if got := c.AgentName(); got != "default-agent" {
		t.Fatalf("expected default-agent, got %q", got)
	}
}

func TestAgentName_FromEnv(t *testing.T) {
	t.Setenv("CZ_AGENT_NAME", "agent-from-env")
	c := newLocalClientT(t)
	if got := c.AgentName(); got != "agent-from-env" {
		t.Fatalf("expected agent-from-env, got %q", got)
	}
}

func TestAgentName_ExplicitWinsOverEnv(t *testing.T) {
	t.Setenv("CZ_AGENT_NAME", "agent-from-env")
	c := newLocalClientT(t, WithAgentName("explicit-arg"))
	if got := c.AgentName(); got != "explicit-arg" {
		t.Fatalf("expected explicit-arg, got %q", got)
	}
}

func TestCZDebug_UnsetDoesNotEnable(t *testing.T) {
	t.Setenv("CZ_DEBUG", "")
	os.Unsetenv("CZ_DEBUG")
	t.Setenv("CONTROLZERO_DEBUG", "")
	os.Unsetenv("CONTROLZERO_DEBUG")
	_ = newLocalClientT(t)
	if v := os.Getenv("CONTROLZERO_DEBUG"); v != "" {
		t.Fatalf("CONTROLZERO_DEBUG should be unset, got %q", v)
	}
}

func TestCZDebug_TruthyValuesEnable(t *testing.T) {
	for _, v := range []string{"1", "true", "yes", "on", "TRUE", "Yes", "ON"} {
		t.Setenv("CONTROLZERO_DEBUG", "")
		os.Unsetenv("CONTROLZERO_DEBUG")
		t.Setenv("CZ_DEBUG", v)
		_ = newLocalClientT(t)
		if got := os.Getenv("CONTROLZERO_DEBUG"); got != "1" {
			t.Fatalf("CZ_DEBUG=%q should set CONTROLZERO_DEBUG=1, got %q", v, got)
		}
	}
}

func TestCZDebug_GarbageDoesNotEnable(t *testing.T) {
	t.Setenv("CONTROLZERO_DEBUG", "")
	os.Unsetenv("CONTROLZERO_DEBUG")
	t.Setenv("CZ_DEBUG", "no")
	_ = newLocalClientT(t)
	if got := os.Getenv("CONTROLZERO_DEBUG"); got != "" {
		t.Fatalf("CZ_DEBUG=no should not set CONTROLZERO_DEBUG, got %q", got)
	}
}
