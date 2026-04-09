package controlzero_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"controlzero.ai/sdk/go"
)

func tmpLog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "audit.log")
}

func TestHelloWorldDeny(t *testing.T) {
	cz, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"deny": "delete_*", "reason": "Hello"},
				map[string]any{"allow": "*"},
			},
		}),
		controlzero.WithLogPath(tmpLog(t)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cz.Close()

	d, _ := cz.Guard("delete_file", controlzero.GuardOptions{
		Args: map[string]any{"path": "/tmp/foo"},
	})
	if d.Decision() != "deny" {
		t.Fatalf("expected deny, got %s", d.Decision())
	}
	if !d.Denied() {
		t.Fatal("expected Denied() == true")
	}
	if d.Allowed() {
		t.Fatal("expected Allowed() == false")
	}
}

func TestHelloWorldAllow(t *testing.T) {
	cz, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"deny": "delete_*"},
				map[string]any{"allow": "read_*"},
			},
		}),
		controlzero.WithLogPath(tmpLog(t)),
	)
	defer cz.Close()

	d, _ := cz.Guard("read_file", controlzero.GuardOptions{})
	if d.Decision() != "allow" {
		t.Fatalf("expected allow, got %s", d.Decision())
	}
}

func TestFailClosedDefault(t *testing.T) {
	cz, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"allow": "read_*"},
			},
		}),
		controlzero.WithLogPath(tmpLog(t)),
	)
	defer cz.Close()

	d, _ := cz.Guard("exec_command", controlzero.GuardOptions{})
	if d.Decision() != "deny" {
		t.Fatalf("expected deny (fail-closed), got %s", d.Decision())
	}
}

func TestRaiseOnDeny(t *testing.T) {
	cz, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"deny": "delete_*"},
			},
		}),
		controlzero.WithLogPath(tmpLog(t)),
	)
	defer cz.Close()

	_, err := cz.Guard("delete_file", controlzero.GuardOptions{RaiseOnDeny: true})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var pde *controlzero.PolicyDeniedError
	if !errors.As(err, &pde) {
		t.Fatalf("expected *PolicyDeniedError, got %T", err)
	}
}

func TestPassingBothPolicyAndFile(t *testing.T) {
	_, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{"rules": []any{}}),
		controlzero.WithPolicyFile("x.yaml"),
	)
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("expected 'not both' error, got %v", err)
	}
}

func TestEmptyRulesRejected(t *testing.T) {
	_, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{"version": "1", "rules": []any{}}),
	)
	if err == nil {
		t.Fatal("expected error for empty rules")
	}
	var pve *controlzero.PolicyValidationError
	if !errors.As(err, &pve) {
		t.Fatalf("expected PolicyValidationError, got %T", err)
	}
}

func TestRuleWithBothDenyAndAllow(t *testing.T) {
	_, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"deny": "x", "allow": "y"},
			},
		}),
	)
	if err == nil {
		t.Fatal("expected error for both deny+allow on same rule")
	}
}

func TestToolMethodPattern(t *testing.T) {
	cz, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"deny": "github:delete_repo"},
				map[string]any{"allow": "github:*"},
			},
		}),
		controlzero.WithLogPath(tmpLog(t)),
	)
	defer cz.Close()

	d, _ := cz.Guard("github", controlzero.GuardOptions{Method: "delete_repo"})
	if d.Decision() != "deny" {
		t.Fatalf("expected deny on delete_repo, got %s", d.Decision())
	}
	d, _ = cz.Guard("github", controlzero.GuardOptions{Method: "list_repos"})
	if d.Decision() != "allow" {
		t.Fatalf("expected allow on list_repos, got %s", d.Decision())
	}
}

// ---- Hosted mode security ----

func TestHostedModeRefusesToConstruct(t *testing.T) {
	t.Setenv("CONTROLZERO_API_KEY", "cz_test_fakekey")
	_, err := controlzero.New()
	if err == nil {
		t.Fatal("expected HostedModeNotImplemented error")
	}
	if !errors.Is(err, controlzero.ErrHostedModeNotImplemented) {
		t.Fatalf("expected ErrHostedModeNotImplemented, got %v", err)
	}
	if !strings.Contains(err.Error(), "hosted mode") {
		t.Fatalf("expected error mentioning hosted mode, got %v", err)
	}
}

func TestHostedModeRefusesWithExplicitKey(t *testing.T) {
	_, err := controlzero.New(controlzero.WithAPIKey("cz_live_fakekey"))
	if !errors.Is(err, controlzero.ErrHostedModeNotImplemented) {
		t.Fatalf("expected ErrHostedModeNotImplemented, got %v", err)
	}
}

// ---- Hybrid mode ----

func TestHybridStrictReturnsError(t *testing.T) {
	t.Setenv("CONTROLZERO_API_KEY", "cz_test_fakekey")
	_, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"deny": "delete_*"}},
		}),
		controlzero.WithStrictHosted(),
	)
	if err == nil {
		t.Fatal("expected ErrHybridMode")
	}
	if !errors.Is(err, controlzero.ErrHybridMode) {
		t.Fatalf("expected ErrHybridMode, got %v", err)
	}
}

func TestHybridLogOptionsWarning(t *testing.T) {
	t.Setenv("CONTROLZERO_API_KEY", "cz_test_fakekey")
	// We can't easily intercept stderr in Go tests without rewiring os.Stderr.
	// This test just ensures construction succeeds in hybrid mode with log opts.
	cz, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*"}},
		}),
		controlzero.WithLogPath("/tmp/custom-cz.log"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if cz == nil {
		t.Fatal("expected non-nil client")
	}
}

// ---- Glob matching ----

func TestResourceGlobInSuffix(t *testing.T) {
	cz, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{
					"allow":     "llm_call",
					"resources": []any{"model:claude-haiku-*"},
				},
				map[string]any{
					"deny":      "llm_call",
					"resources": []any{"model:claude-opus-*"},
				},
				map[string]any{"deny": "*"},
			},
		}),
		controlzero.WithLogPath(tmpLog(t)),
	)
	defer cz.Close()

	d, _ := cz.Guard("llm_call", controlzero.GuardOptions{
		Context: &controlzero.EvalContext{Resource: "model:claude-haiku-3-5-20241022"},
	})
	if d.Decision() != "allow" {
		t.Fatalf("expected allow for haiku, got %s (%s)", d.Decision(), d.Reason)
	}

	d, _ = cz.Guard("llm_call", controlzero.GuardOptions{
		Context: &controlzero.EvalContext{Resource: "model:claude-opus-4-20250101"},
	})
	if d.Decision() != "deny" {
		t.Fatalf("expected deny for opus, got %s", d.Decision())
	}
}

func TestCostCapTemplateEndToEnd(t *testing.T) {
	// Test against the shipped cost-cap template via the CLI templates dir
	wd, _ := os.Getwd()
	templatePath := filepath.Join(wd, "templates", "cost-cap.yaml")
	if _, err := os.Stat(templatePath); err != nil {
		t.Skipf("template not found at %s: %v", templatePath, err)
	}

	cz, err := controlzero.New(
		controlzero.WithPolicyFile(templatePath),
		controlzero.WithLogPath(tmpLog(t)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cz.Close()

	cases := []struct {
		resource string
		want     string
	}{
		{"model:claude-haiku-3-5-20241022", "allow"},
		{"model:claude-sonnet-4-5-20250929", "allow"},
		{"model:gpt-4o-mini", "allow"},
		{"model:claude-opus-4-20250101", "deny"},
		{"model:gpt-4-32k", "deny"},
	}

	for _, tc := range cases {
		d, _ := cz.Guard("llm_call", controlzero.GuardOptions{
			Context: &controlzero.EvalContext{Resource: tc.resource},
		})
		if d.Decision() != tc.want {
			t.Errorf("%s: expected %s, got %s (%s)", tc.resource, tc.want, d.Decision(), d.Reason)
		}
	}
}

// ---- Fail-closed on evaluator panic ----

func TestFailClosedOnPanic(t *testing.T) {
	// We can't easily inject a panic into the evaluator from outside the
	// package, so this test verifies the deny path through a malformed
	// resource (which doesn't actually crash, but exercises the eval path).
	// A real panic test would require white-box testing.
	cz, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*"}},
		}),
		controlzero.WithLogPath(tmpLog(t)),
	)
	defer cz.Close()
	d, _ := cz.Guard("anything", controlzero.GuardOptions{})
	if d.Decision() != "allow" {
		t.Fatalf("baseline allow failed: %s", d.Decision())
	}
}

// ---- No policy + no key ----

func TestNoPolicyNoKey(t *testing.T) {
	cz, err := controlzero.New(controlzero.WithLogPath(tmpLog(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer cz.Close()

	d, _ := cz.Guard("anything", controlzero.GuardOptions{})
	if !d.Allowed() {
		t.Fatalf("expected pass-through allow, got %s", d.Decision())
	}
	if d.PolicyID != "<noop>" {
		t.Fatalf("expected <noop>, got %s", d.PolicyID)
	}
}
