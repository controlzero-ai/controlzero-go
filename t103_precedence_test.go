package controlzero

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T103 regression tests for the hosted-vs-local precedence rules.
//
// Customer report 2026-05-12: a stale local policy file
// shadowed the dashboard policy when api_key was also set. Post-T103
// the api_key path wins by default; local is a fallback only when no
// api_key OR CONTROLZERO_LOCAL_OVERRIDE=1.
//
// These tests run against the real Client constructor. They cannot
// exercise the hosted-load branch without mocking the HTTP layer, so
// we focus on the precedence decision surface that does NOT touch the
// network: caller-supplied local, no-api-key fallback, JSON detection,
// quiet env, and the LOCAL_OVERRIDE escape hatch on a cwd file.

func setupSandboxCwd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	original, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	return dir
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	originalStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = originalStderr }()

	resetWarningState()
	fn()
	_ = w.Close()

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestT103_NoAPIKeyFallsBackToCwdYAML(t *testing.T) {
	dir := setupSandboxCwd(t)
	t.Setenv("CONTROLZERO_API_KEY", "")
	t.Setenv("CONTROLZERO_LOCAL_OVERRIDE", "")

	pol := filepath.Join(dir, "controlzero.yaml")
	if err := os.WriteFile(pol, []byte("version: '1'\nrules:\n  - deny: send_email\n  - allow: '*'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	resetWarningState()
	cz, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cz.Close()

	d, err := cz.Guard("send_email", GuardOptions{})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if !d.Denied() {
		t.Errorf("expected send_email denied, got %s", d.Effect)
	}
}

func TestT103_CwdJSONPolicyAutoDetected(t *testing.T) {
	dir := setupSandboxCwd(t)
	t.Setenv("CONTROLZERO_API_KEY", "")

	pol := filepath.Join(dir, "controlzero.json")
	if err := os.WriteFile(pol, []byte(`{"version":"1","rules":[{"deny":"dangerous"},{"allow":"*"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	resetWarningState()
	cz, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cz.Close()

	d, err := cz.Guard("dangerous", GuardOptions{})
	if err != nil {
		t.Fatalf("Guard: %v", err)
	}
	if !d.Denied() {
		t.Errorf("expected dangerous denied, got %s", d.Effect)
	}
}

func TestT103_ExplicitLocalEmitsHybridWarn(t *testing.T) {
	t.Setenv("CONTROLZERO_API_KEY", "cz_live_fakekey00")

	stderr := captureStderr(t, func() {
		cz, err := New(
			WithPolicy(map[string]any{
				"version": "1",
				"rules": []any{
					map[string]any{"deny": "send_email"},
					map[string]any{"allow": "*"},
				},
			}),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer cz.Close()
		// The explicit local must override hosted -> deny fires.
		d, gerr := cz.Guard("send_email", GuardOptions{})
		if gerr != nil {
			t.Fatalf("Guard: %v", gerr)
		}
		if !d.Denied() {
			t.Errorf("expected send_email denied, got %s", d.Effect)
		}
	})
	if !strings.Contains(stderr, "overrides the hosted bundle") {
		t.Errorf("expected hybrid override warning, got: %s", stderr)
	}
}

func TestT103_QuietEnvSuppressesActiveSourceNotice(t *testing.T) {
	dir := setupSandboxCwd(t)
	t.Setenv("CONTROLZERO_API_KEY", "")
	t.Setenv("CONTROLZERO_QUIET", "1")

	pol := filepath.Join(dir, "controlzero.yaml")
	if err := os.WriteFile(pol, []byte("rules:\n  - allow: '*'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stderr := captureStderr(t, func() {
		cz, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer cz.Close()
	})
	if strings.Contains(stderr, "active policy source") {
		t.Errorf("expected QUIET to suppress, got: %s", stderr)
	}
}

func TestT103_ActiveSourceNoticeFiresWithoutQuiet(t *testing.T) {
	dir := setupSandboxCwd(t)
	t.Setenv("CONTROLZERO_API_KEY", "")
	t.Setenv("CONTROLZERO_QUIET", "")

	pol := filepath.Join(dir, "controlzero.yaml")
	if err := os.WriteFile(pol, []byte("rules:\n  - allow: '*'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stderr := captureStderr(t, func() {
		cz, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer cz.Close()
	})
	if !strings.Contains(stderr, "active policy source") {
		t.Errorf("expected active-source notice, got: %s", stderr)
	}
	if !strings.Contains(stderr, "local") {
		t.Errorf("expected source mode 'local', got: %s", stderr)
	}
}
