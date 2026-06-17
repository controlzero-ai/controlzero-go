// Tests for the non-breaking upgrade nudge (maybeWarnRecommendedSDK).
//
// The nudge is a SOFT signal: when a hosted bundle's metadata carries
// recommended_sdk_version above the running Version, the SDK prints ONE
// non-fatal stderr line per process pointing at `controlzero update`. It
// never changes enforcement and is a no-op when the field is absent
// (back-compat). The arithmetic is covered by
// internal/bundle/recommended_sdk_version_test.go; this file pins the
// stderr contract and the once-per-process throttle.

package controlzero

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

// captureStderrNudge replaces os.Stderr for the duration of fn and returns
// what was written. Mirrors captureStderrHITL.
func captureStderrNudge(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	return <-done
}

// resetNudgeOnce clears the package-level throttle so each test starts from
// a clean "not yet warned" state.
func resetNudgeOnce() { recommendedSDKNudgeOnce = sync.Once{} }

func TestNudge_WarnsWhenBehind(t *testing.T) {
	resetNudgeOnce()
	payload := map[string]any{
		"metadata": map[string]any{"recommended_sdk_version": "9999.0.0"},
	}
	out := captureStderrNudge(t, func() { maybeWarnRecommendedSDK(payload) })
	if !strings.Contains(out, "is behind the recommended 9999.0.0") {
		t.Errorf("expected behind-recommendation warning; got %q", out)
	}
	if !strings.Contains(out, "controlzero update") {
		t.Errorf("expected nudge to point at 'controlzero update'; got %q", out)
	}
	if !strings.Contains(out, Version) {
		t.Errorf("expected the running version in the warning; got %q", out)
	}
}

func TestNudge_SilentWhenAbsent(t *testing.T) {
	resetNudgeOnce()
	// No metadata block at all -- the back-compat case.
	payload := map[string]any{"policies": []any{}}
	out := captureStderrNudge(t, func() { maybeWarnRecommendedSDK(payload) })
	if out != "" {
		t.Errorf("absent recommended_sdk_version must be silent; got %q", out)
	}
}

func TestNudge_SilentWhenFieldMissing(t *testing.T) {
	resetNudgeOnce()
	payload := map[string]any{
		"metadata": map[string]any{"tags": map[string]any{}},
	}
	out := captureStderrNudge(t, func() { maybeWarnRecommendedSDK(payload) })
	if out != "" {
		t.Errorf("missing recommended_sdk_version field must be silent; got %q", out)
	}
}

func TestNudge_SilentWhenCurrent(t *testing.T) {
	resetNudgeOnce()
	// Recommend exactly the version we run -> no nudge.
	payload := map[string]any{
		"metadata": map[string]any{"recommended_sdk_version": Version},
	}
	out := captureStderrNudge(t, func() { maybeWarnRecommendedSDK(payload) })
	if out != "" {
		t.Errorf("at-or-above recommendation must be silent; got %q", out)
	}
}

func TestNudge_OncePerProcess(t *testing.T) {
	resetNudgeOnce()
	payload := map[string]any{
		"metadata": map[string]any{"recommended_sdk_version": "9999.0.0"},
	}
	out := captureStderrNudge(t, func() {
		maybeWarnRecommendedSDK(payload)
		maybeWarnRecommendedSDK(payload)
		maybeWarnRecommendedSDK(payload)
	})
	// Exactly one nudge line despite three calls.
	if n := strings.Count(out, "controlzero update"); n != 1 {
		t.Errorf("expected exactly 1 nudge per process; got %d in %q", n, out)
	}
}
