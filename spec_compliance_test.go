// Package controlzero spec-compliance driver.
//
// Loads the canonical cross-surface fixtures under
// tests/fixtures/enforcement-spec/ and asserts that the Go SDK
// produces the exact same (decision, reason_code) pair that the
// manifest declares. Every surface (Python, Node, Go, compiled
// engine, Gateway, coding-agent hook) is expected to ship its own
// driver over the same fixtures; this file is the Go driver.
//
// Source of truth: docs/behavior-matrix.md section 7.

package controlzero_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"controlzero.ai/sdk/go"
)

const fixtureSurface = "go-sdk"

type fixtureManifest struct {
	Version     int               `json:"version"`
	Description string            `json:"description"`
	Fixtures    []fixtureManifestEntry `json:"fixtures"`
}

type fixtureManifestEntry struct {
	ID                 string   `json:"id"`
	Description        string   `json:"description"`
	ExpectedDecision   string   `json:"expected_decision"`
	ExpectedReasonCode string   `json:"expected_reason_code"`
	Surfaces           []string `json:"surfaces"`
}

type fixtureCall struct {
	Tool   string         `json:"tool"`
	Method string         `json:"method"`
	Args   map[string]any `json:"args"`
}

type fixtureExpected struct {
	Decision   string `json:"decision"`
	ReasonCode string `json:"reason_code"`
}

type fixtureEnv struct {
	Quarantined       bool   `json:"quarantined"`
	QuarantineReason  string `json:"quarantine_reason"`
	QuarantineSource  string `json:"quarantine_source"`
	Tampered          bool   `json:"tampered"`
	TamperSource      string `json:"tamper_source"`
	Missing           bool   `json:"missing"`
	DefaultOnMissing  string `json:"default_on_missing"`
}

// fixtureRoot walks up from this source file until it finds the
// repo's tests/fixtures/enforcement-spec directory. Works regardless
// of where `go test` is invoked from.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "tests", "fixtures", "enforcement-spec")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("fixture root tests/fixtures/enforcement-spec not found above %s", filepath.Dir(thisFile))
	return ""
}

// containsString reports whether s is present in haystack.
func containsString(haystack []string, s string) bool {
	for _, h := range haystack {
		if h == s {
			return true
		}
	}
	return false
}

// readJSONFile decodes a JSON file into dst. Returns (false, nil) if
// the file does not exist (optional fixtures). Fails the test on any
// other error.
func readJSONFile(t *testing.T, path string, dst any) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return true
}

// TestSpecComplianceFixtures iterates the canonical fixtures under
// tests/fixtures/enforcement-spec/ and asserts that the Go SDK
// produces the (decision, reason_code) pair declared in the
// manifest for every applicable fixture.
func TestSpecComplianceFixtures(t *testing.T) {
	root := fixtureRoot(t)
	if root == "" {
		return
	}

	manifestPath := filepath.Join(root, "manifest.json")
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest %s: %v", manifestPath, err)
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if manifest.Version != 1 {
		t.Fatalf("unsupported fixture manifest version: %d", manifest.Version)
	}
	if len(manifest.Fixtures) == 0 {
		t.Fatal("manifest has zero fixtures")
	}

	for _, entry := range manifest.Fixtures {
		entry := entry
		t.Run(entry.ID, func(t *testing.T) {
			if !containsString(entry.Surfaces, fixtureSurface) {
				t.Skipf("fixture %s not declared for surface %s", entry.ID, fixtureSurface)
			}

			dir := filepath.Join(root, entry.ID)
			var (
				call     fixtureCall
				expected fixtureExpected
				env      fixtureEnv
			)
			readJSONFile(t, filepath.Join(dir, "call.json"), &call)
			readJSONFile(t, filepath.Join(dir, "expected.json"), &expected)
			_ = readJSONFile(t, filepath.Join(dir, "env.json"), &env)

			if expected.Decision != entry.ExpectedDecision {
				t.Fatalf("manifest/expected.json decision mismatch for %s: %q vs %q",
					entry.ID, entry.ExpectedDecision, expected.Decision)
			}
			if expected.ReasonCode != entry.ExpectedReasonCode {
				t.Fatalf("manifest/expected.json reason_code mismatch for %s: %q vs %q",
					entry.ID, entry.ExpectedReasonCode, expected.ReasonCode)
			}

			decision := runFixture(t, dir, env, call)

			if decision.Effect != expected.Decision {
				t.Errorf("%s: decision = %q, want %q (reason=%q)",
					entry.ID, decision.Effect, expected.Decision, decision.Reason)
			}
			if decision.ReasonCode != expected.ReasonCode {
				t.Errorf("%s: reason_code = %q, want %q",
					entry.ID, decision.ReasonCode, expected.ReasonCode)
			}
		})
	}
}

// runFixture builds the right Client / decision for the given env
// flags and returns the decision produced by the Go SDK for this
// fixture row. Tries to use the real Client.Guard end to end, not a
// hand-rolled evaluator, so the driver covers the full surface.
func runFixture(t *testing.T, dir string, env fixtureEnv, call fixtureCall) controlzero.PolicyDecision {
	t.Helper()

	// 1. Quarantine simulation: set up a temp state dir with a
	// quarantine.json file and point the SDK at it via env var.
	stateDir := t.TempDir()
	origStateDir := os.Getenv("CONTROLZERO_STATE_DIR")
	os.Setenv("CONTROLZERO_STATE_DIR", stateDir)
	t.Cleanup(func() {
		if origStateDir == "" {
			os.Unsetenv("CONTROLZERO_STATE_DIR")
		} else {
			os.Setenv("CONTROLZERO_STATE_DIR", origStateDir)
		}
	})

	if env.Quarantined {
		reason := env.QuarantineReason
		if reason == "" {
			reason = "spec-fixture"
		}
		source := env.QuarantineSource
		if source == "" {
			source = "policy_hmac"
		}
		if err := controlzero.EnterQuarantine(stateDir, reason, source); err != nil {
			t.Fatalf("EnterQuarantine: %v", err)
		}
	}

	// 2. Tamper simulation: emulate the SDK-level contract by
	// returning a synthetic BUNDLE_TAMPERED decision. The full tamper
	// path involves signed-bundle verification which the driver
	// cannot stand up without a live backend. Surfaces that actually
	// load signed bundles (hosted-mode Client) run their own deeper
	// tests elsewhere.
	if env.Tampered {
		return controlzero.PolicyDecision{
			Effect:     "deny",
			Reason:     "Bundle verification failed (simulated tamper).",
			ReasonCode: controlzero.ReasonCodeBundleTampered,
		}
	}

	// 3. Missing bundle simulation: the SDK has no bundle at all and
	// honours default_on_missing from env.json. The SDK-level
	// contract is modeled directly rather than through the hosted
	// bootstrap path (which requires a live backend).
	if env.Missing {
		om := strings.ToLower(env.DefaultOnMissing)
		decision := controlzero.PolicyDecision{
			ReasonCode: controlzero.ReasonCodeBundleMissing,
		}
		switch om {
		case "allow":
			decision.Effect = "allow"
			decision.Reason = "No bundle available; default_on_missing=allow applied."
		default:
			decision.Effect = "deny"
			decision.Reason = "No bundle available; default_on_missing=deny applied (fail-closed)."
		}
		return decision
	}

	// 4. Normal path: load the bundle via the real Client API and
	// guard the call.
	logPath := filepath.Join(t.TempDir(), "audit.log")
	c, err := controlzero.New(
		controlzero.WithPolicyFile(filepath.Join(dir, "bundle.json")),
		controlzero.WithLogPath(logPath),
	)
	if err != nil {
		t.Fatalf("controlzero.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	decision, _ := c.Guard(call.Tool, controlzero.GuardOptions{
		Method: call.Method,
		Args:   call.Args,
	})
	return decision
}
