// Phase 1B (#451) / PR #463 H4: Go SDK constant matches the Rust
// workspace version in crates/Cargo.toml.
//
// Mirror of test_engine_version_consistency.py and
// engineVersionConsistency.test.ts. CI runs
// scripts/ci/check-engine-version-drift.sh on every change; this
// unit test is the SDK-local mirror so `go test ./...` on the SDK
// alone still catches drift.
//
// Skips cleanly when Cargo.toml is not visible from the test mount.

package controlzero

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func locateCargoToml(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for dir := wd; ; {
		candidate := filepath.Join(dir, "crates", "Cargo.toml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func readWorkspaceVersion(t *testing.T, cargoToml string) string {
	t.Helper()
	data, err := os.ReadFile(cargoToml)
	if err != nil {
		t.Fatalf("read %s: %v", cargoToml, err)
	}
	versionRE := regexp.MustCompile(`^version\s*=\s*"([^"]+)"`)
	inSection := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[workspace.package]") {
			inSection = true
			continue
		}
		if inSection && strings.HasPrefix(line, "[") {
			return ""
		}
		if inSection {
			if m := versionRE.FindStringSubmatch(line); m != nil {
				return m[1]
			}
		}
	}
	return ""
}

func TestEngineVersion_MatchesCargoToml(t *testing.T) {
	cargo := locateCargoToml(t)
	if cargo == "" {
		t.Skip("crates/Cargo.toml not visible from this test mount")
	}
	canonical := readWorkspaceVersion(t, cargo)
	if canonical == "" {
		t.Fatalf("could not parse workspace.package.version from %s", cargo)
	}
	if PolicyEngineVersion != canonical {
		t.Fatalf(
			"Go SDK PolicyEngineVersion (%q) drifted from Rust workspace version (%q) "+
				"in %s. Fix: bump both literals in the same PR. CI: "+
				"scripts/ci/check-engine-version-drift.sh enforces this on every change.",
			PolicyEngineVersion, canonical, cargo,
		)
	}
}

func TestEngineVersion_SemverShape(t *testing.T) {
	// Cargo.toml-independent shape check that runs in any mount.
	if PolicyEngineVersion == "" {
		t.Fatal("PolicyEngineVersion must not be empty")
	}
	if !regexp.MustCompile(`^\d+\.\d+`).MatchString(PolicyEngineVersion) {
		t.Fatalf("expected semver-shaped engine version, got %q", PolicyEngineVersion)
	}
}
