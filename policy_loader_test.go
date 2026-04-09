package controlzero_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"controlzero.ai/sdk/go"
)

func TestLoadYAMLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	content := `
version: "1"
rules:
  - deny: "delete_*"
  - allow: "read_*"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cz, err := controlzero.New(
		controlzero.WithPolicyFile(path),
		controlzero.WithLogPath(filepath.Join(dir, "audit.log")),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cz.Close()

	d, _ := cz.Guard("delete_thing", controlzero.GuardOptions{})
	if d.Decision() != "deny" {
		t.Fatalf("expected deny, got %s", d.Decision())
	}
	d, _ = cz.Guard("read_thing", controlzero.GuardOptions{})
	if d.Decision() != "allow" {
		t.Fatalf("expected allow, got %s", d.Decision())
	}
}

func TestLoadJSONFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	content := `{"version":"1","rules":[{"deny":"delete_*"},{"allow":"read_*"}]}`
	os.WriteFile(path, []byte(content), 0o644)

	cz, _ := controlzero.New(
		controlzero.WithPolicyFile(path),
		controlzero.WithLogPath(filepath.Join(dir, "audit.log")),
	)
	defer cz.Close()

	d, _ := cz.Guard("delete_thing", controlzero.GuardOptions{})
	if d.Decision() != "deny" {
		t.Fatal("expected deny")
	}
}

func TestFileNotFound(t *testing.T) {
	_, err := controlzero.New(
		controlzero.WithPolicyFile("/nonexistent/policy.yaml"),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	var ple *controlzero.PolicyLoadError
	if !errors.As(err, &ple) {
		t.Fatalf("expected *PolicyLoadError, got %T: %v", err, err)
	}
}

func TestYAMLParseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("not: valid: yaml: [unclosed"), 0o644)

	_, err := controlzero.New(controlzero.WithPolicyFile(path))
	var ple *controlzero.PolicyLoadError
	if !errors.As(err, &ple) {
		t.Fatalf("expected *PolicyLoadError, got %T: %v", err, err)
	}
}

func TestJSONParseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{not valid json}"), 0o644)

	_, err := controlzero.New(controlzero.WithPolicyFile(path))
	var ple *controlzero.PolicyLoadError
	if !errors.As(err, &ple) {
		t.Fatalf("expected *PolicyLoadError, got %T: %v", err, err)
	}
}

func TestEmptyYAMLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	os.WriteFile(path, []byte(""), 0o644)

	_, err := controlzero.New(controlzero.WithPolicyFile(path))
	var pve *controlzero.PolicyValidationError
	if !errors.As(err, &pve) {
		t.Fatalf("expected *PolicyValidationError, got %T: %v", err, err)
	}
}

func TestUnsupportedFileFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.txt")
	os.WriteFile(path, []byte("not yaml"), 0o644)

	_, err := controlzero.New(controlzero.WithPolicyFile(path))
	var ple *controlzero.PolicyLoadError
	if !errors.As(err, &ple) {
		t.Fatalf("expected *PolicyLoadError, got %T: %v", err, err)
	}
}
