package controlzero

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTamperStateSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	ts := TamperState{
		Quarantined: true,
		Reason:      "test reason",
		DetectedAt:  "2026-04-12T00:00:00Z",
		Source:      "policy_hmac",
	}
	if err := SaveTamperState(dir, ts); err != nil {
		t.Fatalf("SaveTamperState: %v", err)
	}
	loaded := LoadTamperState(dir)
	if loaded.Quarantined != true {
		t.Errorf("Quarantined = %v, want true", loaded.Quarantined)
	}
	if loaded.Reason != "test reason" {
		t.Errorf("Reason = %q, want %q", loaded.Reason, "test reason")
	}
	if loaded.DetectedAt != "2026-04-12T00:00:00Z" {
		t.Errorf("DetectedAt = %q, want %q", loaded.DetectedAt, "2026-04-12T00:00:00Z")
	}
	if loaded.Source != "policy_hmac" {
		t.Errorf("Source = %q, want %q", loaded.Source, "policy_hmac")
	}
}

func TestIsQuarantinedTrueAfterEnter(t *testing.T) {
	dir := t.TempDir()
	if err := EnterQuarantine(dir, "tamper", "audit_chain"); err != nil {
		t.Fatalf("EnterQuarantine: %v", err)
	}
	if !IsQuarantined(dir) {
		t.Error("IsQuarantined returned false, want true")
	}
}

func TestIsQuarantinedFalseNoFile(t *testing.T) {
	dir := t.TempDir()
	if IsQuarantined(dir) {
		t.Error("IsQuarantined returned true for empty dir, want false")
	}
}

func TestClearQuarantine(t *testing.T) {
	dir := t.TempDir()
	if err := EnterQuarantine(dir, "tamper", "policy_hmac"); err != nil {
		t.Fatalf("EnterQuarantine: %v", err)
	}
	if !IsQuarantined(dir) {
		t.Fatal("expected quarantined before clear")
	}
	ClearQuarantine(dir)
	if IsQuarantined(dir) {
		t.Error("IsQuarantined returned true after clear, want false")
	}
	path := filepath.Join(dir, quarantineFileName)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("quarantine file still exists after clear")
	}
}

func TestLoadTamperStateMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, quarantineFileName)
	if err := os.WriteFile(path, []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ts := LoadTamperState(dir)
	if ts.Quarantined {
		t.Error("expected Quarantined=false for malformed JSON")
	}
}

func TestEnterQuarantineSetsDetectedAt(t *testing.T) {
	dir := t.TempDir()
	if err := EnterQuarantine(dir, "reason", "bundle_signature"); err != nil {
		t.Fatalf("EnterQuarantine: %v", err)
	}
	ts := LoadTamperState(dir)
	if len(ts.DetectedAt) < 10 {
		t.Errorf("DetectedAt too short: %q", ts.DetectedAt)
	}
}

func TestGuardDeniesWhenQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := EnterQuarantine(dir, "tamper", "policy_hmac"); err != nil {
		t.Fatalf("EnterQuarantine: %v", err)
	}

	// Override default state dir
	origEnv := os.Getenv(defaultStateDirEv)
	os.Setenv(defaultStateDirEv, dir)
	defer func() {
		if origEnv != "" {
			os.Setenv(defaultStateDirEv, origEnv)
		} else {
			os.Unsetenv(defaultStateDirEv)
		}
	}()

	c, err := New(WithPolicy(map[string]any{
		"version": "1",
		"rules":   []any{map[string]any{"allow": "*"}},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	decision, _ := c.Guard("anything", GuardOptions{})
	if decision.Effect != "deny" {
		t.Errorf("expected deny, got %q", decision.Effect)
	}
	if decision.Reason == "" {
		t.Error("expected non-empty reason")
	}
	if decision.ReasonCode != ReasonCodeMachineQuarantined {
		t.Errorf("ReasonCode = %q, want %q", decision.ReasonCode, ReasonCodeMachineQuarantined)
	}
}

func TestApplyTamperBehaviorQuarantineEntersState(t *testing.T) {
	dir := t.TempDir()
	entered := ApplyTamperBehavior(dir, PolicySettings{DefaultOnTamper: "quarantine"}, "test", "policy_hmac")
	if !entered {
		t.Error("ApplyTamperBehavior returned false, want true for quarantine")
	}
	if !IsQuarantined(dir) {
		t.Error("state dir not quarantined after ApplyTamperBehavior")
	}
}

func TestApplyTamperBehaviorDenyAllEntersState(t *testing.T) {
	dir := t.TempDir()
	entered := ApplyTamperBehavior(dir, PolicySettings{DefaultOnTamper: "deny-all"}, "test", "policy_hmac")
	if !entered {
		t.Error("ApplyTamperBehavior returned false for deny-all, want true")
	}
	if !IsQuarantined(dir) {
		t.Error("state dir not quarantined after deny-all")
	}
}

func TestApplyTamperBehaviorDenyDoesNotQuarantine(t *testing.T) {
	dir := t.TempDir()
	entered := ApplyTamperBehavior(dir, PolicySettings{DefaultOnTamper: "deny"}, "test", "policy_hmac")
	if entered {
		t.Error("deny must NOT enter quarantine (per-call deny only)")
	}
	if IsQuarantined(dir) {
		t.Error("state dir quarantined for deny, want not")
	}
}

func TestApplyTamperBehaviorWarnIsNoOp(t *testing.T) {
	dir := t.TempDir()
	entered := ApplyTamperBehavior(dir, PolicySettings{DefaultOnTamper: "warn"}, "test", "policy_hmac")
	if entered {
		t.Error("warn must NOT enter quarantine")
	}
	if IsQuarantined(dir) {
		t.Error("state dir quarantined for warn, want not")
	}
}

func TestApplyTamperBehaviorUnknownIsNoOp(t *testing.T) {
	dir := t.TempDir()
	entered := ApplyTamperBehavior(dir, PolicySettings{DefaultOnTamper: "panic"}, "test", "policy_hmac")
	if entered {
		t.Error("unknown behavior must NOT enter quarantine (forward-compat warn)")
	}
}

func TestApplyTamperBehaviorUsesLegacyAlias(t *testing.T) {
	dir := t.TempDir()
	// Only the legacy TamperBehavior field set -> resolves via
	// EffectiveTamperBehavior() to "quarantine".
	entered := ApplyTamperBehavior(dir, PolicySettings{TamperBehavior: "quarantine"}, "test", "policy_hmac")
	if !entered {
		t.Error("legacy tamper_behavior=quarantine must enter quarantine")
	}
}

func TestApplyTamperBehaviorEmptyStateDir(t *testing.T) {
	entered := ApplyTamperBehavior("", PolicySettings{DefaultOnTamper: "quarantine"}, "test", "policy_hmac")
	if entered {
		t.Error("empty stateDir must not crash and must return false")
	}
}

func TestGuardAllowsAfterClear(t *testing.T) {
	dir := t.TempDir()
	if err := EnterQuarantine(dir, "tamper", "policy_hmac"); err != nil {
		t.Fatalf("EnterQuarantine: %v", err)
	}
	ClearQuarantine(dir)

	origEnv := os.Getenv(defaultStateDirEv)
	os.Setenv(defaultStateDirEv, dir)
	defer func() {
		if origEnv != "" {
			os.Setenv(defaultStateDirEv, origEnv)
		} else {
			os.Unsetenv(defaultStateDirEv)
		}
	}()

	resetWarningState()
	c, err := New(WithPolicy(map[string]any{
		"version": "1",
		"rules":   []any{map[string]any{"allow": "*"}},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	decision, _ := c.Guard("anything", GuardOptions{})
	if decision.Effect != "allow" {
		t.Errorf("expected allow after clear, got %q", decision.Effect)
	}
}
