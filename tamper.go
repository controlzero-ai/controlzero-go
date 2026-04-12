package controlzero

// Quarantine state for mandatory tamper enforcement.
//
// When tamper_behavior is 'deny-all' or 'quarantine' and tampering is
// detected, the machine enters quarantine. All tool calls are denied
// until recovery (re-enrollment or fresh policy pull).
//
// On-disk format matches the Python and Node SDKs exactly (quarantine.json).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const quarantineFileName = "quarantine.json"

// TamperState is the persisted quarantine state for mandatory tamper
// enforcement. Fields match the Python/Node SDKs exactly.
type TamperState struct {
	Quarantined bool   `json:"quarantined"`
	Reason      string `json:"reason"`
	DetectedAt  string `json:"detected_at"`
	Source      string `json:"source"` // "policy_hmac" | "audit_chain" | "bundle_signature"
}

// LoadTamperState reads the quarantine state from the given directory.
// Returns a zero-value TamperState if the file does not exist or is
// malformed (never returns an error).
func LoadTamperState(stateDir string) TamperState {
	path := filepath.Join(stateDir, quarantineFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return TamperState{}
	}
	var ts TamperState
	if err := json.Unmarshal(data, &ts); err != nil {
		return TamperState{}
	}
	return ts
}

// SaveTamperState writes the quarantine state to the given directory.
// Uses tmp + rename for atomicity. Permissions are set to 0600.
func SaveTamperState(stateDir string, ts TamperState) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(stateDir, quarantineFileName)
	tmp := path + ".tmp"
	data, err := json.Marshal(ts)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, path)
}

// ClearQuarantine removes the quarantine file. Best-effort, never errors.
func ClearQuarantine(stateDir string) {
	path := filepath.Join(stateDir, quarantineFileName)
	_ = os.Remove(path)
}

// IsQuarantined checks whether the quarantine state is set without
// loading the full struct. Returns false if the file does not exist
// or is malformed.
func IsQuarantined(stateDir string) bool {
	ts := LoadTamperState(stateDir)
	return ts.Quarantined
}

// EnterQuarantine creates a quarantine state file with the given
// reason and source.
func EnterQuarantine(stateDir, reason, source string) error {
	ts := TamperState{
		Quarantined: true,
		Reason:      reason,
		DetectedAt:  time.Now().UTC().Format(time.RFC3339),
		Source:      source,
	}
	return SaveTamperState(stateDir, ts)
}
