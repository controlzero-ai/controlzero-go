// I/O capture CONTRACT wire fields (spine S0, T77 / epic #1390).
//
// S0 ship-dark guarantees, mirroring the Python + Node SDK tests:
//   - SHIP DARK: a plain decision entry produces a wire map with NONE of the
//     new io_* keys -- the dark default matches pre-S0 behaviour.
//   - The raw cleartext payloads (input_payload / output_payload) are NEVER
//     forwarded yet, even when an entry carries them -- the S4 producer has not
//     landed and backend persistence is gated off until S1 DLP + S2 land.
//   - The lightweight provenance/completeness metadata IS forwarded.
//
// fail-if-reverted: re-adding input_payload / output_payload to the forwarded
// keys in toWireFormat makes the payload-suppression assertions below fail.

package controlzero

import (
	"encoding/json"
	"testing"
)

var ioContractKeys = []string{
	"input_payload",
	"output_payload",
	"io_source_type",
	"io_capture_surface",
	"io_producer_version",
	"io_invocation_id",
	"io_capture_completeness",
	"io_truncation_reason",
	"io_capture_failed_reason",
	"io_input_captured",
	"io_output_captured",
	"io_redaction_applied",
}

func TestToWire_IOCaptureDarkDefault_NoKeys(t *testing.T) {
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	wire := sink.toWireFormat(map[string]any{
		"tool":     "Bash",
		"decision": "allow",
	})
	for _, k := range ioContractKeys {
		if _, present := wire[k]; present {
			t.Errorf("dark wire unexpectedly carried %q: %v", k, wire)
		}
	}
	if wire["tool_name"] != "Bash" || wire["decision"] != "allow" {
		t.Errorf("baseline fields regressed: %v", wire)
	}
}

func TestToWire_IOCaptureShipDark_NoPayloads(t *testing.T) {
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	// S0 ship-dark: even with payloads present, they are never forwarded.
	wire := sink.toWireFormat(map[string]any{
		"tool":           "Bash",
		"decision":       "allow",
		"input_payload":  "ls -la /tmp",
		"output_payload": "total 0",
	})
	for _, k := range []string{"input_payload", "output_payload"} {
		if _, present := wire[k]; present {
			t.Errorf("payload leaked onto wire in S0 (%q): %v", k, wire)
		}
	}
}

func TestToWire_IOCapturePopulated_ForwardsMetadataOnly(t *testing.T) {
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	wire := sink.toWireFormat(map[string]any{
		"tool":                    "Bash",
		"decision":                "allow",
		"input_payload":           "ls -la /tmp",
		"output_payload":          "total 0",
		"io_source_type":          "agent_hook",
		"io_capture_surface":      "claude_code",
		"io_producer_version":     "1.0.0",
		"io_invocation_id":        "inv-1",
		"io_capture_completeness": "full",
		"io_input_captured":       true,
		"io_output_captured":      true,
		"io_redaction_applied":    true,
	})
	// S0 ship-dark: the cleartext payloads are NEVER forwarded yet.
	for _, k := range []string{"input_payload", "output_payload"} {
		if _, present := wire[k]; present {
			t.Errorf("payload leaked onto wire in S0 (%q): %v", k, wire)
		}
	}
	// The lightweight metadata IS forwarded.
	checks := map[string]any{
		"io_source_type":          "agent_hook",
		"io_capture_surface":      "claude_code",
		"io_producer_version":     "1.0.0",
		"io_invocation_id":        "inv-1",
		"io_capture_completeness": "full",
		"io_input_captured":       true,
		"io_output_captured":      true,
		"io_redaction_applied":    true,
	}
	for k, want := range checks {
		if wire[k] != want {
			t.Errorf("wire[%q] = %v, want %v", k, wire[k], want)
		}
	}
	// The batch body must still serialize cleanly.
	if _, err := json.Marshal(map[string]any{"entries": []map[string]any{wire}}); err != nil {
		t.Fatalf("batch body did not serialize: %v", err)
	}
}

func TestToWire_IOCaptureFalseBooleansNotEmitted(t *testing.T) {
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	wire := sink.toWireFormat(map[string]any{
		"tool":                 "Bash",
		"decision":             "allow",
		"io_input_captured":    false,
		"io_output_captured":   false,
		"io_redaction_applied": false,
	})
	for _, k := range []string{"io_input_captured", "io_output_captured", "io_redaction_applied"} {
		if _, present := wire[k]; present {
			t.Errorf("a false io_* boolean was emitted (%q): %v", k, wire)
		}
	}
}
