// I/O capture CONTRACT wire fields (spine S4, T77 / epic #1390 / #1392).
//
// S4 producer contract (reverses the S0 ship-dark payload suppression),
// mirroring the Python + Node SDK tests:
//   - SHIP DARK DEFAULT: a plain decision entry produces a wire map with NONE
//     of the new io_* keys -- byte-identical to pre-S0.
//   - The raw payloads (input_payload / output_payload) ARE forwarded now when
//     an entry carries them (the S4 agent_hook producer captures them). The
//     backend master gate is the persistence backstop -- a forwarded payload is
//     dropped server-side until S7+S8.
//   - Forwarding is present-only: no producer -> no payload on the wire.
//   - The lightweight provenance/completeness metadata is forwarded when set.
//
// fail-if-reverted: re-suppressing input_payload / output_payload (removing them
// from the forwarded keys in toWireFormat) breaks
// TestToWire_IOCapturePayloadsForwarded.

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

func TestToWire_IOCapturePresentOnly_NoPayloadWhenAbsent(t *testing.T) {
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	// Metadata present but no payload -> no payload forwarded (present-only).
	wire := sink.toWireFormat(map[string]any{
		"tool":                    "Bash",
		"decision":                "allow",
		"io_source_type":          "agent_hook",
		"io_capture_surface":      "claude_code",
		"io_capture_completeness": "none_unsupported",
	})
	for _, k := range []string{"input_payload", "output_payload"} {
		if _, present := wire[k]; present {
			t.Errorf("payload forwarded with no producer payload (%q): %v", k, wire)
		}
	}
	if wire["io_source_type"] != "agent_hook" {
		t.Errorf("metadata regressed: %v", wire)
	}
}

func TestToWire_IOCapturePayloadsForwarded(t *testing.T) {
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	// S4: the producer attached payloads -> the builder forwards them.
	// fail-if-reverted: re-suppressing the payloads breaks this.
	wire := sink.toWireFormat(map[string]any{
		"tool":           "Bash",
		"decision":       "allow",
		"input_payload":  "ls -la /tmp",
		"output_payload": "total 0",
	})
	if wire["input_payload"] != "ls -la /tmp" {
		t.Errorf("input_payload not forwarded: %v", wire)
	}
	if wire["output_payload"] != "total 0" {
		t.Errorf("output_payload not forwarded: %v", wire)
	}
}

func TestToWire_IOCapturePopulated_ForwardsPayloadsAndMetadata(t *testing.T) {
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
		"io_producer_version":     "agent_hook@1.0.0",
		"io_invocation_id":        "inv-1",
		"io_capture_completeness": "full",
		"io_input_captured":       true,
		"io_output_captured":      true,
		"io_redaction_applied":    true,
	})
	checks := map[string]any{
		"input_payload":           "ls -la /tmp",
		"output_payload":          "total 0",
		"io_source_type":          "agent_hook",
		"io_capture_surface":      "claude_code",
		"io_producer_version":     "agent_hook@1.0.0",
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
