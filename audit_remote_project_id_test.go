// PR2 (TIER-0 audit attribution): project_id is forwarded UNCONDITIONALLY on
// the audit wire (top-level field), not gated inside the event_kind
// credential-leak branch. Go mirror of the Python + Node wire tests -- the
// wire field name (project_id) and behavior MUST match across SDKs so the
// backend reader honors one shape.
//
// fail-if-reverted: move project_id back under the event_kind branch and a
// plain decision row loses attribution -> the present-when-absent and
// present-when-set assertions below fail.

package controlzero

import (
	"encoding/json"
	"testing"
)

func newProjectIDTestSink() *BearerAuditSink {
	return NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
}

func TestToWire_ProjectID_ForwardedWhenPresent(t *testing.T) {
	sink := newProjectIDTestSink()
	wire := sink.toWireFormat(map[string]any{
		"tool":       "Bash",
		"decision":   "deny",
		"project_id": "P",
	})
	if got, _ := wire["project_id"].(string); got != "P" {
		t.Fatalf("project_id = %q, want %q", got, "P")
	}
}

func TestToWire_ProjectID_EmptyWhenAbsent(t *testing.T) {
	sink := newProjectIDTestSink()
	wire := sink.toWireFormat(map[string]any{
		"tool":     "Bash",
		"decision": "allow",
	})
	got, ok := wire["project_id"]
	if !ok {
		t.Fatalf("project_id must always be present on the wire (top-level field)")
	}
	if s, _ := got.(string); s != "" {
		t.Fatalf("absent project_id must ship as empty string, got %q", s)
	}
}

func TestToWire_ProjectID_NotEventKindGated(t *testing.T) {
	sink := newProjectIDTestSink()
	wire := sink.toWireFormat(map[string]any{
		"tool":       "database",
		"decision":   "deny",
		"project_id": "proj-prod",
	})
	if _, ok := wire["event_kind"]; ok {
		t.Fatalf("decision row must not carry event_kind")
	}
	if got, _ := wire["project_id"].(string); got != "proj-prod" {
		t.Fatalf("project_id must forward without event_kind, got %q", got)
	}
}

func TestToWire_ProjectID_BatchSerializes(t *testing.T) {
	sink := newProjectIDTestSink()
	wire := sink.toWireFormat(map[string]any{
		"tool":       "Bash",
		"decision":   "deny",
		"project_id": "P",
	})
	body, err := json.Marshal(map[string]any{"entries": []any{wire}})
	if err != nil {
		t.Fatalf("batch body must serialize: %v", err)
	}
	var parsed struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if got, _ := parsed.Entries[0]["project_id"].(string); got != "P" {
		t.Fatalf("project_id lost in round-trip, got %q", got)
	}
}
