// Contract tests for the controlzero_sdk_version wire field
// (#495 / v1, 2026-05-14).
//
// Pins the wire-format invariants the backend ingest depends on:
//   - field is present on every audit POST entry
//   - shape is "go@<version>" (lang-prefixed, distinct from client_version)
//   - capped at 64 chars to protect the LowCardinality column
//   - Version constant is non-empty (drift guard against accidental wipe)

package controlzero

import (
	"strings"
	"testing"
)

func TestSDKVersion_NonEmpty(t *testing.T) {
	if Version == "" {
		t.Fatal("Version constant is empty -- drift / accidental wipe")
	}
}

func TestSDKVersionWire_LangPrefixed(t *testing.T) {
	if !strings.HasPrefix(sdkVersionWire, "go@") {
		t.Errorf("sdkVersionWire = %q; want prefix \"go@\"", sdkVersionWire)
	}
}

func TestSDKVersionWire_NonEmpty(t *testing.T) {
	if sdkVersionWire == "" || sdkVersionWire == "go@" {
		t.Fatalf("sdkVersionWire is blank: %q -- audit pipeline would carry empty strings to prod", sdkVersionWire)
	}
}

func TestSDKVersionWire_LengthCap(t *testing.T) {
	// Backend MaxControlzeroSDKVersionLen is 64 chars
	// (LowCardinality dict-encoded). The construction in version.go
	// returns "" rather than truncating when the full string would
	// overflow, so any length <= 64 is fine.
	if len(sdkVersionWire) > 64 {
		t.Errorf("sdkVersionWire length %d > 64; backend will reject", len(sdkVersionWire))
	}
}

func TestSDKVersionWire_MatchesVersionConstant(t *testing.T) {
	expected := "go@" + Version
	if len(expected) > 64 {
		// If the version itself is over the cap, the wire format
		// is intentionally empty.
		if sdkVersionWire != "" {
			t.Errorf("sdkVersionWire should be empty for over-cap version, got %q", sdkVersionWire)
		}
		return
	}
	if sdkVersionWire != expected {
		t.Errorf("sdkVersionWire = %q; want %q", sdkVersionWire, expected)
	}
}

func TestBearerAuditSink_ToWireIncludesSDKVersion(t *testing.T) {
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	wire := sink.toWireFormat(map[string]any{
		"tool":      "test_tool",
		"decision":  "allow",
		"policy_id": "rule-0",
		"reason":    "test",
	})
	got, ok := wire["controlzero_sdk_version"].(string)
	if !ok {
		t.Fatalf("controlzero_sdk_version missing or wrong type: %#v", wire["controlzero_sdk_version"])
	}
	if got != sdkVersionWire {
		t.Errorf("wire controlzero_sdk_version = %q; want %q", got, sdkVersionWire)
	}
}

func TestBearerAuditSink_SDKVersionDistinctFromClientVersion(t *testing.T) {
	// The whole point of v1 is to disambiguate the two. They must
	// be distinct keys with distinct shapes.
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	wire := sink.toWireFormat(map[string]any{
		"tool":     "x",
		"decision": "allow",
	})
	sdkVer := wire["controlzero_sdk_version"]
	clientVer := wire["client_version"]
	if sdkVer == clientVer {
		t.Errorf("controlzero_sdk_version and client_version collided: both = %q", sdkVer)
	}
}
