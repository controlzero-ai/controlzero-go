// #439: non-finite telemetry must NOT poison the batch (shared emit layer).
//
// A non-finite estimated_cost_usd (NaN / +/-Inf -- e.g. an adapter that
// already holds inf, or the string "inf" which strconv.ParseFloat accepts
// without error) must NOT reach the wire: json.Marshal of the batch body
// errors on Inf/NaN in Go, which would drop EVERY entry in that batch (the
// "one bad row cannot poison a batch" contract). Same for non-finite token
// counts, which would also corrupt the value. Node already guards with
// Number.isFinite; these tests pin the Go parity.
//
// fail-if-reverted: remove the math.IsInf/IsNaN guards in floatOrZero /
// uintOrZero and json.Marshal of the batch below returns an error.

package controlzero

import (
	"encoding/json"
	"math"
	"testing"
)

func TestToWire_NonFiniteCostAndTokensOmitted_BatchSerializes(t *testing.T) {
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})

	// One entry carries every flavor of non-finite value; a second is good.
	bad := sink.toWireFormat(map[string]any{
		"tool":               "llm_request",
		"decision":           "allow",
		"estimated_cost_usd": math.Inf(1),
		"input_tokens":       math.Inf(1),
		"output_tokens":      math.NaN(),
		"latency_ms":         math.Inf(-1),
	})
	good := sink.toWireFormat(map[string]any{
		"tool":               "llm_request",
		"decision":           "allow",
		"estimated_cost_usd": 0.0042,
		"input_tokens":       1200,
		"output_tokens":      350,
		"latency_ms":         842,
	})

	// Non-finite values must be omitted entirely (not 0, not Inf/NaN).
	for _, k := range []string{"estimated_cost_usd", "input_tokens", "output_tokens", "latency_ms"} {
		if v, present := bad[k]; present {
			t.Errorf("%s must be omitted on a non-finite value, got %#v", k, v)
		}
	}

	// The good entry keeps its finite values.
	if got := good["estimated_cost_usd"]; got != 0.0042 {
		t.Errorf("estimated_cost_usd = %#v, want 0.0042", got)
	}
	if got := good["input_tokens"]; got != uint32(1200) {
		t.Errorf("input_tokens = %#v, want 1200", got)
	}

	// The batch body must marshal cleanly: encoding/json returns an error
	// for a non-finite float64, so this passing proves no Inf/NaN reached
	// the wire.
	body, err := json.Marshal(map[string]any{"entries": []map[string]any{bad, good}})
	if err != nil {
		t.Fatalf("batch must JSON-marshal cleanly (no Inf/NaN on the wire), got error: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty batch body")
	}
}

func TestToWire_StringInfCostOmitted(t *testing.T) {
	// strconv.ParseFloat("inf", 64) returns (+Inf, nil) -- no error -- so a
	// quoted "inf" cost from an adapter would slip through a naive guard.
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	wire := sink.toWireFormat(map[string]any{
		"tool":               "t",
		"decision":           "allow",
		"estimated_cost_usd": "inf",
		"input_tokens":       "nan",
	})
	if v, present := wire["estimated_cost_usd"]; present {
		t.Errorf("string \"inf\" cost must be omitted, got %#v", v)
	}
	if v, present := wire["input_tokens"]; present {
		t.Errorf("string \"nan\" tokens must be omitted, got %#v", v)
	}
	if _, err := json.Marshal(map[string]any{"entries": []map[string]any{wire}}); err != nil {
		t.Fatalf("batch must marshal cleanly, got error: %v", err)
	}
}

func TestToWire_NonSerializableArgsSanitized_BatchSerializes(t *testing.T) {
	// A nested non-finite float / unsupported type inside args must NOT
	// poison the batch (#439): args is sanitized to strict-JSON-safe before
	// it goes on the wire. fail-if-reverted: drop jsonSafe and json.Marshal
	// of the batch below returns an error.
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	wire := sink.toWireFormat(map[string]any{
		"tool":     "db_query",
		"decision": "allow",
		"args": map[string]any{
			"limit":  10,
			"ratio":  math.Inf(1),                       // nested non-finite -> dropped
			"fn":     func() {},                          // unsupported type -> string form
			"nested": map[string]any{"score": math.NaN(), "name": "ok"},
			"items":  []any{1, math.Inf(-1), "x"},
		},
	})

	a, ok := wire["args"].(map[string]any)
	if !ok {
		t.Fatalf("args missing or wrong type: %#v", wire["args"])
	}
	if a["ratio"] != nil {
		t.Errorf("nested +Inf must be dropped to nil, got %#v", a["ratio"])
	}
	if nested, ok := a["nested"].(map[string]any); ok {
		if nested["score"] != nil {
			t.Errorf("nested NaN must be dropped to nil, got %#v", nested["score"])
		}
		if nested["name"] != "ok" {
			t.Errorf("valid sibling must be preserved, got %#v", nested["name"])
		}
	} else {
		t.Errorf("nested map missing: %#v", a["nested"])
	}

	// The batch body must marshal cleanly (Go errors on Inf/NaN and on
	// unsupported types like func), proving none reached the wire.
	if _, err := json.Marshal(map[string]any{"entries": []map[string]any{wire}}); err != nil {
		t.Fatalf("batch must JSON-marshal cleanly, got error: %v", err)
	}
}

func TestToWire_CyclicArgsTerminates_BatchSerializes(t *testing.T) {
	// A self-referential args map must NOT hang / stack-overflow (#439 codex
	// P1): jsonSafe is depth-bounded and returns a constant marker at the
	// limit. The batch must still marshal cleanly. A test timeout would catch
	// a non-terminating walk.
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	cyclic := map[string]any{"k": "v"}
	cyclic["self"] = cyclic // cycle

	wire := sink.toWireFormat(map[string]any{
		"tool":     "t",
		"decision": "allow",
		"args":     cyclic,
	})

	// Must terminate and produce a JSON-marshalable body (no hang, no panic).
	if _, err := json.Marshal(map[string]any{"entries": []map[string]any{wire}}); err != nil {
		t.Fatalf("cyclic args must still marshal cleanly, got error: %v", err)
	}
}

func TestToWire_TopLevelForwardedFieldSanitized_BatchSerializes(t *testing.T) {
	// A non-finite / unsupported value on a RAW top-level forwarded field
	// (the credential_* envelope under event_kind) must NOT poison the batch
	// (#439 codex P1-b): the final wire map is sanitized before return.
	// fail-if-reverted: drop the final jsonSafe(wire) and json.Marshal of the
	// batch below returns an error (Go errors on Inf and on func values).
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	wire := sink.toWireFormat(map[string]any{
		"tool":       "credential_scan",
		"decision":   "warn",
		"event_kind": "credential_leak_detected",
		"pattern_id": "aws-access-key-id",
		// A malformed adapter stuffs non-finite / unsupported values onto
		// forwarded credential fields -- copied raw, so without the final-map
		// sanitizer they would reach json.Marshal.
		"value_hash": math.Inf(1),
		"source":     func() {}, // unsupported type
	})

	if wire["event_kind"] != "credential_leak_detected" {
		t.Errorf("event_kind not forwarded: %#v", wire["event_kind"])
	}
	if wire["pattern_id"] != "aws-access-key-id" {
		t.Errorf("pattern_id not forwarded: %#v", wire["pattern_id"])
	}
	if v := wire["value_hash"]; v != nil {
		t.Errorf("non-finite value_hash must be sanitized to nil, got %#v", v)
	}
	// The batch must marshal cleanly (Go errors on Inf and on func), proving
	// none reached the wire.
	if _, err := json.Marshal(map[string]any{"entries": []map[string]any{wire}}); err != nil {
		t.Fatalf("batch must JSON-marshal cleanly, got error: %v", err)
	}
}

func TestToWire_HugeFiniteCostStillEmitted(t *testing.T) {
	// A large but FINITE cost is legitimate and must still be emitted.
	sink := NewBearerAuditSink(BearerAuditOptions{
		APIURL: "https://api.example.com",
		APIKey: "cz_test_fakekey",
	})
	wire := sink.toWireFormat(map[string]any{
		"tool":               "t",
		"decision":           "allow",
		"estimated_cost_usd": 1234.56,
	})
	if got := wire["estimated_cost_usd"]; got != 1234.56 {
		t.Errorf("finite cost must be emitted, got %#v", got)
	}
	if _, err := json.Marshal(map[string]any{"entries": []map[string]any{wire}}); err != nil {
		t.Fatalf("batch must marshal cleanly, got error: %v", err)
	}
}
