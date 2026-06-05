package controlzero

// W3C Trace Context origination for the Go SDK (#955, #956).
//
// Asserts the SDK parser agrees with the shared W3C conformance fixture (so it
// cannot drift from the gateway/Python/Node parsers and the backend Go core)
// and that outbound injection originates a fresh valid trace when none is
// ambient and continues an ambient TRACEPARENT (same trace-id, new child span).

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var (
	tcReTraceID = regexp.MustCompile(`^[0-9a-f]{32}$`)
	tcReSpanID  = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

func tcFindSharedFixture() string {
	rel := filepath.Join("tests", "fixtures", "tracecontext", "vectors.json")
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(dir, rel)
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func TestSDKParserAgreesWithSharedFixture(t *testing.T) {
	path := tcFindSharedFixture()
	if path == "" {
		t.Skip("shared trace-context fixture not present in this checkout")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f struct {
		Vectors []struct {
			Name     string `json:"name"`
			Header   string `json:"header"`
			Valid    bool   `json:"valid"`
			TraceID  string `json:"trace_id"`
			ParentID string `json:"parent_id"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}
	for _, v := range f.Vectors {
		tp, ok := parseTraceParent(v.Header)
		if ok != v.Valid {
			t.Errorf("%s: parse ok=%v want %v", v.Name, ok, v.Valid)
			continue
		}
		if v.Valid {
			if tp.traceID != v.TraceID || tp.parentID != v.ParentID {
				t.Errorf("%s: got (%s,%s) want (%s,%s)", v.Name, tp.traceID, tp.parentID, v.TraceID, v.ParentID)
			}
		}
	}
}

func TestInjectOriginatesTraceWhenNoAmbient(t *testing.T) {
	t.Setenv("TRACEPARENT", "")
	req, _ := http.NewRequest(http.MethodPost, "http://x/v1/sdk/audit", nil)
	injectTraceContext(req)
	tp, ok := parseTraceParent(req.Header.Get(traceparentHeader))
	if !ok {
		t.Fatalf("injected traceparent %q did not parse", req.Header.Get(traceparentHeader))
	}
	if !tcReTraceID.MatchString(tp.traceID) || !tcReSpanID.MatchString(tp.parentID) {
		t.Fatalf("invalid generated ids: %+v", tp)
	}
	if req.Header.Get("X-Request-ID") != tp.traceID {
		t.Errorf("X-Request-ID = %q, want trace-id %q", req.Header.Get("X-Request-ID"), tp.traceID)
	}
	if req.Header.Get("X-Correlation-ID") != tp.traceID {
		t.Errorf("X-Correlation-ID = %q, want trace-id %q", req.Header.Get("X-Correlation-ID"), tp.traceID)
	}
}

func TestInjectContinuesAmbientTrace(t *testing.T) {
	t.Setenv("TRACEPARENT", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	req, _ := http.NewRequest(http.MethodPost, "http://x/v1/sdk/audit", nil)
	injectTraceContext(req)
	tp, ok := parseTraceParent(req.Header.Get(traceparentHeader))
	if !ok {
		t.Fatal("traceparent did not parse")
	}
	if tp.traceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace-id not continued: %q", tp.traceID)
	}
	if tp.parentID == "00f067aa0ba902b7" {
		t.Errorf("parent-id should be a new child span, got the ambient %q", tp.parentID)
	}
}

func TestInjectNeverPropagatesMalformedAmbient(t *testing.T) {
	t.Setenv("TRACEPARENT", "garbage")
	req, _ := http.NewRequest(http.MethodPost, "http://x/v1/sdk/audit", nil)
	injectTraceContext(req)
	got := req.Header.Get(traceparentHeader)
	if got == "garbage" {
		t.Fatal("malformed ambient traceparent was propagated")
	}
	if _, ok := parseTraceParent(got); !ok {
		t.Fatalf("originated traceparent %q is not valid", got)
	}
}
