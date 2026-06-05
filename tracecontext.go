package controlzero

// W3C Trace Context (https://www.w3.org/TR/trace-context/) origination for the
// Go SDK (#955, child D of epic #951).
//
// The SDK originates the trace so a request is correlated from the agent, not
// just from the Control Zero edge inward. On every outbound call the SDK either
// CONTINUES an ambient trace (the TRACEPARENT env var the host app / OTel
// auto-instrumentation set), generating a fresh child span, or ORIGINATES a new
// trace. It then injects traceparent (+ legacy X-Request-ID / X-Correlation-ID
// carrying the trace-id) so the gateway continues the SAME trace (child B /
// #953) and the trace-id appears in the gateway response, logs, and audit
// (child C / #954).
//
// Dependency-free mirror of the gateway/Python/Node parsers and the backend Go
// core (internal/tracecontext); the same strict validation keeps the SDK from
// propagating a malformed ambient value.

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"strconv"
)

const traceparentHeader = "traceparent"

const (
	tcSupportedVersion = "00"
	tcFlagSampled      = "01"
	tcMaxHeaderLen     = 512
	tcZeroTraceID      = "00000000000000000000000000000000"
	tcZeroSpanID       = "0000000000000000"
)

// traceParent is a parsed, validated W3C traceparent.
type traceParent struct {
	traceID  string
	parentID string
	flags    string
}

func (tp traceParent) serialize() string {
	return tcSupportedVersion + "-" + tp.traceID + "-" + tp.parentID + "-" + tp.flags
}

func (tp traceParent) withNewSpan() traceParent {
	tp.parentID = tcRandHex(8)
	return tp
}

func tcIsLowerHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

func tcMaskFlags(flags string) string {
	v, err := strconv.ParseInt(flags, 16, 0)
	if err != nil {
		return "00"
	}
	if v&0x01 == 0x01 {
		return tcFlagSampled
	}
	return "00"
}

// parseTraceParent strictly validates a traceparent value, returning ok=false
// on any deviation so a malformed ambient value is never propagated. Mirrors
// the gateway/Python/Node parsers and internal/tracecontext exactly.
func parseTraceParent(header string) (traceParent, bool) {
	n := len(header)
	if n < 55 || n > tcMaxHeaderLen {
		return traceParent{}, false
	}
	version := header[0:2]
	if !tcIsLowerHex(version) || version == "ff" || header[2] != '-' {
		return traceParent{}, false
	}
	traceID := header[3:35]
	if header[35] != '-' {
		return traceParent{}, false
	}
	parentID := header[36:52]
	if header[52] != '-' {
		return traceParent{}, false
	}
	flags := header[53:55]
	if version == tcSupportedVersion {
		if n != 55 {
			return traceParent{}, false
		}
	} else if n > 55 && header[55] != '-' {
		return traceParent{}, false
	}
	if !tcIsLowerHex(traceID) || traceID == tcZeroTraceID {
		return traceParent{}, false
	}
	if !tcIsLowerHex(parentID) || parentID == tcZeroSpanID {
		return traceParent{}, false
	}
	if !tcIsLowerHex(flags) {
		return traceParent{}, false
	}
	return traceParent{traceID: traceID, parentID: parentID, flags: tcMaskFlags(flags)}, true
}

// newTrace originates a brand-new sampled trace.
func newTrace() traceParent {
	return traceParent{traceID: tcRandHex(16), parentID: tcRandHex(8), flags: tcFlagSampled}
}

// traceParentForOutbound resolves the child traceparent to inject on an
// outbound request: continue the ambient TRACEPARENT env trace if present +
// valid (new child span), else originate a new trace.
func traceParentForOutbound() traceParent {
	if ambient, ok := parseTraceParent(os.Getenv("TRACEPARENT")); ok {
		return ambient.withNewSpan()
	}
	return newTrace().withNewSpan()
}

// injectTraceContext sets traceparent (child span) + legacy X-Request-ID /
// X-Correlation-ID (carrying the trace-id) on an outbound request so the
// gateway continues the same trace.
func injectTraceContext(req *http.Request) {
	if req == nil {
		return
	}
	tp := traceParentForOutbound()
	req.Header.Set(traceparentHeader, tp.serialize())
	if req.Header.Get("X-Request-ID") == "" {
		req.Header.Set("X-Request-ID", tp.traceID)
	}
	if req.Header.Get("X-Correlation-ID") == "" {
		req.Header.Set("X-Correlation-ID", tp.traceID)
	}
}

func tcRandHex(n int) string {
	b := make([]byte, n)
	for {
		if _, err := rand.Read(b); err != nil {
			panic("controlzero: crypto/rand failed: " + err.Error())
		}
		allZero := true
		for _, x := range b {
			if x != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			return hex.EncodeToString(b)
		}
	}
}
