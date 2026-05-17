// HITL HTTP client helper -- gemini P1 (PR #584).
//
// Replaces http.DefaultClient as the fallback for HITL fetch sites so
// the SDK never reuses (or pollutes) the global Go HTTP transport from
// a library context. A dedicated *http.Client with an explicit 10s
// per-request timeout caps a stuck socket without relying on the outer
// wait() loop's deadline. Callers can still inject their own client via
// GetSecretOpts.HTTPClient / RequestApprovalOpts.HTTPClient.
//
// 10s mirrors the Node SDK's AbortSignal.timeout(10_000) for parity.

package controlzero

import (
	"net/http"
	"time"
)

const hitlDefaultHTTPTimeout = 10 * time.Second

// defaultHITLClient returns a fresh *http.Client per call (cheap, the
// underlying Transport handles connection pooling) with a sane request
// timeout. Used as the nil-fallback for HITL SDK fetches; never used in
// production callers' code paths if they inject their own client.
func defaultHITLClient() *http.Client {
	return &http.Client{Timeout: hitlDefaultHTTPTimeout}
}
