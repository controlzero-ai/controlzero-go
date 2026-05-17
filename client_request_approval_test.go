// HITL-6c Client.RequestApproval tests. Mirror Python
// test_hitl_6a_request_approval.py 1:1, adapted for httptest.

package controlzero

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------

// setFakeHomeAndEmail wires HOME at a tmp dir and (optionally) writes
// ~/.controlzero/config.yaml with the given email. Returns the tmp
// home path so callers can poke at it.
func setFakeHomeAndEmail(t *testing.T, email string) string {
	t.Helper()
	tmp := t.TempDir()
	prev, had := os.LookupEnv("HOME")
	_ = os.Setenv("HOME", tmp)
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("HOME", prev)
		} else {
			_ = os.Unsetenv("HOME")
		}
	})
	if email != "" {
		dir := filepath.Join(tmp, ".controlzero")
		_ = os.MkdirAll(dir, 0o700)
		_ = os.WriteFile(filepath.Join(dir, "config.yaml"),
			[]byte("email: "+email+"\n"), 0o600)
	}
	return tmp
}

// setAPIURL points the SDK at the supplied URL via CONTROLZERO_API_URL.
func setAPIURL(t *testing.T, url string) {
	t.Helper()
	prev, had := os.LookupEnv("CONTROLZERO_API_URL")
	_ = os.Setenv("CONTROLZERO_API_URL", url)
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("CONTROLZERO_API_URL", prev)
		} else {
			_ = os.Unsetenv("CONTROLZERO_API_URL")
		}
	})
}

// makeAPIClient builds a Client with an API key + trivial local
// policy (short-circuiting hosted bootstrap) for use in tests.
func makeAPIClient(t *testing.T) *Client {
	t.Helper()
	resetWarningState()
	c, err := New(
		WithAPIKey("cz_test_unit_fixture_000000000000000000000000"),
		WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"allow": "*", "reason": "test"},
			},
		}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// makeNoKeyClient builds a Client with no API key (local-only).
func makeNoKeyClient(t *testing.T) *Client {
	t.Helper()
	resetWarningState()
	prev, had := os.LookupEnv("CONTROLZERO_API_KEY")
	_ = os.Unsetenv("CONTROLZERO_API_KEY")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("CONTROLZERO_API_KEY", prev)
		}
	})
	c, err := New(
		WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"allow": "*", "reason": "test"},
			},
		}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// futureISO returns an ISO-8601 UTC timestamp `seconds` in the future
// with the Z suffix the backend sends.
func futureISO(seconds int) string {
	return time.Now().UTC().Add(time.Duration(seconds) * time.Second).Format("2006-01-02T15:04:05Z")
}

type capturedRequest struct {
	method  string
	url     string
	headers http.Header
	body    map[string]any
}

// serveResponse returns an httptest.Server that responds with the
// given status + JSON body (or non-JSON when bodyRaw != "") for the
// first request, and captures the inbound request fields.
func serveResponse(t *testing.T, status int, body any, bodyRaw string) (*httptest.Server, *capturedRequest) {
	t.Helper()
	cap := &capturedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.method = r.Method
		cap.url = r.URL.String()
		cap.headers = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &cap.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if bodyRaw != "" {
			_, _ = io.WriteString(w, bodyRaw)
		} else if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

// -----------------------------------------------------------------------
// Happy path
// -----------------------------------------------------------------------

func TestRequestApprovalHappyPath(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	requestID := "req-uuid-happy"
	expiresAt := futureISO(600)
	srv, cap := serveResponse(t, 200, map[string]any{
		"id": requestID, "expires_at": expiresAt, "state": "pending",
	}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()

	pa, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{
		Message:  "please approve",
		TimeoutS: 300,
		Context: HITLApprovalContext{
			CanonicalAction: "delete_file",
			ProjectID:       "proj-1",
			AgentID:         "agent-1",
			Resource:        "/tmp/test",
			ArgsRedacted:    map[string]any{"path": "/tmp/test"},
			ArgsHash:        "abc123",
		},
	})
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if pa.RequestID != requestID {
		t.Errorf("RequestID = %q, want %q", pa.RequestID, requestID)
	}
	if pa.Status != StatusPending {
		t.Errorf("Status = %q", pa.Status)
	}
	if pa.IdempotencyKey == "" || len(pa.IdempotencyKey) != 36 {
		t.Errorf("IdempotencyKey = %q (len %d), want UUIDv4", pa.IdempotencyKey, len(pa.IdempotencyKey))
	}
	if pa.PollIntervalS != 1.0 {
		t.Errorf("PollIntervalS = %v", pa.PollIntervalS)
	}

	// Headers + URL + body shape.
	if cap.method != "POST" {
		t.Errorf("method = %s", cap.method)
	}
	if cap.url != "/api/approval-requests" {
		t.Errorf("url = %s", cap.url)
	}
	if got := cap.headers.Get("Authorization"); !strings.HasPrefix(got, "Bearer cz_test_") {
		t.Errorf("Authorization = %q", got)
	}
	if got := cap.headers.Get("Idempotency-Key"); got != pa.IdempotencyKey {
		t.Errorf("Idempotency-Key on wire = %q, want %q", got, pa.IdempotencyKey)
	}
	if got := cap.headers.Get("X-CZ-Requestor-Email"); got != "alice@example.com" {
		t.Errorf("X-CZ-Requestor-Email = %q", got)
	}
	if cap.body["canonical_action"] != "delete_file" {
		t.Errorf("canonical_action = %v", cap.body["canonical_action"])
	}
	if cap.body["project_id"] != "proj-1" {
		t.Errorf("project_id = %v", cap.body["project_id"])
	}
	if cap.body["reason"] != "please approve" {
		t.Errorf("reason = %v", cap.body["reason"])
	}
	if int(cap.body["ttl_seconds"].(float64)) != 300 {
		t.Errorf("ttl_seconds = %v", cap.body["ttl_seconds"])
	}
}

func TestRequestApprovalDefaultMessageWhenEmpty(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, cap := serveResponse(t, 200, map[string]any{
		"id": "r", "expires_at": futureISO(60),
	}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if cap.body["reason"] != "requested by SDK" {
		t.Errorf("default reason = %v", cap.body["reason"])
	}
}

func TestRequestApprovalDefaultTimeoutWhenZero(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, cap := serveResponse(t, 200, map[string]any{
		"id": "r", "expires_at": futureISO(60),
	}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{TimeoutS: 0})
	if err != nil {
		t.Fatal(err)
	}
	if int(cap.body["ttl_seconds"].(float64)) != 300 {
		t.Errorf("default ttl = %v, want 300", cap.body["ttl_seconds"])
	}
}

func TestRequestApprovalOptionalFieldsOmittedWhenEmpty(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, cap := serveResponse(t, 200, map[string]any{
		"id": "r", "expires_at": futureISO(60),
	}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{
		Context: HITLApprovalContext{CanonicalAction: "delete_file"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"project_id", "agent_id", "resource", "args_redacted", "args_hash"} {
		if _, has := cap.body[k]; has {
			t.Errorf("expected %s to be omitted from body, got %v", k, cap.body[k])
		}
	}
	if cap.body["canonical_action"] != "delete_file" {
		t.Errorf("canonical_action = %v", cap.body["canonical_action"])
	}
}

// -----------------------------------------------------------------------
// Idempotency-Key
// -----------------------------------------------------------------------

func TestRequestApprovalTwoCallsDistinctIdempotencyKeys(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	mu := sync.Mutex{}
	seenIDs := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenIDs = append(seenIDs, r.Header.Get("Idempotency-Key"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"r","expires_at":"`+futureISO(60)+`"}`)
	}))
	t.Cleanup(srv.Close)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()

	pa1, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	if err != nil {
		t.Fatal(err)
	}
	pa2, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if pa1.IdempotencyKey == pa2.IdempotencyKey {
		t.Errorf("two calls produced identical keys: %s", pa1.IdempotencyKey)
	}
	if len(seenIDs) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(seenIDs))
	}
	if seenIDs[0] != pa1.IdempotencyKey || seenIDs[1] != pa2.IdempotencyKey {
		t.Errorf("wire keys did not match returned PendingApproval keys")
	}
}

func TestRequestApprovalConcurrentCallsProduceDistinctKeys(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	mu := sync.Mutex{}
	seen := map[string]bool{}
	count := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Header.Get("Idempotency-Key")] = true
		mu.Unlock()
		count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"r","expires_at":"`+futureISO(60)+`"}`)
	}))
	t.Cleanup(srv.Close)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()

	const N = 32
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
		}()
	}
	wg.Wait()
	if int(count.Load()) != N {
		t.Errorf("server saw %d, want %d", count.Load(), N)
	}
	if len(seen) != N {
		t.Errorf("distinct keys = %d, want %d", len(seen), N)
	}
}

// -----------------------------------------------------------------------
// Error mapping
// -----------------------------------------------------------------------

func TestRequestApprovalMissingAPIKeyBackendUnreachable(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	c := makeNoKeyClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) {
		t.Fatalf("expected *HITLBackendUnreachableError, got %T: %v", err, err)
	}
	if !strings.Contains(bu.Message, "API key") {
		t.Errorf("expected 'API key' in message, got %q", bu.Message)
	}
}

func TestRequestApprovalMissingEmailIdentityRequired(t *testing.T) {
	setFakeHomeAndEmail(t, "") // no email
	srv, _ := serveResponse(t, 200, map[string]any{}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var ir *HITLIdentityRequired
	if !errors.As(err, &ir) {
		t.Fatalf("expected *HITLIdentityRequired, got %T: %v", err, err)
	}
}

func TestRequestApprovalSecretLeakInArgsAbortsBeforePost(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	called := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	leaky := map[string]any{"token": "cz_test_" + strings.Repeat("a", 40)}
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{
		Context: HITLApprovalContext{ArgsRedacted: leaky},
	})
	var leak *SecretValueLeakInPayload
	if !errors.As(err, &leak) {
		t.Fatalf("expected *SecretValueLeakInPayload, got %T: %v", err, err)
	}
	if called.Load() != 0 {
		t.Errorf("server received %d requests, want 0", called.Load())
	}
}

func TestRequestApprovalNetworkErrorMapsToBackendUnreachable(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	// Point at an unreachable URL.
	setAPIURL(t, "http://127.0.0.1:1/no-server-here")
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) {
		t.Fatalf("expected *HITLBackendUnreachableError, got %T: %v", err, err)
	}
}

func TestRequestApprovalHTTP500MapsToBackendUnreachable(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 500, map[string]any{"error": "internal"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) {
		t.Fatalf("expected backend unreachable, got %v", err)
	}
	if !strings.Contains(bu.Message, "500") {
		t.Errorf("expected HTTP 500 in message: %q", bu.Message)
	}
}

func TestRequestApprovalHTTP502NonJSONBody(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 502, nil, "<html>bad gateway</html>")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(bu.Message, "502") {
		t.Errorf("expected HTTP 502 backend unreachable, got %v", err)
	}
}

func TestRequestApprovalHTTP401MapsToHostedAuthError(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 401, map[string]any{"error": "Unauthorized"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var ae *HostedAuthError
	if !errors.As(err, &ae) {
		t.Errorf("expected *HostedAuthError, got %T: %v", err, err)
	}
}

func TestRequestApprovalHTTP404MapsToNotConfigured(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 404, map[string]any{"error": "not found"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var nc *HITLNotConfiguredError
	if !errors.As(err, &nc) {
		t.Errorf("expected *HITLNotConfiguredError, got %T: %v", err, err)
	}
}

func TestRequestApprovalHTTP400E1307MapsToIdentityRequired(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 400, map[string]any{"code": "E1307", "message": "need email"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var ir *HITLIdentityRequired
	if !errors.As(err, &ir) {
		t.Fatalf("expected *HITLIdentityRequired, got %T: %v", err, err)
	}
	if !strings.Contains(ir.Message, "need email") {
		t.Errorf("backend message not propagated: %q", ir.Message)
	}
}

func TestRequestApprovalHTTP400E1306MapsToIdentityNotInOrg(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 400, map[string]any{"code": "E1306", "message": "wrong org"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var noo *HITLIdentityNotInOrg
	if !errors.As(err, &noo) {
		t.Errorf("expected *HITLIdentityNotInOrg, got %T: %v", err, err)
	}
}

func TestRequestApprovalHTTP400E1308MapsToClaimRejected(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 400, map[string]any{"code": "E1308", "message": "rejected"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var cr *HITLIdentityClaimRejected
	if !errors.As(err, &cr) {
		t.Errorf("expected *HITLIdentityClaimRejected, got %T: %v", err, err)
	}
}

func TestRequestApprovalHTTP400UnknownCodeFallsThrough(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 400, map[string]any{"code": "E9999", "message": "other"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(bu.Message, "400") {
		t.Errorf("expected backend unreachable on unknown 400 code, got %v", err)
	}
}

func TestRequestApprovalHTTP503E1305MapsToNoApprover(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 503, map[string]any{"code": "E1305", "message": "no approvers"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var na *HITLNoApproverAvailable
	if !errors.As(err, &na) {
		t.Errorf("expected *HITLNoApproverAvailable, got %T: %v", err, err)
	}
}

func TestRequestApprovalHTTP503NoApproverMessageMaps(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 503, map[string]any{"message": "No approver available right now"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var na *HITLNoApproverAvailable
	if !errors.As(err, &na) {
		t.Errorf("expected *HITLNoApproverAvailable, got %T: %v", err, err)
	}
}

func TestRequestApprovalHTTP503UnrelatedFallsThrough(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 503, map[string]any{"message": "db pool exhausted"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(bu.Message, "503") {
		t.Errorf("expected HTTP 503 backend unreachable, got %v", err)
	}
}

func TestRequestApprovalErrorBodyNotDictIgnored(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 500, []any{"error", "something"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(bu.Message, "500") {
		t.Errorf("expected fallback 500, got %v", err)
	}
}

// -----------------------------------------------------------------------
// Malformed 2xx responses
// -----------------------------------------------------------------------

func TestRequestApprovalMissingIDReturnsMalformedError(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 200, map[string]any{"expires_at": futureISO(60)}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(strings.ToLower(bu.Message), "malformed") {
		t.Errorf("expected malformed response error, got %v", err)
	}
}

func TestRequestApprovalMissingExpiresAtReturnsMalformedError(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 200, map[string]any{"id": "r"}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(strings.ToLower(bu.Message), "malformed") {
		t.Errorf("expected malformed response error, got %v", err)
	}
}

func TestRequestApprovalNonJSONBodyOn2xx(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 200, nil, "not-json-at-all")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(bu.Message, "non-JSON") {
		t.Errorf("expected non-JSON error, got %v", err)
	}
}

func TestRequestApprovalUnparseableExpiresAt(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 200, map[string]any{
		"id": "r", "expires_at": "not-a-real-timestamp",
	}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(bu.Message, "expires_at") {
		t.Errorf("expected unparseable expires_at error, got %v", err)
	}
}

func TestRequestApprovalNaiveExpiresAtRejected(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 200, map[string]any{
		"id": "r", "expires_at": "2099-01-01T00:00:00",
	}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) {
		t.Errorf("expected backend unreachable on naive datetime, got %v", err)
	}
}

// -----------------------------------------------------------------------
// Context handling
// -----------------------------------------------------------------------

func TestRequestApprovalNilContextDefaultsToBackground(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 200, map[string]any{
		"id": "r", "expires_at": futureISO(60),
	}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	//nolint:staticcheck // testing nil ctx path on purpose
	_, err := c.RequestApproval(nil, PolicyDecision{}, RequestApprovalOpts{})
	if err != nil {
		t.Errorf("nil ctx should fall back to Background, got %v", err)
	}
}

func TestRequestApprovalCustomHTTPClientHonoured(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv, _ := serveResponse(t, 200, map[string]any{
		"id": "r", "expires_at": futureISO(60),
	}, "")
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	customCalls := atomic.Int32{}
	custom := &http.Client{
		Transport: &countingTransport{counter: &customCalls, next: http.DefaultTransport},
		Timeout:   5 * time.Second,
	}
	_, err := c.RequestApproval(context.Background(), PolicyDecision{}, RequestApprovalOpts{
		HTTPClient: custom,
	})
	if err != nil {
		t.Fatal(err)
	}
	if customCalls.Load() != 1 {
		t.Errorf("custom client unused: %d calls", customCalls.Load())
	}
}

type countingTransport struct {
	counter *atomic.Int32
	next    http.RoundTripper
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.counter.Add(1)
	return c.next.RoundTrip(r)
}

// -----------------------------------------------------------------------
// parseISO8601UTC helper coverage
// -----------------------------------------------------------------------

func TestParseISO8601UTCParsesZSuffix(t *testing.T) {
	got, err := parseISO8601UTC("2099-01-02T03:04:05Z")
	if err != nil {
		t.Fatal(err)
	}
	if got.Year() != 2099 || got.Location() != time.UTC {
		t.Errorf("got %v", got)
	}
}

func TestParseISO8601UTCParsesNanoZ(t *testing.T) {
	got, err := parseISO8601UTC("2099-01-02T03:04:05.123456789Z")
	if err != nil {
		t.Fatal(err)
	}
	if got.Year() != 2099 {
		t.Errorf("got %v", got)
	}
}

func TestParseISO8601UTCParsesOffset(t *testing.T) {
	got, err := parseISO8601UTC("2099-01-02T03:04:05+00:00")
	if err != nil {
		t.Fatal(err)
	}
	if got.Year() != 2099 {
		t.Errorf("got %v", got)
	}
}

func TestParseISO8601UTCParsesMillisZ(t *testing.T) {
	got, err := parseISO8601UTC("2099-01-02T03:04:05.123Z")
	if err != nil {
		t.Fatal(err)
	}
	if got.Year() != 2099 {
		t.Errorf("got %v", got)
	}
}

func TestParseISO8601UTCRejectsEmpty(t *testing.T) {
	if _, err := parseISO8601UTC(""); err == nil {
		t.Error("expected error on empty")
	}
}

func TestParseISO8601UTCRejectsNaive(t *testing.T) {
	if _, err := parseISO8601UTC("2099-01-02T03:04:05"); err == nil {
		t.Error("expected error on naive datetime")
	}
}

func TestParseISO8601UTCRejectsGarbage(t *testing.T) {
	if _, err := parseISO8601UTC("not-a-real-timestamp"); err == nil {
		t.Error("expected error on garbage")
	}
}

// -----------------------------------------------------------------------
// lowercaseASCII / containsASCII helpers
// -----------------------------------------------------------------------

func TestLowercaseASCII(t *testing.T) {
	if got := lowercaseASCII("HELLO"); got != "hello" {
		t.Errorf("got %q", got)
	}
	if got := lowercaseASCII("MixedCASE"); got != "mixedcase" {
		t.Errorf("got %q", got)
	}
}

func TestContainsASCII(t *testing.T) {
	if !containsASCII("the quick brown fox", "quick") {
		t.Error("substring missed")
	}
	if containsASCII("abc", "xyz") {
		t.Error("false positive")
	}
	if !containsASCII("abc", "") {
		t.Error("empty needle should match")
	}
	if containsASCII("ab", "abc") {
		t.Error("longer needle than haystack should not match")
	}
}

func TestBytesIndex(t *testing.T) {
	if got := bytesIndex("hello world", "world"); got != 6 {
		t.Errorf("got %d, want 6", got)
	}
	if got := bytesIndex("abc", "xyz"); got != -1 {
		t.Errorf("got %d, want -1", got)
	}
	if got := bytesIndex("abc", ""); got != 0 {
		t.Errorf("empty needle: got %d, want 0", got)
	}
	if got := bytesIndex("a", "ab"); got != -1 {
		t.Errorf("longer needle: got %d, want -1", got)
	}
}
