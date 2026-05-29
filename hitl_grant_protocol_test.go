// HITL Phase 2d grants-protocol tests. Mirrors the negative-test
// matrix the Python (2b) and Node (2c) ports settled on:
//
//   1. POST /api/grants fails (non-2xx)            -> deny
//   2. POST /api/grants returns malformed body     -> deny
//   3. Poll deadline elapses                        -> deny
//   4. Poll terminal denied                         -> deny outcome
//   5. Poll terminal approved                       -> allow outcome
//   6. Context cancelled during poll                -> deny
//   7. Backward compat: RequiresApproval=false      -> no-op
//   8. No API key                                   -> deny
//   9. Backend returns unknown status               -> deny

package controlzero

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeApprovalActionPtr is a tiny helper -- *string for the field.
func fakeApprovalActionPtr(s string) *string { return &s }

// makeGrantClient wires a Client with an API key + a trivial local
// policy so hosted bootstrap is short-circuited. Mirrors the helper
// from client_request_approval_test.go but kept local to keep the
// 2d slice self-contained.
func makeGrantClient(t *testing.T) *Client {
	t.Helper()
	resetWarningState()
	c, err := New(
		WithAPIKey("cz_test_grants_fixture_000000000000000000000000"),
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

// pointGrantClientAt updates CONTROLZERO_API_URL to the test server
// for the duration of the test. Mirrors setAPIURL in
// client_request_approval_test.go.
func pointGrantClientAt(t *testing.T, url string) {
	t.Helper()
	setAPIURL(t, url)
}

// approveDecision builds a synthetic PolicyDecision with the new
// RequiresApproval flag flipped on.
func approveDecision(action string) PolicyDecision {
	return PolicyDecision{
		Effect:           "allow",
		PolicyID:         "rule:hitl-grant-test",
		Reason:           "needs human approval",
		ReasonCode:       "REQUIRES_APPROVAL",
		RequiresApproval: true,
		ApprovalAction:   fakeApprovalActionPtr(action),
	}
}

// -----------------------------------------------------------------------
// Backward-compat: RequiresApproval=false short-circuits cleanly.
// -----------------------------------------------------------------------

func TestMaybeAwaitGrantNoApprovalRequiredIsNoop(t *testing.T) {
	c := makeGrantClient(t)
	defer c.Close()

	decision := PolicyDecision{Effect: "allow", PolicyID: "rule:plain"}
	outcome, err := c.MaybeAwaitGrant(context.Background(), decision, GrantProtocolOpts{})
	if err != nil {
		t.Fatalf("MaybeAwaitGrant returned err = %v, want nil", err)
	}
	if outcome != nil {
		t.Fatalf("outcome = %+v, want nil", outcome)
	}
}

// -----------------------------------------------------------------------
// No API key -> deny (fail-closed).
// -----------------------------------------------------------------------

func TestMaybeAwaitGrantNoAPIKeyFailsClosed(t *testing.T) {
	resetWarningState()
	c, err := New(
		WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*", "reason": "t"}},
		}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	_, err = c.MaybeAwaitGrant(context.Background(), approveDecision("delete_file"), GrantProtocolOpts{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var backend *HITLBackendUnreachableError
	if !errors.As(err, &backend) {
		t.Errorf("err type = %T, want *HITLBackendUnreachableError", err)
	}
}

// -----------------------------------------------------------------------
// POST /api/grants returns non-2xx -> deny.
// -----------------------------------------------------------------------

func TestRequestGrantNon2xxFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	pointGrantClientAt(t, srv.URL)
	c := makeGrantClient(t)
	defer c.Close()

	outcome, err := c.MaybeAwaitGrant(context.Background(),
		approveDecision("delete_file"), GrantProtocolOpts{})
	if err == nil {
		t.Fatal("expected error on 500, got nil")
	}
	if outcome != nil {
		t.Errorf("outcome = %+v, want nil", outcome)
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("err = %v, want HTTP 500 marker", err)
	}
}

// -----------------------------------------------------------------------
// POST /api/grants returns malformed (missing grant_id) -> deny.
// -----------------------------------------------------------------------

func TestRequestGrantMalformedBodyFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"unrelated":"value"}`))
	}))
	defer srv.Close()
	pointGrantClientAt(t, srv.URL)
	c := makeGrantClient(t)
	defer c.Close()

	_, err := c.MaybeAwaitGrant(context.Background(),
		approveDecision("delete_file"), GrantProtocolOpts{})
	if err == nil {
		t.Fatal("expected error on missing grant_id, got nil")
	}
	if !strings.Contains(err.Error(), "missing grant_id") {
		t.Errorf("err = %v, want missing grant_id marker", err)
	}
}

// -----------------------------------------------------------------------
// Poll terminal approved -> allow outcome.
// -----------------------------------------------------------------------

func TestPollGrantApprovedReturnsAllow(t *testing.T) {
	grantID := "grant-abc"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"grant_id":   grantID,
				"expires_at": time.Now().UTC().Add(60 * time.Second).Format("2006-01-02T15:04:05Z"),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"grant_id": grantID, "status": "approved",
		})
	}))
	defer srv.Close()
	pointGrantClientAt(t, srv.URL)
	c := makeGrantClient(t)
	defer c.Close()

	outcome, err := c.MaybeAwaitGrant(context.Background(),
		approveDecision("delete_file"), GrantProtocolOpts{
			SleepFn: func(time.Duration) {},
		})
	if err != nil {
		t.Fatalf("MaybeAwaitGrant err = %v", err)
	}
	if outcome == nil || !outcome.Approved {
		t.Fatalf("outcome = %+v, want Approved=true", outcome)
	}
	if outcome.GrantID != grantID {
		t.Errorf("GrantID = %q, want %q", outcome.GrantID, grantID)
	}
}

// -----------------------------------------------------------------------
// Poll terminal denied -> deny outcome (not error).
// -----------------------------------------------------------------------

func TestPollGrantDeniedReturnsDeny(t *testing.T) {
	grantID := "grant-denied"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"grant_id":   grantID,
				"expires_at": time.Now().UTC().Add(60 * time.Second).Format("2006-01-02T15:04:05Z"),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"grant_id": grantID, "status": "denied",
		})
	}))
	defer srv.Close()
	pointGrantClientAt(t, srv.URL)
	c := makeGrantClient(t)
	defer c.Close()

	outcome, err := c.MaybeAwaitGrant(context.Background(),
		approveDecision("delete_file"), GrantProtocolOpts{
			SleepFn: func(time.Duration) {},
		})
	if err != nil {
		t.Fatalf("MaybeAwaitGrant err = %v, want nil (denied is a clean outcome)", err)
	}
	if outcome == nil || !outcome.Denied {
		t.Fatalf("outcome = %+v, want Denied=true", outcome)
	}
}

// -----------------------------------------------------------------------
// Poll deadline elapses while backend keeps returning pending -> deny
// (HITLTimeoutError).
// -----------------------------------------------------------------------

func TestPollGrantDeadlineFailsClosed(t *testing.T) {
	grantID := "grant-pending-forever"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"grant_id":   grantID,
				"expires_at": time.Now().UTC().Add(2 * time.Second).Format("2006-01-02T15:04:05Z"),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"grant_id": grantID, "status": "pending",
		})
	}))
	defer srv.Close()
	pointGrantClientAt(t, srv.URL)
	c := makeGrantClient(t)
	defer c.Close()

	// Use a 1-second timeout so the deadline trips fast. SleepFn
	// drops real sleeps so the loop ticks instantly.
	_, err := c.MaybeAwaitGrant(context.Background(),
		approveDecision("delete_file"), GrantProtocolOpts{
			TimeoutSecs: 1,
			SleepFn:     func(time.Duration) {},
		})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	var to *HITLTimeoutError
	if !errors.As(err, &to) {
		t.Errorf("err type = %T, want *HITLTimeoutError", err)
	}
}

// -----------------------------------------------------------------------
// Context cancelled while polling -> deny.
// -----------------------------------------------------------------------

func TestPollGrantCtxCancelFailsClosed(t *testing.T) {
	grantID := "grant-pending-cancel"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"grant_id":   grantID,
				"expires_at": time.Now().UTC().Add(60 * time.Second).Format("2006-01-02T15:04:05Z"),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"grant_id": grantID, "status": "pending",
		})
	}))
	defer srv.Close()
	pointGrantClientAt(t, srv.URL)
	c := makeGrantClient(t)
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := c.MaybeAwaitGrant(ctx, approveDecision("delete_file"),
		GrantProtocolOpts{
			// Real sleep so cancel can fire while we are parked.
		})
	if err == nil {
		t.Fatal("expected ctx-cancel error, got nil")
	}
	if !strings.Contains(err.Error(), "cancelled") && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("err = %v, want cancellation marker", err)
	}
}

// -----------------------------------------------------------------------
// Backend returns an unknown status string -> deny (fail closed).
// -----------------------------------------------------------------------

func TestPollGrantUnknownStatusFailsClosed(t *testing.T) {
	grantID := "grant-unknown"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"grant_id":   grantID,
				"expires_at": time.Now().UTC().Add(60 * time.Second).Format("2006-01-02T15:04:05Z"),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"grant_id": grantID, "status": "fubar",
		})
	}))
	defer srv.Close()
	pointGrantClientAt(t, srv.URL)
	c := makeGrantClient(t)
	defer c.Close()

	_, err := c.MaybeAwaitGrant(context.Background(),
		approveDecision("delete_file"), GrantProtocolOpts{
			SleepFn: func(time.Duration) {},
		})
	if err == nil {
		t.Fatal("expected error on unknown status, got nil")
	}
	if !strings.Contains(err.Error(), "unknown status") {
		t.Errorf("err = %v, want unknown status marker", err)
	}
}

// -----------------------------------------------------------------------
// Verify the request headers + body shape so the backend contract is
// pinned.
// -----------------------------------------------------------------------

func TestRequestGrantWireShape(t *testing.T) {
	var got struct {
		method  string
		path    string
		auth    string
		idem    string
		ctype   string
		body    map[string]any
		count   int32
	}
	grantID := "grant-shape"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&got.count, 1)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			got.method = r.Method
			got.path = r.URL.Path
			got.auth = r.Header.Get("Authorization")
			got.idem = r.Header.Get("Idempotency-Key")
			got.ctype = r.Header.Get("Content-Type")
			_ = json.NewDecoder(r.Body).Decode(&got.body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"grant_id":   grantID,
				"expires_at": time.Now().UTC().Add(60 * time.Second).Format("2006-01-02T15:04:05Z"),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"grant_id": grantID, "status": "approved",
		})
	}))
	defer srv.Close()
	pointGrantClientAt(t, srv.URL)
	c := makeGrantClient(t)
	defer c.Close()

	outcome, err := c.MaybeAwaitGrant(context.Background(),
		approveDecision("delete_file"), GrantProtocolOpts{
			SleepFn: func(time.Duration) {},
		})
	if err != nil {
		t.Fatalf("MaybeAwaitGrant err = %v", err)
	}
	if outcome == nil || !outcome.Approved {
		t.Fatalf("outcome = %+v, want Approved", outcome)
	}
	if got.method != "POST" {
		t.Errorf("method = %s", got.method)
	}
	if got.path != "/api/grants" {
		t.Errorf("path = %s, want /api/grants", got.path)
	}
	if !strings.HasPrefix(got.auth, "Bearer cz_test_") {
		t.Errorf("auth = %q", got.auth)
	}
	if got.idem == "" || len(got.idem) != 36 {
		t.Errorf("Idempotency-Key = %q, want UUIDv4", got.idem)
	}
	if got.ctype != "application/json" {
		t.Errorf("Content-Type = %q", got.ctype)
	}
	if got.body["canonical_action"] != "delete_file" {
		t.Errorf("canonical_action = %v, want delete_file", got.body["canonical_action"])
	}
	if got.body["surface"] != "go-sdk" {
		t.Errorf("surface = %v, want go-sdk", got.body["surface"])
	}
}

// -----------------------------------------------------------------------
// Pure helper coverage -- timeout resolution + backoff schedule.
// -----------------------------------------------------------------------

func TestResolveGrantTimeoutSecs(t *testing.T) {
	prev, had := setEnvForTest(t, grantTimeoutEnvVar, "")
	defer restoreEnvForTest(grantTimeoutEnvVar, prev, had)

	if v := resolveGrantTimeoutSecs(GrantProtocolOpts{}); v != grantDefaultTimeoutSecs {
		t.Errorf("default = %d, want %d", v, grantDefaultTimeoutSecs)
	}
	if v := resolveGrantTimeoutSecs(GrantProtocolOpts{TimeoutSecs: 9999}); v != grantMaxTimeoutSecs {
		t.Errorf("over-cap = %d, want %d", v, grantMaxTimeoutSecs)
	}
	if v := resolveGrantTimeoutSecs(GrantProtocolOpts{TimeoutSecs: 42}); v != 42 {
		t.Errorf("explicit = %d, want 42", v)
	}

	setEnvForTest(t, grantTimeoutEnvVar, "120")
	if v := resolveGrantTimeoutSecs(GrantProtocolOpts{}); v != 120 {
		t.Errorf("env = %d, want 120", v)
	}
}

func TestNextGrantPollSecs(t *testing.T) {
	cases := []struct{ prev, want int }{
		{0, 1}, {1, 2}, {2, 4}, {4, 8}, {8, 10}, {10, 10},
	}
	for _, c := range cases {
		if got := nextGrantPollSecs(c.prev); got != c.want {
			t.Errorf("nextGrantPollSecs(%d) = %d, want %d", c.prev, got, c.want)
		}
	}
}

// setEnvForTest is a tiny env-helper kept local so the file does not
// reach into another test file's unexported helpers.
func setEnvForTest(t *testing.T, key, value string) (string, bool) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if value == "" {
		_ = os.Unsetenv(key)
	} else {
		_ = os.Setenv(key, value)
	}
	return prev, had
}

func restoreEnvForTest(key, prev string, had bool) {
	if had {
		_ = os.Setenv(key, prev)
	} else {
		_ = os.Unsetenv(key)
	}
}
