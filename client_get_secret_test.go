// HITL-6c Client.GetSecret tests. Mirror Python
// test_hitl_6a_get_secret_hitl.py 1:1.

package controlzero

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// allowDecision / denyDecision / hitlDecision helpers mirror the
// Python fixtures of the same name.
func allowDecision() *PolicyDecision {
	return &PolicyDecision{Effect: "allow", PolicyID: "test:allow", Reason: "ok", ReasonCode: "RULE_MATCH"}
}

func denyDecision() *PolicyDecision {
	return &PolicyDecision{Effect: "deny", PolicyID: "test:deny", Reason: "not allowed", ReasonCode: "RULE_MATCH"}
}

func hitlDecision() *PolicyDecision {
	return &PolicyDecision{Effect: "deny", PolicyID: "test:hitl", Reason: "needs approval", ReasonCode: "HITL_SDK_TIMEOUT"}
}

// secretsServer responds to GET /api/secrets/{name} and POST
// /api/approval-requests with the supplied handlers. Either handler
// may be nil to indicate "should not be called".
func secretsServer(t *testing.T, getHandler, postHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	if getHandler != nil {
		mux.Handle("/api/secrets/", getHandler)
	} else {
		mux.HandleFunc("/api/secrets/", func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected GET /api/secrets/* call")
			w.WriteHeader(500)
		})
	}
	if postHandler != nil {
		mux.Handle("/api/approval-requests", postHandler)
	} else {
		mux.HandleFunc("/api/approval-requests", func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected POST /api/approval-requests call")
			w.WriteHeader(500)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// -----------------------------------------------------------------------
// Allow path
// -----------------------------------------------------------------------

func TestGetSecretAllowFetchesAndReturnsValue(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	secretValue := "super-secret-value-12345"
	var gotURL string
	var gotAuth string
	srv := secretsServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			gotURL = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"value": secretValue})
		},
		nil,
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()

	value, err := c.GetSecret(context.Background(), "prod_api_key", GetSecretOpts{
		SkipGuard: true, Decision: allowDecision(),
	})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if value != secretValue {
		t.Errorf("value mismatch")
	}
	if gotURL != "/api/secrets/prod_api_key" {
		t.Errorf("URL = %q", gotURL)
	}
	if !strings.HasPrefix(gotAuth, "Bearer cz_test_") {
		t.Errorf("auth = %q", gotAuth)
	}
}

func TestGetSecretAllowPreservesCaseSensitiveName(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	var gotURL string
	srv := secretsServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			gotURL = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"value": "v"})
		},
		nil,
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()

	_, err := c.GetSecret(context.Background(), "PROD_Token_X", GetSecretOpts{
		SkipGuard: true, Decision: allowDecision(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(gotURL, "/api/secrets/PROD_Token_X") {
		t.Errorf("case-sensitive name not preserved: %q", gotURL)
	}
}

func TestGetSecretAllowUsesGuardWhenSkipFalse(t *testing.T) {
	// Without SkipGuard, the client should call c.Guard which returns
	// allow (trivial local policy). The HTTP GET should still happen.
	setFakeHomeAndEmail(t, "alice@example.com")
	called := atomic.Int32{}
	srv := secretsServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			called.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"value": "v"})
		},
		nil,
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	v, err := c.GetSecret(context.Background(), "name", GetSecretOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if v != "v" {
		t.Errorf("value = %q", v)
	}
	if called.Load() != 1 {
		t.Errorf("server called %d times, want 1", called.Load())
	}
}

// -----------------------------------------------------------------------
// HITL-required path
// -----------------------------------------------------------------------

func TestGetSecretHITLRequiredViaReasonCode(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	requestID := "req-uuid-1234"
	var postBody map[string]any
	srv := secretsServer(t, nil,
		func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &postBody)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"`+requestID+`","expires_at":"`+futureISO(60)+`"}`)
		},
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()

	_, err := c.GetSecret(context.Background(), "prod_api_key", GetSecretOpts{
		SkipGuard: true, Decision: hitlDecision(), TimeoutS: 120,
	})
	if err == nil {
		t.Fatal("expected SecretApprovalRequired")
	}
	var sar *SecretApprovalRequired
	if !errors.As(err, &sar) {
		t.Fatalf("expected *SecretApprovalRequired, got %T: %v", err, err)
	}
	if sar.ECode() != ECodeSecretApprovalRequired {
		t.Errorf("ECode = %q", sar.ECode())
	}
	if sar.Pending == nil || sar.Pending.RequestID != requestID {
		t.Errorf("Pending.RequestID = %v", sar.Pending)
	}
	if int(postBody["ttl_seconds"].(float64)) != 120 {
		t.Errorf("ttl_seconds wire = %v, want 120", postBody["ttl_seconds"])
	}
	if postBody["reason"] != "secret read" {
		t.Errorf("reason = %v, want \"secret read\"", postBody["reason"])
	}
	// errors.Is contract.
	if !errors.Is(err, ErrPolicyDenied) {
		t.Error("SecretApprovalRequired must satisfy errors.Is(err, ErrPolicyDenied)")
	}
}

func TestGetSecretHITLRequiredViaEffectString(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := secretsServer(t, nil,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"r","expires_at":"`+futureISO(60)+`"}`)
		},
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	d := &PolicyDecision{Effect: "hitl_required", PolicyID: "p", Reason: "future"}
	_, err := c.GetSecret(context.Background(), "prod_api_key", GetSecretOpts{
		SkipGuard: true, Decision: d,
	})
	var sar *SecretApprovalRequired
	if !errors.As(err, &sar) {
		t.Errorf("expected *SecretApprovalRequired, got %T: %v", err, err)
	}
}

func TestGetSecretCallerCanWaitOnPendingApproved(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := secretsServer(t, nil,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"r","expires_at":"`+futureISO(60)+`"}`)
		},
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "prod_api_key", GetSecretOpts{
		SkipGuard: true, Decision: hitlDecision(),
	})
	var sar *SecretApprovalRequired
	if !errors.As(err, &sar) {
		t.Fatal(err)
	}
	approved, err := sar.Pending.WaitInjected(
		func(rid string) (PollResponse, error) {
			return PollResponse{"id": rid, "state": "approved"}, nil
		},
		func(_ time.Duration) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != StatusApproved {
		t.Errorf("status = %q", approved.Status)
	}
}

func TestGetSecretCallerCanWaitOnPendingDenied(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := secretsServer(t, nil,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"r","expires_at":"`+futureISO(60)+`"}`)
		},
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "prod_api_key", GetSecretOpts{
		SkipGuard: true, Decision: hitlDecision(),
	})
	var sar *SecretApprovalRequired
	if !errors.As(err, &sar) {
		t.Fatal(err)
	}
	_, err = sar.Pending.WaitInjected(
		func(rid string) (PollResponse, error) {
			return PollResponse{"id": rid, "state": "denied"}, nil
		},
		func(_ time.Duration) {},
	)
	var pde *PolicyDeniedError
	if !errors.As(err, &pde) {
		t.Errorf("expected *PolicyDeniedError, got %T: %v", err, err)
	}
}

func TestGetSecretHITLPropagatesRequestApprovalError(t *testing.T) {
	// If POST returns 401, GetSecret should surface *HostedAuthError
	// (not SecretApprovalRequired) so the caller sees the underlying
	// transport error.
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := secretsServer(t, nil,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
		},
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "prod_api_key", GetSecretOpts{
		SkipGuard: true, Decision: hitlDecision(),
	})
	var ae *HostedAuthError
	if !errors.As(err, &ae) {
		t.Errorf("expected *HostedAuthError, got %T: %v", err, err)
	}
}

// -----------------------------------------------------------------------
// Static deny path
// -----------------------------------------------------------------------

func TestGetSecretStaticDenyRaisesPolicyDenied(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "name", GetSecretOpts{
		SkipGuard: true, Decision: denyDecision(),
	})
	var pde *PolicyDeniedError
	if !errors.As(err, &pde) {
		t.Errorf("expected *PolicyDeniedError, got %T: %v", err, err)
	}
	if pde.Decision.Effect != "deny" {
		t.Errorf("decision Effect = %q", pde.Decision.Effect)
	}
}

func TestGetSecretStaticDenyIsNotSecretApprovalRequired(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "name", GetSecretOpts{
		SkipGuard: true, Decision: denyDecision(),
	})
	var sar *SecretApprovalRequired
	if errors.As(err, &sar) {
		t.Errorf("static deny must not be *SecretApprovalRequired")
	}
}

// -----------------------------------------------------------------------
// Fetch-path errors
// -----------------------------------------------------------------------

func TestGetSecret404RaisesSecretNotFound(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := secretsServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"error":"not found"}`)
		},
		nil,
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "missing_secret", GetSecretOpts{
		SkipGuard: true, Decision: allowDecision(),
	})
	var snf *SecretNotFound
	if !errors.As(err, &snf) {
		t.Errorf("expected *SecretNotFound, got %T: %v", err, err)
	}
	if !strings.Contains(snf.Message, "missing_secret") {
		t.Errorf("name missing from message: %q", snf.Message)
	}
}

func TestGetSecret401RaisesHostedAuthError(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := secretsServer(t,
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) },
		nil,
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "name", GetSecretOpts{
		SkipGuard: true, Decision: allowDecision(),
	})
	var ae *HostedAuthError
	if !errors.As(err, &ae) {
		t.Errorf("expected *HostedAuthError, got %T: %v", err, err)
	}
}

func TestGetSecretNetworkErrorRaisesBackendUnreachable(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	setAPIURL(t, "http://127.0.0.1:1/no-server-here")
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "name", GetSecretOpts{
		SkipGuard: true, Decision: allowDecision(),
	})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) {
		t.Errorf("expected *HITLBackendUnreachableError, got %T: %v", err, err)
	}
}

func TestGetSecret500RaisesBackendUnreachable(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := secretsServer(t,
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		nil,
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "name", GetSecretOpts{
		SkipGuard: true, Decision: allowDecision(),
	})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(bu.Message, "500") {
		t.Errorf("expected 500 backend unreachable, got %v", err)
	}
}

func TestGetSecretNonJSONBodyRaisesBackendUnreachable(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := secretsServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "not-json")
		},
		nil,
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "name", GetSecretOpts{
		SkipGuard: true, Decision: allowDecision(),
	})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(bu.Message, "non-JSON") {
		t.Errorf("expected non-JSON error, got %v", err)
	}
}

func TestGetSecretMissingValueField(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := secretsServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "wrong_shape"})
		},
		nil,
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "name", GetSecretOpts{
		SkipGuard: true, Decision: allowDecision(),
	})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(strings.ToLower(bu.Message), "malformed") {
		t.Errorf("expected malformed error, got %v", err)
	}
}

func TestGetSecretNonStringValue(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := secretsServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"value": 12345})
		},
		nil,
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "name", GetSecretOpts{
		SkipGuard: true, Decision: allowDecision(),
	})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(bu.Message, "non-string") {
		t.Errorf("expected non-string error, got %v", err)
	}
}

// -----------------------------------------------------------------------
// Input validation + no api key
// -----------------------------------------------------------------------

func TestGetSecretEmptyNameRejected(t *testing.T) {
	c := makeAPIClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "", GetSecretOpts{})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestGetSecretNoAPIKeyOnAllowPath(t *testing.T) {
	c := makeNoKeyClient(t)
	defer c.Close()
	_, err := c.GetSecret(context.Background(), "name", GetSecretOpts{
		SkipGuard: true, Decision: allowDecision(),
	})
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) {
		t.Errorf("expected backend unreachable, got %T: %v", err, err)
	}
	if !strings.Contains(bu.Message, "API key") {
		t.Errorf("expected 'API key' in message: %q", bu.Message)
	}
}

func TestGetSecretNilContextDefaultsToBackground(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := secretsServer(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"value": "v"})
		},
		nil,
	)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	//nolint:staticcheck // testing nil ctx on purpose
	_, err := c.GetSecret(nil, "name", GetSecretOpts{
		SkipGuard: true, Decision: allowDecision(),
	})
	if err != nil {
		t.Errorf("nil ctx should fall back to Background, got %v", err)
	}
}

// -----------------------------------------------------------------------
// GetSecretPollFunc
// -----------------------------------------------------------------------

func TestGetSecretPollFuncReturnsBackendPayload(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"r-1","state":"approved"}`)
	}))
	t.Cleanup(srv.Close)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	poll, err := c.GetSecretPollFunc("r-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := poll("r-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp["state"] != "approved" {
		t.Errorf("state = %v", resp["state"])
	}
}

func TestGetSecretPollFuncNetworkErrorBackendUnreachable(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	setAPIURL(t, "http://127.0.0.1:1/none")
	c := makeAPIClient(t)
	defer c.Close()
	poll, err := c.GetSecretPollFunc("r-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = poll("r-1")
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) {
		t.Errorf("expected backend unreachable, got %T: %v", err, err)
	}
}

func TestGetSecretPollFuncNon2xxBackendUnreachable(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	t.Cleanup(srv.Close)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	poll, _ := c.GetSecretPollFunc("r-1", nil)
	_, err := poll("r-1")
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) || !strings.Contains(bu.Message, "500") {
		t.Errorf("expected 500, got %v", err)
	}
}

func TestGetSecretPollFuncNonJSONBodyBackendUnreachable(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "not-json")
	}))
	t.Cleanup(srv.Close)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	poll, _ := c.GetSecretPollFunc("r-1", nil)
	_, err := poll("r-1")
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) {
		t.Errorf("expected backend unreachable, got %v", err)
	}
}

func TestGetSecretPollFuncRequiresAPIKey(t *testing.T) {
	c := makeNoKeyClient(t)
	defer c.Close()
	_, err := c.GetSecretPollFunc("r-1", nil)
	var bu *HITLBackendUnreachableError
	if !errors.As(err, &bu) {
		t.Errorf("expected backend unreachable, got %T: %v", err, err)
	}
	if !strings.Contains(bu.Message, "API key") {
		t.Errorf("expected 'API key' in message: %q", bu.Message)
	}
}

func TestGetSecretPollFuncCustomHTTPClient(t *testing.T) {
	setFakeHomeAndEmail(t, "alice@example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"r-1","state":"pending"}`)
	}))
	t.Cleanup(srv.Close)
	setAPIURL(t, srv.URL)
	c := makeAPIClient(t)
	defer c.Close()
	called := atomic.Int32{}
	custom := &http.Client{Transport: &countingTransport{counter: &called, next: http.DefaultTransport}}
	poll, _ := c.GetSecretPollFunc("r-1", custom)
	_, err := poll("r-1")
	if err != nil {
		t.Fatal(err)
	}
	if called.Load() != 1 {
		t.Errorf("custom client unused: %d", called.Load())
	}
}

// -----------------------------------------------------------------------
// hasHITLReasonCode helper
// -----------------------------------------------------------------------

func TestHasHITLReasonCode(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"HITL_SDK_TIMEOUT", true},
		{"HITL_", true},
		{"HITLX_NO", false},
		{"RULE_MATCH", false},
		{"", false},
		{"HIT", false},
	}
	for _, c := range cases {
		if got := hasHITLReasonCode(c.in); got != c.want {
			t.Errorf("hasHITLReasonCode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
