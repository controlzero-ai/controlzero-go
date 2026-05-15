// Phase 6 Go SDK enrollment client tests.
//
// Mirrors the Python and Node test_enrollment coverage matrix:
//   - keypair generation produces a valid key
//   - private key save/load roundtrip preserves identity
//   - state save/load roundtrip preserves all fields
//   - sign_request canonical format matches the Go backend EXACTLY
//     (verified by re-deriving the canonical string and round-trip
//     verifying with the same public key)
//   - enroll happy path against an httptest server
//   - enroll 401 -> *TokenError
//   - enroll 503 -> *EnrollmentError mentioning FEATURE_DISABLED
//   - heartbeat sends signed request
//   - pull_policy with matching ETag returns nil
//   - pull_policy with stale ETag returns bundle and updates state
//   - send_audit_batch validates 1..500
//
// Test files in this package are exempt from the IP scrub rule
// (per scripts/ip-scrub-check.sh) so the algorithm name CAN appear
// here -- and SHOULD, because the canonical-string round-trip is
// the only thing protecting against silent client-server drift.

package controlzero

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- key + state I/O ----------------------------------------------------

func TestGenerateKeypair(t *testing.T) {
	priv, pemStr, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pemStr, "BEGIN PUBLIC KEY") {
		t.Errorf("PEM missing BEGIN PUBLIC KEY: %s", pemStr)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key wrong size: %d", len(priv))
	}
}

func TestSaveAndLoadPrivateKey_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SavePrivateKey(priv, dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Sign the same payload with both; signatures should be byte-equal
	// (Ed25519 is deterministic).
	payload := []byte("hello-world")
	sigA := ed25519.Sign(priv, payload)
	sigB := ed25519.Sign(loaded, payload)
	if !equalBytes(sigA, sigB) {
		t.Errorf("save/load roundtrip didn't preserve key")
	}
}

func TestLoadPrivateKey_MissingReturnsNotEnrolledError(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadPrivateKey(dir)
	var nee *NotEnrolledError
	if err == nil {
		t.Fatal("expected error")
	}
	if !errorsAs(err, &nee) {
		t.Errorf("expected NotEnrolledError, got %T: %v", err, err)
	}
}

func TestSaveAndLoadState_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	state := &EnrollmentState{
		MachineID:        "ba0d16ee-0580-49e5-a791-2c2cccedb13e",
		OrgID:            "b4fdd5e2-292f-403b-96e8-ab9f2fb91788",
		APIURL:           "https://api.example.com",
		Hostname:         "dev-laptop",
		FingerprintHint:  "abc123",
		MachinePubkeyPEM: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
		EnrolledAt:       "2026-04-08T10:50:42Z",
		PolicyVersion:    3,
		PluginVersions:   map[string]string{"sdk": "0.2.0"},
	}
	if _, err := SaveState(state, dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil state")
	}
	if loaded.MachineID != state.MachineID {
		t.Errorf("machine_id mismatch")
	}
	if loaded.PolicyVersion != 3 {
		t.Errorf("policy_version mismatch: %d", loaded.PolicyVersion)
	}
}

func TestLoadState_MissingReturnsNil(t *testing.T) {
	dir := t.TempDir()
	state, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if state != nil {
		t.Errorf("expected nil, got %+v", state)
	}
}

// --- sign_request canonical format -------------------------------------

func TestSignRequest_CanonicalFormatMatchesBackend(t *testing.T) {
	// Critical drift-detection test. If this ever fails, the Go SDK
	// signs requests in a way the backend won't accept and every
	// /api/heartbeat call returns 401 INVALID_SIGNATURE in production.
	dir := t.TempDir()
	priv, pubPEM, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SavePrivateKey(priv, dir); err != nil {
		t.Fatal(err)
	}

	state := &EnrollmentState{
		MachineID:        "ba0d16ee-0580-49e5-a791-2c2cccedb13e",
		OrgID:            "b4fdd5e2-292f-403b-96e8-ab9f2fb91788",
		APIURL:           "https://api.example.com",
		Hostname:         "dev-laptop",
		FingerprintHint:  "abc",
		MachinePubkeyPEM: pubPEM,
		EnrolledAt:       "2026-04-08T10:50:42Z",
	}

	body := []byte(`{"hello":"world"}`)
	headers, err := SignRequest(state, "POST", "/api/heartbeat", body, dir, 1712572800)
	if err != nil {
		t.Fatal(err)
	}

	if headers["X-CZ-Machine-ID"] != state.MachineID {
		t.Error("machine_id header wrong")
	}
	if headers["X-CZ-Timestamp"] != "1712572800" {
		t.Errorf("timestamp wrong: %s", headers["X-CZ-Timestamp"])
	}

	// Reconstruct canonical + verify with the public key
	bodyHash := sha256.Sum256(body)
	canonical := fmt.Sprintf("%s\n1712572800\nPOST\n/api/heartbeat\n%s",
		state.MachineID, hex.EncodeToString(bodyHash[:]))

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatal("decode pub PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub := pubAny.(ed25519.PublicKey)
	sig, _ := base64.StdEncoding.DecodeString(headers["X-CZ-Signature"])
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		t.Error("signature did NOT verify with the same public key -- canonical drift")
	}
}

func TestSignRequest_EmptyBody(t *testing.T) {
	dir := t.TempDir()
	priv, pubPEM, _ := GenerateKeypair()
	_, _ = SavePrivateKey(priv, dir)
	state := &EnrollmentState{
		MachineID:        "m1",
		MachinePubkeyPEM: pubPEM,
	}
	headers, err := SignRequest(state, "GET", "/api/policy", nil, dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if headers["X-CZ-Signature"] == "" {
		t.Error("signature header missing")
	}
}

func TestSignRequest_NotEnrolledRaises(t *testing.T) {
	state := &EnrollmentState{}
	_, err := SignRequest(state, "GET", "/api/policy", nil, "", 0)
	var nee *NotEnrolledError
	if !errorsAs(err, &nee) {
		t.Errorf("expected NotEnrolledError, got %T", err)
	}
}

// --- compute_fingerprint ------------------------------------------------

func TestComputeFingerprint_Stable(t *testing.T) {
	a := ComputeFingerprint()
	b := ComputeFingerprint()
	if a != b {
		t.Errorf("fingerprint not stable: %s != %s", a, b)
	}
	if len(a) != 32 {
		t.Errorf("fingerprint should be 32 chars, got %d", len(a))
	}
}

// --- enroll() -----------------------------------------------------------

func newServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func TestEnroll_HappyPath(t *testing.T) {
	dir := t.TempDir()

	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/enroll" {
			t.Errorf("wrong path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"machine_id":     "ba0d16ee-0580-49e5-a791-2c2cccedb13e",
			"org_id":         "b4fdd5e2-292f-403b-96e8-ab9f2fb91788",
			"enrolled_at":    "2026-04-08T10:50:42Z",
			"policy_version": 0,
		})
	})
	defer srv.Close()

	state, err := Enroll(context.Background(), EnrollOptions{
		APIURL:   srv.URL,
		Token:    "cz_enroll_test",
		StateDir: dir,
	})
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}
	if state.MachineID != "ba0d16ee-0580-49e5-a791-2c2cccedb13e" {
		t.Errorf("wrong machine_id: %s", state.MachineID)
	}
	if _, err := LoadState(dir); err != nil {
		t.Errorf("state file not loadable: %v", err)
	}
	// Private key file exists
	if _, err := io.ReadAll(mustOpen(t, filepath.Join(dir, "machine.key"))); err != nil {
		t.Errorf("private key file missing: %v", err)
	}
}

func TestEnroll_TokenRejected(t *testing.T) {
	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"INVALID_TOKEN","message":"not found"}}`))
	})
	defer srv.Close()

	_, err := Enroll(context.Background(), EnrollOptions{
		APIURL: srv.URL, Token: "bad", StateDir: t.TempDir(),
	})
	var te *TokenError
	if !errorsAs(err, &te) {
		t.Errorf("expected *TokenError, got %T: %v", err, err)
	}
}

func TestEnroll_FeatureDisabled(t *testing.T) {
	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"FEATURE_DISABLED","message":"disabled"}`))
	})
	defer srv.Close()

	_, err := Enroll(context.Background(), EnrollOptions{
		APIURL: srv.URL, Token: "any", StateDir: t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "FEATURE_DISABLED") {
		t.Errorf("expected FEATURE_DISABLED error, got: %v", err)
	}
}

func TestEnroll_MissingToken(t *testing.T) {
	_, err := Enroll(context.Background(), EnrollOptions{APIURL: "https://x"})
	var te *TokenError
	if !errorsAs(err, &te) {
		t.Errorf("expected *TokenError, got %T", err)
	}
}

// --- heartbeat ----------------------------------------------------------

func TestHeartbeat_SignedRequest(t *testing.T) {
	dir := t.TempDir()
	enrollSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"machine_id":"m1","org_id":"o1","enrolled_at":"x","policy_version":0}`))
	})
	defer enrollSrv.Close()

	state, err := Enroll(context.Background(), EnrollOptions{
		APIURL: enrollSrv.URL, Token: "t", StateDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}

	hbSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		// Verify the signature headers are present
		if r.Header.Get("X-CZ-Machine-ID") != "m1" {
			t.Errorf("wrong X-CZ-Machine-ID: %s", r.Header.Get("X-CZ-Machine-ID"))
		}
		if r.Header.Get("X-CZ-Signature") == "" {
			t.Error("missing X-CZ-Signature")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"server_time":"2026-04-08T10:01:00Z","policy_version":5}`))
	})
	defer hbSrv.Close()

	state.APIURL = hbSrv.URL
	resp, err := Heartbeat(context.Background(), state, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.PolicyVersion != 5 {
		t.Errorf("policy_version: %d", resp.PolicyVersion)
	}
}

func TestHeartbeat_NotEnrolled(t *testing.T) {
	_, err := Heartbeat(context.Background(), nil, t.TempDir(), nil)
	var nee *NotEnrolledError
	if !errorsAs(err, &nee) {
		t.Errorf("expected NotEnrolledError, got %T", err)
	}
}

// --- pull_policy --------------------------------------------------------

func TestPullPolicy_NotModifiedReturnsNil(t *testing.T) {
	dir := t.TempDir()
	enrollSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"machine_id":"m1","org_id":"o1","enrolled_at":"x","policy_version":3}`))
	})
	defer enrollSrv.Close()

	state, _ := Enroll(context.Background(), EnrollOptions{
		APIURL: enrollSrv.URL, Token: "t", StateDir: dir,
	})

	pullSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		// Verify If-None-Match was sent with the cached version
		if r.Header.Get("If-None-Match") != `"3"` {
			t.Errorf("wrong If-None-Match: %s", r.Header.Get("If-None-Match"))
		}
		w.WriteHeader(http.StatusNotModified)
	})
	defer pullSrv.Close()

	state.APIURL = pullSrv.URL
	bundle, err := PullPolicy(context.Background(), state, dir)
	if err != nil {
		t.Fatal(err)
	}
	if bundle != nil {
		t.Errorf("expected nil bundle on 304, got %+v", bundle)
	}
}

func TestPullPolicy_StaleETagUpdatesState(t *testing.T) {
	dir := t.TempDir()
	enrollSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"machine_id":"m1","org_id":"o1","enrolled_at":"x","policy_version":2}`))
	})
	defer enrollSrv.Close()

	state, _ := Enroll(context.Background(), EnrollOptions{
		APIURL: enrollSrv.URL, Token: "t", StateDir: dir,
	})

	pullSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"policy_version":5,"rules":[{"id":"r1","name":"ssn","pattern":"\\d{3}","category":"pii","action":"block","scopes":["sdk"]}]}`))
	})
	defer pullSrv.Close()

	state.APIURL = pullSrv.URL
	bundle, err := PullPolicy(context.Background(), state, dir)
	if err != nil {
		t.Fatal(err)
	}
	if bundle == nil {
		t.Fatal("bundle nil")
	}
	if bundle.PolicyVersion != 5 {
		t.Errorf("policy_version: %d", bundle.PolicyVersion)
	}
	// State file should be updated
	reloaded, _ := LoadState(dir)
	if reloaded.PolicyVersion != 5 {
		t.Errorf("state file not updated: %d", reloaded.PolicyVersion)
	}
}

// --- send_audit_batch ---------------------------------------------------

func TestSendAuditBatch_Validates(t *testing.T) {
	state := &EnrollmentState{MachineID: "m"}
	if _, err := SendAuditBatch(context.Background(), state, "", nil); err == nil {
		t.Error("expected error for empty entries")
	}
	too := make([]AuditEntry, 501)
	if _, err := SendAuditBatch(context.Background(), state, "", too); err == nil {
		t.Error("expected error for >500 entries")
	}
}

func TestSendAuditBatch_HappyPath(t *testing.T) {
	dir := t.TempDir()
	enrollSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"machine_id":"m1","org_id":"o1","enrolled_at":"x","policy_version":0}`))
	})
	defer enrollSrv.Close()
	state, _ := Enroll(context.Background(), EnrollOptions{
		APIURL: enrollSrv.URL, Token: "t", StateDir: dir,
	})

	auditSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CZ-Signature") == "" {
			t.Error("missing X-CZ-Signature")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":2,"dropped":0}`))
	})
	defer auditSrv.Close()

	state.APIURL = auditSrv.URL
	resp, err := SendAuditBatch(context.Background(), state, dir, []AuditEntry{
		{ID: "e1", ToolName: "bash", Decision: "allow"},
		{ID: "e2", ToolName: "read", Decision: "deny"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Accepted != 2 || resp.Dropped != 0 {
		t.Errorf("wrong counts: %+v", resp)
	}
}

// --- helpers ------------------------------------------------------------

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// errorsAs is a tiny shim around errors.As so each call site reads
// cleanly without polluting test scope.
func errorsAs(err error, target interface{}) bool {
	return stderrors.As(err, target)
}

// mustOpen is a tiny test helper that fails the test on error.
func mustOpen(t *testing.T, path string) io.Reader {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// --- WS1: org signing pubkey + bundle signature verification -----------

func TestEnroll_PersistsOrgSigningPubkey(t *testing.T) {
	dir := t.TempDir()

	// Generate an org signing keypair on the "server"
	orgPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(orgPub)
	orgPubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"machine_id":        "m1",
			"org_id":            "o1",
			"enrolled_at":       "2026-04-12T00:00:00Z",
			"policy_version":    0,
			"org_signing_pubkey": orgPubPEM,
		})
	})
	defer srv.Close()

	state, err := Enroll(context.Background(), EnrollOptions{
		APIURL: srv.URL, Token: "tok", StateDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.OrgSigningPubkeyPEM != orgPubPEM {
		t.Errorf("org pubkey not stored: %q", state.OrgSigningPubkeyPEM)
	}

	reloaded, _ := LoadState(dir)
	if reloaded.OrgSigningPubkeyPEM != orgPubPEM {
		t.Errorf("org pubkey not persisted: %q", reloaded.OrgSigningPubkeyPEM)
	}
}

func TestEnroll_OrgSigningPubkeyDefaultsEmpty(t *testing.T) {
	dir := t.TempDir()
	srv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"machine_id":"m1","org_id":"o1","enrolled_at":"x","policy_version":0}`))
	})
	defer srv.Close()

	state, err := Enroll(context.Background(), EnrollOptions{
		APIURL: srv.URL, Token: "tok", StateDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.OrgSigningPubkeyPEM != "" {
		t.Errorf("expected empty org pubkey, got %q", state.OrgSigningPubkeyPEM)
	}
}

func TestPullPolicy_VerifiesValidSignature(t *testing.T) {
	dir := t.TempDir()
	orgPub, orgPriv, _ := ed25519.GenerateKey(nil)
	der, _ := x509.MarshalPKIXPublicKey(orgPub)
	orgPubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	// Enroll with org pubkey
	enrollSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"machine_id":        "m1",
			"org_id":            "o1",
			"enrolled_at":       "x",
			"policy_version":    0,
			"org_signing_pubkey": orgPubPEM,
		})
	})
	defer enrollSrv.Close()

	state, _ := Enroll(context.Background(), EnrollOptions{
		APIURL: enrollSrv.URL, Token: "t", StateDir: dir,
	})

	// Signed policy pull
	bundleJSON := []byte(`{"policy_version":1,"rules":[]}`)
	sig := ed25519.Sign(orgPriv, bundleJSON)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	pullSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Policy-Signature", sigB64)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundleJSON)
	})
	defer pullSrv.Close()

	state.APIURL = pullSrv.URL
	bundle, err := PullPolicy(context.Background(), state, dir)
	if err != nil {
		t.Fatalf("pull_policy failed: %v", err)
	}
	if bundle == nil {
		t.Fatal("bundle nil")
	}
	if bundle.PolicyVersion != 1 {
		t.Errorf("policy_version: %d", bundle.PolicyVersion)
	}
}

func TestPullPolicy_RejectsInvalidSignature(t *testing.T) {
	dir := t.TempDir()
	orgPub, _, _ := ed25519.GenerateKey(nil)
	der, _ := x509.MarshalPKIXPublicKey(orgPub)
	orgPubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	// Enroll with org pubkey
	enrollSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"machine_id":        "m1",
			"org_id":            "o1",
			"enrolled_at":       "x",
			"policy_version":    0,
			"org_signing_pubkey": orgPubPEM,
		})
	})
	defer enrollSrv.Close()

	state, _ := Enroll(context.Background(), EnrollOptions{
		APIURL: enrollSrv.URL, Token: "t", StateDir: dir,
	})

	// Sign with a WRONG key
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	bundleJSON := []byte(`{"policy_version":1,"rules":[]}`)
	badSig := ed25519.Sign(wrongPriv, bundleJSON)
	badSigB64 := base64.StdEncoding.EncodeToString(badSig)

	pullSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Policy-Signature", badSigB64)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundleJSON)
	})
	defer pullSrv.Close()

	state.APIURL = pullSrv.URL
	_, err := PullPolicy(context.Background(), state, dir)
	if err == nil {
		t.Fatal("expected error on bad signature")
	}
	if !stderrors.Is(err, ErrBundleSignatureInvalid) {
		t.Errorf("expected ErrBundleSignatureInvalid, got: %v", err)
	}
}

func TestPullPolicy_BackwardCompat_NoKeyNoSig(t *testing.T) {
	dir := t.TempDir()
	// Enroll WITHOUT org pubkey
	enrollSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"machine_id":"m1","org_id":"o1","enrolled_at":"x","policy_version":0}`))
	})
	defer enrollSrv.Close()

	state, _ := Enroll(context.Background(), EnrollOptions{
		APIURL: enrollSrv.URL, Token: "t", StateDir: dir,
	})

	pullSrv := newServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"policy_version":1,"rules":[]}`))
	})
	defer pullSrv.Close()

	state.APIURL = pullSrv.URL
	bundle, err := PullPolicy(context.Background(), state, dir)
	if err != nil {
		t.Fatal(err)
	}
	if bundle == nil {
		t.Fatal("bundle nil")
	}
	if bundle.PolicyVersion != 1 {
		t.Errorf("policy_version: %d", bundle.PolicyVersion)
	}
}
