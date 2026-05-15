// End-to-end hosted-mode test against an in-process mock backend.
//
// Spins up a tiny HTTP server that serves valid /v1/sdk/bootstrap and
// /v1/sdk/policies/pull responses with a bundle built using the exact
// wire format from the spec. Verifies:
//
//   - New(WithAPIKey) pulls, verifies, decrypts, enforces.
//   - Guard returns correct allow/deny per the policy.
//   - Audit entries posted to /v1/sdk/audit.
//   - Second construction uses cached bundle (304 path).
//   - Invalid API key surfaces HostedAuthError.
package controlzero_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	controlzero "controlzero.ai/sdk/go"
	"github.com/klauspost/compress/zstd"
)

type mockBackend struct {
	server   *httptest.Server
	audits   []map[string]any
	auditsMu sync.Mutex
}

func (m *mockBackend) snapshotAudits() []map[string]any {
	m.auditsMu.Lock()
	defer m.auditsMu.Unlock()
	out := make([]map[string]any, len(m.audits))
	copy(out, m.audits)
	return out
}

func newMockBackend(t *testing.T) *mockBackend {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatal(err)
	}

	// Build a signed bundle matching the backend wire format.
	payload, _ := json.Marshal(map[string]any{
		"schema_version": "1.0",
		"bundle_id":      "v1",
		"project_id":     "test-project",
		"policies": []any{
			map[string]any{
				"id":       "p1",
				"name":     "Demo",
				"priority": 10,
				"rules": []any{
					map[string]any{"effect": "deny", "tool": "send_email", "reason": "blocked"},
					map[string]any{"effect": "allow", "tool": "*"},
				},
			},
		},
	})

	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	compressed := enc.EncodeAll(payload, nil)
	enc.Close()

	block, _ := aes.NewCipher(encKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	ct := gcm.Seal(nonce, nonce, compressed, nil)

	header := make([]byte, 32)
	copy(header[0:4], []byte("CZ01"))
	binary.LittleEndian.PutUint16(header[4:6], 1)
	binary.LittleEndian.PutUint64(header[6:14], 1700000000)
	binary.LittleEndian.PutUint16(header[14:16], 1)
	binary.LittleEndian.PutUint32(header[16:20], uint32(32+len(ct)))
	binary.LittleEndian.PutUint32(header[20:24], 64)
	toSign := append([]byte{}, header...)
	toSign = append(toSign, ct...)
	sig := ed25519.Sign(priv, toSign)
	bundle := append(toSign, sig...)

	bootstrapResp, _ := json.Marshal(map[string]any{
		"project_id":                 "test-project",
		"org_id":                     "test-org",
		"project_encryption_key_b64": base64.StdEncoding.EncodeToString(encKey),
		"signing_pubkey_hex":         hex.EncodeToString(pub),
		"signing_pubkey_pem":         "",
		"key_version":                1,
		"algorithm":                  "ed25519",
	})

	m := &mockBackend{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sdk/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer cz_") {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(bootstrapResp)
	})
	mux.HandleFunc("/v1/sdk/policies/pull", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer cz_") {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(bundle)
	})
	mux.HandleFunc("/v1/sdk/audit", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer cz_") {
			w.WriteHeader(401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var parsed struct {
			Entries []map[string]any `json:"entries"`
		}
		if err := json.Unmarshal(body, &parsed); err == nil {
			m.auditsMu.Lock()
			m.audits = append(m.audits, parsed.Entries...)
			m.auditsMu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"accepted":1,"dropped":0}`))
	})

	m.server = httptest.NewServer(mux)
	return m
}

func (m *mockBackend) close() {
	m.server.Close()
}

func setupHosted(t *testing.T) *mockBackend {
	t.Helper()
	m := newMockBackend(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CONTROLZERO_API_URL", m.server.URL)
	t.Cleanup(m.close)
	return m
}

func TestHostedE2E_Allow(t *testing.T) {
	setupHosted(t)
	cz, err := controlzero.New(controlzero.WithAPIKey("cz_live_e2e_test"))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer cz.Close()
	d, _ := cz.Guard("web_search", controlzero.GuardOptions{Args: map[string]any{"q": "x"}})
	if d.Effect != "allow" {
		t.Errorf("want allow, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestHostedE2E_Deny(t *testing.T) {
	setupHosted(t)
	cz, err := controlzero.New(controlzero.WithAPIKey("cz_live_e2e_test"))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer cz.Close()
	d, _ := cz.Guard("send_email", controlzero.GuardOptions{Args: map[string]any{"body": "x"}})
	if d.Effect != "deny" {
		t.Errorf("want deny, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestHostedE2E_AuditPushed(t *testing.T) {
	m := setupHosted(t)
	cz, err := controlzero.New(controlzero.WithAPIKey("cz_live_e2e_test"))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	cz.Guard("web_search", controlzero.GuardOptions{})
	cz.Guard("send_email", controlzero.GuardOptions{})
	cz.Close() // flushes synchronously

	// Wait up to 2s for audits to arrive (HTTP posting is async).
	deadline := time.Now().Add(2 * time.Second)
	var audits []map[string]any
	for time.Now().Before(deadline) {
		audits = m.snapshotAudits()
		if len(audits) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(audits) < 2 {
		t.Fatalf("want >= 2 audits, got %d", len(audits))
	}
	var hasWebSearch, hasSendEmail bool
	for _, a := range audits {
		if a["tool_name"] == "web_search" {
			hasWebSearch = true
		}
		if a["tool_name"] == "send_email" {
			hasSendEmail = true
		}
		if a["mode"] != "hosted" {
			t.Errorf("expected mode=hosted, got %v", a["mode"])
		}
	}
	if !hasWebSearch || !hasSendEmail {
		t.Errorf("missing audit entries: web_search=%v send_email=%v", hasWebSearch, hasSendEmail)
	}
}

func TestHostedE2E_SecondRunUsesCache(t *testing.T) {
	setupHosted(t)
	c1, err := controlzero.New(controlzero.WithAPIKey("cz_live_e2e_test"))
	if err != nil {
		t.Fatal(err)
	}
	c1.Close()

	c2, err := controlzero.New(controlzero.WithAPIKey("cz_live_e2e_test"))
	if err != nil {
		t.Fatalf("second construction failed: %v", err)
	}
	defer c2.Close()
	d, _ := c2.Guard("send_email", controlzero.GuardOptions{})
	if d.Effect != "deny" {
		t.Errorf("want deny from cached bundle, got %s", d.Effect)
	}
}

func TestHostedE2E_InvalidKeyFailsFast(t *testing.T) {
	setupHosted(t)
	_, err := controlzero.New(controlzero.WithAPIKey("not_a_real_key_prefix"))
	if err == nil {
		t.Fatal("expected HostedAuthError for invalid key")
	}
	var ae *controlzero.HostedAuthError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *HostedAuthError, got %T: %v", err, err)
	}
}
