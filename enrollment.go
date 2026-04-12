// Phase 6: Go SDK enrollment client. Counterpart to the Python and
// Node clients. Wire-format and on-disk layout match the other two
// SDKs exactly so a machine enrolled with one client can be used
// by the others. Uses Go stdlib only -- no new dependencies.
//
// Wire-format reference:
//
//	apps/control-zero-platform/backend/internal/api/middleware/machine_auth.go

package controlzero

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors.
var ErrBundleSignatureInvalid = errors.New("policy bundle signature verification failed")

// On-disk layout (must match Python + Node SDKs).
const (
	stateFileName     = "enrollment.json"
	privKeyFileName   = "machine.key"
	defaultStateDirEv = "CONTROLZERO_STATE_DIR"
)

// EnrollmentState is everything the SDK needs to authenticate signed
// requests after a successful enroll round-trip.
type EnrollmentState struct {
	MachineID            string            `json:"machine_id"`
	OrgID                string            `json:"org_id"`
	APIURL               string            `json:"api_url"`
	Hostname             string            `json:"hostname"`
	FingerprintHint      string            `json:"fingerprint_hint"`
	MachinePubkeyPEM     string            `json:"machine_pubkey_pem"`
	EnrolledAt           string            `json:"enrolled_at"`
	PolicyVersion        int               `json:"policy_version"`
	TamperBehavior       string            `json:"tamper_behavior"`
	OrgSigningPubkeyPEM  string            `json:"org_signing_pubkey_pem"`
	PluginVersions       map[string]string `json:"plugin_versions"`
}

// EnrollOptions is the input to Enroll.
type EnrollOptions struct {
	APIURL          string
	Token           string
	Hostname        string            // optional override
	FingerprintHint string            // optional override
	PluginVersions  map[string]string // optional override
	StateDir        string            // optional override (default: ~/.controlzero)
	UserEmail       string            // optional
	Timeout         time.Duration     // optional, default 30s
}

// PolicyBundle is the SDK projection returned by GET /api/policy.
type PolicyBundle struct {
	PolicyVersion int          `json:"policy_version"`
	Rules         []EnrollmentPolicyRule `json:"rules"`
}

// EnrollmentPolicyRule is one entry inside a PolicyBundle. Slim projection of
// the admin DLPRule shape -- no lifecycle / approver fields.
type EnrollmentPolicyRule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Pattern  string   `json:"pattern"`
	Category string   `json:"category"`
	Action   string   `json:"action"`
	Scopes   []string `json:"scopes"`
}

// AuditEntry is one decision record streamed via /api/audit.
type AuditEntry struct {
	ID             string `json:"id"`
	User           string `json:"user,omitempty"`
	ToolName       string `json:"tool_name"`
	Decision       string `json:"decision"`
	PolicyID       string `json:"policy_id,omitempty"`
	RuleID         string `json:"rule_id,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Ts             string `json:"ts,omitempty"`
	VerbosityLevel string `json:"verbosity_level,omitempty"`
}

// EnrollmentError is the typed error for everything in this file.
type EnrollmentError struct{ Msg string }

func (e *EnrollmentError) Error() string { return e.Msg }

// TokenError is a more specific subtype for enroll-token rejections.
type TokenError struct{ Msg string }

func (e *TokenError) Error() string { return e.Msg }

// NotEnrolledError fires when a method that needs local state is
// called before Enroll has run successfully.
type NotEnrolledError struct{ Msg string }

func (e *NotEnrolledError) Error() string { return e.Msg }

// DefaultStateDir returns ~/.controlzero (or the override env var).
func DefaultStateDir() string {
	if v := os.Getenv(defaultStateDirEv); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".controlzero"
	}
	return filepath.Join(home, ".controlzero")
}

// ComputeFingerprint returns a stable 32-char hex hash of host
// attributes. Re-running enroll on the same machine converges on
// the same fingerprint, which lets the backend's
// UNIQUE(org_id, fingerprint_hint) upsert return the existing
// machine_id rather than minting a new one.
func ComputeFingerprint() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	parts := []string{
		hostname,
		runtime.GOOS,
		runtime.GOARCH,
		filepath.Join(DefaultStateDir()),
	}
	h := sha256.New()
	h.Write([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// GenerateKeypair mints a fresh signing keypair and returns the
// private key bytes plus the PEM-encoded public key suitable for
// the /api/enroll machine_pubkey field.
func GenerateKeypair() (ed25519.PrivateKey, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, string(pemBytes), nil
}

// SavePrivateKey writes the private key to <stateDir>/machine.key
// with mode 0600 via an atomic tmp + rename.
func SavePrivateKey(priv ed25519.PrivateKey, stateDir string) (string, error) {
	if err := ensureStateDir(stateDir); err != nil {
		return "", err
	}
	path := filepath.Join(stateDir, privKeyFileName)
	tmp := path + ".tmp"

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(tmp, pemBytes, 0o600); err != nil {
		return "", fmt.Errorf("write tmp private key: %w", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("rename private key: %w", err)
	}
	return path, nil
}

// LoadPrivateKey reads the private key from <stateDir>/machine.key.
func LoadPrivateKey(stateDir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(stateDir, privKeyFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, &NotEnrolledError{Msg: fmt.Sprintf("private key not found at %s; run `controlzero enroll` first", path)}
		}
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &EnrollmentError{Msg: "no PEM block in private key file"}
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, &EnrollmentError{Msg: fmt.Sprintf("parse private key: %v", err)}
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, &EnrollmentError{Msg: fmt.Sprintf("private key at %s is not a supported signing key", path)}
	}
	return priv, nil
}

// SaveState persists the enrollment state to <stateDir>/enrollment.json.
func SaveState(state *EnrollmentState, stateDir string) (string, error) {
	if err := ensureStateDir(stateDir); err != nil {
		return "", err
	}
	path := filepath.Join(stateDir, stateFileName)
	tmp := path + ".tmp"
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return "", err
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

// LoadState reads the persisted enrollment state. Returns (nil, nil)
// when no state file exists (i.e. machine not yet enrolled).
func LoadState(stateDir string) (*EnrollmentState, error) {
	path := filepath.Join(stateDir, stateFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var s EnrollmentState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Enroll runs the round-trip and persists state + private key.
// Idempotent on the same machine because the backend dedups by
// (org_id, fingerprint_hint).
func Enroll(ctx context.Context, opts EnrollOptions) (*EnrollmentState, error) {
	if opts.Token == "" {
		return nil, &TokenError{Msg: "token is required"}
	}
	if opts.APIURL == "" {
		return nil, &EnrollmentError{Msg: "api_url is required"}
	}
	apiURL := strings.TrimRight(opts.APIURL, "/")
	stateDir := opts.StateDir
	if stateDir == "" {
		stateDir = DefaultStateDir()
	}
	hostname := opts.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if hostname == "" {
		hostname = "unknown"
	}
	fp := opts.FingerprintHint
	if fp == "" {
		fp = ComputeFingerprint()
	}
	pluginVersions := opts.PluginVersions
	if pluginVersions == nil {
		pluginVersions = map[string]string{"sdk": "go-sdk"}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	priv, pubPEM, err := GenerateKeypair()
	if err != nil {
		return nil, &EnrollmentError{Msg: fmt.Sprintf("generate keypair: %v", err)}
	}

	payload := map[string]interface{}{
		"token":            opts.Token,
		"fingerprint_hint": fp,
		"hostname":         hostname,
		"os":               runtime.GOOS + " " + runtime.GOARCH,
		"user_email":       opts.UserEmail,
		"plugin_versions":  pluginVersions,
		"machine_pubkey":   pubPEM,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, &EnrollmentError{Msg: fmt.Sprintf("marshal enroll payload: %v", err)}
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "POST", apiURL+"/api/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, &EnrollmentError{Msg: fmt.Sprintf("build request: %v", err)}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, &EnrollmentError{Msg: fmt.Sprintf("network error during enroll: %v", err)}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusCreated:
		// fallthrough below
	case http.StatusUnauthorized:
		return nil, &TokenError{Msg: extractError(respBody, "token rejected by server")}
	case http.StatusServiceUnavailable:
		return nil, &EnrollmentError{Msg: "server returned 503 FEATURE_DISABLED -- the enrollment API is currently disabled by the operator. Ask your admin to set ENROLLMENT_API_ENABLED=true."}
	default:
		return nil, &EnrollmentError{Msg: fmt.Sprintf("enroll failed: HTTP %d: %s", resp.StatusCode, extractError(respBody, string(respBody)))}
	}

	var parsed struct {
		MachineID          string `json:"machine_id"`
		OrgID              string `json:"org_id"`
		EnrolledAt         string `json:"enrolled_at"`
		PolicyVersion      int    `json:"policy_version"`
		TamperBehavior     string `json:"tamper_behavior"`
		OrgSigningPubkey   string `json:"org_signing_pubkey"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, &EnrollmentError{Msg: fmt.Sprintf("parse enroll response: %v", err)}
	}

	state := &EnrollmentState{
		MachineID:           parsed.MachineID,
		OrgID:               parsed.OrgID,
		APIURL:              apiURL,
		Hostname:            hostname,
		FingerprintHint:     fp,
		MachinePubkeyPEM:    pubPEM,
		EnrolledAt:          parsed.EnrolledAt,
		PolicyVersion:       parsed.PolicyVersion,
		TamperBehavior:      parsed.TamperBehavior,
		OrgSigningPubkeyPEM: parsed.OrgSigningPubkey,
		PluginVersions:      pluginVersions,
	}
	if _, err := SavePrivateKey(priv, stateDir); err != nil {
		return nil, err
	}
	if _, err := SaveState(state, stateDir); err != nil {
		return nil, err
	}
	return state, nil
}

// SignRequest builds the X-CZ-* headers for a signed machine
// request. Canonical signed string format matches the backend exactly:
//
//	machine_id + "\n" + ts + "\n" + METHOD + "\n" + path + "\n" + sha256_hex(body)
func SignRequest(state *EnrollmentState, method, path string, body []byte, stateDir string, now int64) (map[string]string, error) {
	if state == nil || state.MachineID == "" {
		return nil, &NotEnrolledError{Msg: "no enrollment state -- run `controlzero enroll` first"}
	}
	if stateDir == "" {
		stateDir = DefaultStateDir()
	}
	priv, err := LoadPrivateKey(stateDir)
	if err != nil {
		return nil, err
	}
	if now == 0 {
		now = time.Now().Unix()
	}
	ts := strconv.FormatInt(now, 10)
	hash := sha256.Sum256(body)
	canonical := state.MachineID + "\n" + ts + "\n" + strings.ToUpper(method) + "\n" + path + "\n" + hex.EncodeToString(hash[:])
	sig := ed25519.Sign(priv, []byte(canonical))
	return map[string]string{
		"X-CZ-Machine-ID": state.MachineID,
		"X-CZ-Timestamp":  ts,
		"X-CZ-Signature":  base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// HeartbeatResponse mirrors the JSON returned by /api/heartbeat.
type HeartbeatResponse struct {
	ServerTime    string `json:"server_time"`
	PolicyVersion int    `json:"policy_version"`
}

// Heartbeat sends a single signed POST /api/heartbeat. The optional
// pluginVersions update is merged server-side.
func Heartbeat(ctx context.Context, state *EnrollmentState, stateDir string, pluginVersions map[string]string) (*HeartbeatResponse, error) {
	if state == nil {
		return nil, &NotEnrolledError{Msg: "not enrolled"}
	}
	if stateDir == "" {
		stateDir = DefaultStateDir()
	}

	var body []byte
	if len(pluginVersions) > 0 {
		var err error
		body, err = json.Marshal(map[string]interface{}{"plugin_versions": pluginVersions})
		if err != nil {
			return nil, err
		}
	}
	headers, err := SignRequest(state, "POST", "/api/heartbeat", body, stateDir, 0)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		headers["Content-Type"] = "application/json"
	}

	resp, err := doSigned(ctx, "POST", state.APIURL+"/api/heartbeat", body, headers, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, &EnrollmentError{Msg: fmt.Sprintf("heartbeat failed: HTTP %d: %s", resp.StatusCode, extractError(respBody, string(respBody)))}
	}
	var hr HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		return nil, &EnrollmentError{Msg: fmt.Sprintf("decode heartbeat response: %v", err)}
	}
	return &hr, nil
}

// PullPolicy issues a signed GET /api/policy with If-None-Match
// using the cached version. Returns nil bundle on 304 (caller keeps
// the existing local copy). On 200, also persists the new
// policy_version to the state file.
func PullPolicy(ctx context.Context, state *EnrollmentState, stateDir string) (*PolicyBundle, error) {
	if state == nil {
		return nil, &NotEnrolledError{Msg: "not enrolled"}
	}
	if stateDir == "" {
		stateDir = DefaultStateDir()
	}

	headers, err := SignRequest(state, "GET", "/api/policy", nil, stateDir, 0)
	if err != nil {
		return nil, err
	}
	if state.PolicyVersion > 0 {
		headers["If-None-Match"] = fmt.Sprintf(`"%d"`, state.PolicyVersion)
	}

	resp, err := doSigned(ctx, "GET", state.APIURL+"/api/policy", nil, headers, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, &EnrollmentError{Msg: fmt.Sprintf("pull_policy failed: HTTP %d: %s", resp.StatusCode, extractError(respBody, string(respBody)))}
	}

	// Verify bundle signature if org pubkey is available
	sigHeader := resp.Header.Get("X-Policy-Signature")
	if state.OrgSigningPubkeyPEM != "" && sigHeader != "" {
		block, _ := pem.Decode([]byte(state.OrgSigningPubkeyPEM))
		if block != nil {
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err == nil {
				if edPub, ok := pub.(ed25519.PublicKey); ok {
					sigBytes, err := base64.StdEncoding.DecodeString(sigHeader)
					if err != nil || !ed25519.Verify(edPub, respBody, sigBytes) {
						return nil, ErrBundleSignatureInvalid
					}
				}
			}
		}
	}

	var bundle PolicyBundle
	if err := json.Unmarshal(respBody, &bundle); err != nil {
		return nil, &EnrollmentError{Msg: fmt.Sprintf("decode policy bundle: %v", err)}
	}
	if bundle.PolicyVersion != state.PolicyVersion {
		state.PolicyVersion = bundle.PolicyVersion
		_, _ = SaveState(state, stateDir)
	}
	return &bundle, nil
}

// AuditIngestResponse is the body of POST /api/audit.
type AuditIngestResponse struct {
	Accepted int `json:"accepted"`
	Dropped  int `json:"dropped"`
}

// SendAuditBatch streams up to 500 entries to /api/audit. The
// caller is responsible for batching larger flushes.
func SendAuditBatch(ctx context.Context, state *EnrollmentState, stateDir string, entries []AuditEntry) (*AuditIngestResponse, error) {
	if state == nil {
		return nil, &NotEnrolledError{Msg: "not enrolled"}
	}
	if len(entries) == 0 {
		return nil, &EnrollmentError{Msg: "entries cannot be empty"}
	}
	if len(entries) > 500 {
		return nil, &EnrollmentError{Msg: "entries cannot exceed 500 per batch"}
	}
	if stateDir == "" {
		stateDir = DefaultStateDir()
	}

	body, err := json.Marshal(map[string]interface{}{"entries": entries})
	if err != nil {
		return nil, err
	}
	headers, err := SignRequest(state, "POST", "/api/audit", body, stateDir, 0)
	if err != nil {
		return nil, err
	}
	headers["Content-Type"] = "application/json"

	resp, err := doSigned(ctx, "POST", state.APIURL+"/api/audit", body, headers, 15*time.Second)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, &EnrollmentError{Msg: fmt.Sprintf("send_audit_batch failed: HTTP %d: %s", resp.StatusCode, extractError(respBody, string(respBody)))}
	}
	var out AuditIngestResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, &EnrollmentError{Msg: fmt.Sprintf("decode audit response: %v", err)}
	}
	return &out, nil
}

// ----- internals --------------------------------------------------------

func doSigned(ctx context.Context, method, url string, body []byte, headers map[string]string, timeout time.Duration) (*http.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, url, reader)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return http.DefaultClient.Do(req)
}

func ensureStateDir(stateDir string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	_ = os.Chmod(stateDir, 0o700)
	return nil
}

func extractError(body []byte, fallback string) string {
	if len(body) == 0 {
		return fallback
	}
	var outer struct {
		Error interface{} `json:"error"`
	}
	if err := json.Unmarshal(body, &outer); err != nil {
		return fallback
	}
	switch v := outer.Error.(type) {
	case string:
		return v
	case map[string]interface{}:
		code, _ := v["code"].(string)
		msg, _ := v["message"].(string)
		return strings.TrimSpace(code + ": " + msg)
	}
	return fallback
}
