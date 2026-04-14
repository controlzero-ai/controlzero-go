package controlzero

// BearerAuditSink: hosted-mode audit sink using Bearer API key auth
// (parity with controlzero.audit_remote.BearerAuditSink in Python and
// BearerAuditSink in the Node SDK).
//
// Authenticates with the project API key and posts batches of audit
// entries to POST /v1/sdk/audit. Used by Client when constructed with
// WithAPIKey(...), independent of enrollment state.
//
// Constraints:
//   - NEVER block or crash the Guard() critical path. log() returns
//     synchronously; the HTTP POST happens on a goroutine.
//   - On 401 the sink disables itself (key revoked / invalid) so a bad
//     key does not produce a storm of failing requests.
//   - On transient errors the buffer is retained for the next flush.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"
)

// newUUID returns a random hex 32-char string. Good enough to identify
// an audit entry; not RFC-4122 formatted.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

const (
	bearerMaxBuffer    = 50
	bearerFlushInterv  = 30 * time.Second
	bearerFlushTimeout = 2 * time.Second
)

// BearerAuditOptions configures a BearerAuditSink.
type BearerAuditOptions struct {
	APIURL string
	APIKey string
}

// BearerAuditSink is the hosted-mode audit shipper.
type BearerAuditSink struct {
	apiURL string
	apiKey string

	mu       sync.Mutex
	buffer   []map[string]any
	disabled bool
	closed   bool

	stop   chan struct{}
	wg     sync.WaitGroup
	ticker *time.Ticker
}

// NewBearerAuditSink constructs a hosted audit sink.
func NewBearerAuditSink(opts BearerAuditOptions) *BearerAuditSink {
	s := &BearerAuditSink{
		apiURL: strings.TrimRight(opts.APIURL, "/"),
		apiKey: opts.APIKey,
		stop:   make(chan struct{}),
		ticker: time.NewTicker(bearerFlushInterv),
	}
	s.wg.Add(1)
	go s.flushLoop()
	return s
}

// Log appends an entry to the buffer. Non-blocking.
func (s *BearerAuditSink) Log(entry map[string]any) {
	s.mu.Lock()
	if s.disabled || s.closed {
		s.mu.Unlock()
		return
	}
	s.buffer = append(s.buffer, s.toWireFormat(entry))
	overflow := len(s.buffer) >= bearerMaxBuffer
	s.mu.Unlock()
	if overflow {
		go s.flushOnce()
	}
}

// Close flushes pending entries and stops the background goroutine.
func (s *BearerAuditSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.stop)
	s.ticker.Stop()
	s.mu.Unlock()
	s.wg.Wait()
	s.flushOnce()
	return nil
}

// IsDisabled reports whether the sink has permanently disabled itself
// (e.g. due to 401 from the backend).
func (s *BearerAuditSink) IsDisabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disabled
}

func (s *BearerAuditSink) flushLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stop:
			return
		case <-s.ticker.C:
			s.flushOnce()
		}
	}
}

func (s *BearerAuditSink) flushOnce() {
	s.mu.Lock()
	if s.disabled || len(s.buffer) == 0 {
		s.mu.Unlock()
		return
	}
	batch := make([]map[string]any, len(s.buffer))
	copy(batch, s.buffer)
	s.mu.Unlock()

	err := s.postBatch(batch)
	if err != nil {
		if _, ok := err.(*authExpiredError); ok {
			fmt.Fprintln(os.Stderr,
				"controlzero: bearer audit sink disabled (API key rejected 401). "+
					"Check that CONTROLZERO_API_KEY is a valid cz_live_ or cz_test_ key.")
			s.mu.Lock()
			s.disabled = true
			s.buffer = nil
			s.mu.Unlock()
			return
		}
		fmt.Fprintf(os.Stderr,
			"controlzero: bearer audit flush failed (%v); entries retained for retry\n", err)
		return
	}
	s.mu.Lock()
	if len(s.buffer) >= len(batch) {
		s.buffer = s.buffer[len(batch):]
	} else {
		s.buffer = nil
	}
	s.mu.Unlock()
}

func (s *BearerAuditSink) postBatch(batch []map[string]any) error {
	body, err := json.Marshal(map[string]any{"entries": batch})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), bearerFlushTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.apiURL+"/v1/sdk/audit", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return &authExpiredError{}
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("audit ingest returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *BearerAuditSink) toWireFormat(entry map[string]any) map[string]any {
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown"
	}
	u := ""
	if usr, err := user.Current(); err == nil {
		u = usr.Username
	}
	policyID, _ := entry["policy_id"].(string)
	return map[string]any{
		"id":             newUUID(),
		"tool_name":      strOrEmpty(entry["tool"]),
		"decision":       strOrDefault(entry["decision"], "allow"),
		"policy_id":      policyID,
		"rule_id":        policyID,
		"reason":         strOrEmpty(entry["reason"]),
		"hostname":       host,
		"user":           u,
		"mode":           strOrDefault(entry["mode"], "hosted"),
		"ts":             time.Now().UTC().Format(time.RFC3339),
		"client_name":    detectClientName(),
		"client_version": detectClientVersion(),
		"user_email":     "",
	}
}

type authExpiredError struct{}

func (*authExpiredError) Error() string { return "server returned 401" }

func detectClientName() string {
	if os.Getenv("CLAUDECODE") != "" {
		return "claude-code"
	}
	if os.Getenv("GEMINI_CLI") != "" {
		return "gemini-cli"
	}
	if os.Getenv("CODEX_CLI") != "" {
		return "codex-cli"
	}
	if v := os.Getenv("CONTROLZERO_CLIENT_NAME"); v != "" {
		return v
	}
	return "go-sdk"
}

func detectClientVersion() string {
	if v := os.Getenv("CONTROLZERO_CLIENT_VERSION"); v != "" {
		return v
	}
	return "1.4.0"
}

func strOrEmpty(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func strOrDefault(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}
