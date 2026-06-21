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
	"math"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// newUUID returns a random hex 32-char string. Good enough to identify
// an audit entry; not RFC-4122 formatted.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// readEmailFromConfig reads the operator email persisted by
// `controlzero install <agent> --email <addr>` (Python or Node CLI)
// from ~/.controlzero/config.yaml. Re-read on each batch so a fresh
// install with a different email takes effect without restarting the
// host process. Missing config or unreadable file = empty string,
// which the backend identity resolver treats as anonymous (existing
// pre-HITL behaviour, preserved for backward compat).
//
// HITL-5d (gh#537). Go SDK does not have its own install CLI yet --
// operators install via Python or Node and Go reads the shared
// config.
func readEmailFromConfig() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	cfgPath := filepath.Join(home, ".controlzero", "config.yaml")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return ""
	}
	var parsed struct {
		Email string `yaml:"email"`
	}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return ""
	}
	return parsed.Email
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
	// W3C Trace Context origination (#955): inject a child traceparent +
	// correlation headers so this audit submission is correlated end to end
	// (the gateway continues the same trace-id).
	injectTraceContext(req)
	// HITL-5d: optional operator identity header. Server-side resolver
	// maps email -> user_id and stamps it on every audit row, so HITL
	// approvals can attribute a shared API key to the right human.
	if email := readEmailFromConfig(); email != "" {
		req.Header.Set("X-CZ-Requestor-Email", email)
	}
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
	wire := map[string]any{
		"id":        newUUID(),
		"tool_name": strOrEmpty(entry["tool"]),
		"decision":  strOrDefault(entry["decision"], "allow"),
		"policy_id": policyID,
		"rule_id":   policyID,
		"reason":    strOrEmpty(entry["reason"]),
		// T108 (2026-05-12): governance reason_code that the backend
		// audit_logs column already accepts. Lets ops filter / alert
		// on synthetic lifecycle events (LOCAL_OVERRIDE_ACTIVE).
		"reason_code":    strOrEmpty(entry["reason_code"]),
		"hostname":       host,
		"user":           u,
		"mode":           strOrDefault(entry["mode"], "hosted"),
		"ts":             time.Now().UTC().Format(time.RFC3339),
		"client_name":    detectClientName(),
		"client_version": detectClientVersion(),
		"user_email":     "",
		// Phase 1A (cua rig v2, #450). SHA-256 over RFC 8785 canonical
		// bytes of args. Same input -> identical hash across all 3
		// SDKs. Backend accepts missing/empty (additive only).
		"args_hash": strOrEmpty(entry["args_hash"]),
		// Phase 1B (#451). Engine version that produced the decision.
		// Lets audit consumers detect stale SDK installs.
		"policy_engine_version": strOrEmpty(entry["policy_engine_version"]),
		// #495 / v1 (2026-05-14): normalised controlzero SDK package
		// version on the wire as "go@v1.7.2". Distinct from
		// client_version which carries the host CLI version. See
		// version.go for the source-of-truth + drift guard rationale.
		"controlzero_sdk_version": sdkVersionWire,
		// Migration 048 (2026-05-19): per-decision policy_source.
		// Stamped by the client (hosted | local | local-override) on
		// every decision. Empty -> backend's column DEFAULT ('hosted')
		// wins, matching the legacy pre-048 behaviour.
		"policy_source": strOrEmpty(entry["policy_source"]),
	}

	// Wire-payload parity with the backend /v1/sdk/audit AuditIngestEntry
	// widening (#439 / #120). Populated by host adapters / integrations
	// that carry per-call telemetry (latency, the LLM cost-tracking quartet
	// provider / model / tokens / cost, an explicit status / error pair, an
	// explicit method_name, and the full args map). Emitted HERE in the
	// shared builder so the wire shape matches Python + Node uniformly.
	// Each field is emitted ONLY when the entry carries a non-empty /
	// non-zero value, so the common guard()-decision row keeps its lean
	// payload and older backends ignore the extra keys (additive contract).
	//
	// method_name backfills extracted_method only when the extractor did
	// not already resolve one (extracted_method is canonical).
	methodName := strOrEmpty(entry["method_name"])
	if methodName == "" {
		methodName = strOrEmpty(entry["method"])
	}
	if methodName != "" && strOrEmpty(wire["extracted_method"]) == "" {
		wire["extracted_method"] = methodName
	}
	if mn := strOrEmpty(entry["method_name"]); mn != "" {
		wire["method_name"] = mn
	}
	if args, ok := entry["args"].(map[string]any); ok && len(args) > 0 {
		// Sanitize to a strict-JSON-safe map before forwarding (#439, codex
		// P1): a nested non-finite float (NaN/Inf) or an unsupported type
		// (func / chan / complex) inside args would make json.Marshal of the
		// whole batch body fail, dropping EVERY entry in that batch -- the
		// "one bad row cannot poison a batch" contract. If sanitization
		// cannot produce a non-empty safe map, args is omitted.
		if safe, okm := jsonSafe(args, 0).(map[string]any); okm && len(safe) > 0 {
			wire["args"] = safe
		}
	}
	if ms := uintOrZero(entry["latency_ms"]); ms > 0 {
		wire["latency_ms"] = ms
	}
	for _, key := range []string{"status", "error_type", "error_message", "provider"} {
		if v := strOrEmpty(entry[key]); v != "" {
			wire[key] = v
		}
	}
	// model_id: accept either "model_id" or the shorter "model" key.
	modelID := strOrEmpty(entry["model_id"])
	if modelID == "" {
		modelID = strOrEmpty(entry["model"])
	}
	if modelID != "" {
		wire["model_id"] = modelID
	}
	for _, key := range []string{"input_tokens", "output_tokens", "total_tokens"} {
		if n := uintOrZero(entry[key]); n > 0 {
			wire[key] = n
		}
	}
	// Only a positive finite cost is emitted (floatOrZero already folds
	// NaN/Inf -> 0); a negative value is dropped for parity with Python/Node.
	if cost := floatOrZero(entry["estimated_cost_usd"]); cost > 0 {
		wire["estimated_cost_usd"] = cost
	}

	// Credential leak detection (epic #666, PR-4): forward the new
	// event-kind plus its credential-specific fields onto the wire.
	// The backend ingest at /api/audit accepts unknown fields today
	// (additive schema contract); PR-5 lands the matching analytical
	// store columns + handler routing. Kept additive so older backends
	// silently ignore the extra payload until PR-5 ships.
	//
	// Cross-SDK parity: Python forwards the same set in
	// `audit_remote._build_wire_entry`; Node forwards the same set in
	// `audit_remote.ts toWireFormat`. Keep this list in lockstep when
	// the schema evolves; the cross-SDK conformance test guards it.
	if kind, ok := entry["event_kind"]; ok {
		if kindStr, ok := kind.(string); ok && kindStr != "" {
			wire["event_kind"] = kindStr
			for _, key := range []string{
				"pattern_id",
				"severity",
				"value_hash",
				"context_window",
				"source",
				"tool_call_id",
				"agent_name",
				"project_id",
				"enforcement_action",
				"enforcement_downgraded",
			} {
				if v, present := entry[key]; present {
					wire[key] = v
				}
			}
		}
	}

	// Final batch-poison backstop (#439 codex P1-b): every value that goes on
	// the wire -- including the raw top-level forwarded fields above (the
	// credential_* envelope copies entry[key] verbatim) and any future field
	// -- is run through jsonSafe so a non-finite float or an unsupported type
	// (func / chan / complex) on ANY field cannot make json.Marshal of the
	// whole batch body fail. jsonSafe is a no-op on already-clean scalars, so
	// the common path is unchanged. The input is a map literal, so the result
	// is always a map[string]any.
	if safe, ok := jsonSafe(wire, 0).(map[string]any); ok {
		return safe
	}
	return wire
}

type authExpiredError struct{}

func (*authExpiredError) Error() string { return "server returned 401" }

func detectClientName() string {
	// T92: explicit override wins. Cross-SDK convention is
	// CONTROLZERO_CLIENT; CONTROLZERO_CLIENT_NAME alias preserved for
	// existing Go consumers.
	if v := strings.TrimSpace(os.Getenv("CONTROLZERO_CLIENT")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("CONTROLZERO_CLIENT_NAME")); v != "" {
		return v
	}

	// Claude Code: Anthropic exports CLAUDECODE=1.
	if os.Getenv("CLAUDECODE") != "" || os.Getenv("CLAUDE_CODE") != "" {
		return "claude-code"
	}

	// Codex CLI: runtime exports CODEX_HOME / CODEX_PROFILE in
	// launched subprocesses; CODEX_CLI mirrors the prior single-env
	// convention.
	if os.Getenv("CODEX_HOME") != "" || os.Getenv("CODEX_PROFILE") != "" || os.Getenv("CODEX_CLI") != "" {
		return "codex-cli"
	}

	// Cursor: IDE sets CURSOR_TRACE_ID per terminal window and
	// CURSOR_AGENT in agent panes. TERM_PROGRAM=cursor catches the
	// integrated shell. Pre-T92 there was no Cursor detection in Go.
	if os.Getenv("CURSOR_TRACE_ID") != "" ||
		os.Getenv("CURSOR_AGENT") != "" ||
		os.Getenv("CURSOR_USER_AGENT") != "" ||
		os.Getenv("TERM_PROGRAM") == "cursor" {
		return "cursor"
	}

	// Windsurf
	if os.Getenv("WINDSURF_AGENT") != "" || os.Getenv("WINDSURF_SESSION_ID") != "" {
		return "windsurf"
	}

	// Gemini CLI: match ONLY env vars the CLI runtime sets, NOT the
	// broad GEMINI_ prefix. GEMINI_API_KEY is exported by anyone
	// using Google's Go SDK directly.
	if os.Getenv("GEMINI_CLI") != "" ||
		os.Getenv("GEMINI_SANDBOX") != "" ||
		os.Getenv("GEMINI_SYSTEM_MD") != "" {
		return "gemini-cli"
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

// uintOrZero coerces a numeric entry value (the audit entry map is
// loosely typed) into a uint32, clamped non-negative, or 0 when missing /
// malformed (#439). Accepts int / int64 / uint / uint32 / uint64 /
// float64 / numeric string so an adapter can attach a count in any of the
// natural Go shapes.
func uintOrZero(v any) uint32 {
	const maxUint32 = uint64(^uint32(0))
	clamp := func(n uint64) uint32 {
		if n > maxUint32 {
			return uint32(maxUint32)
		}
		return uint32(n)
	}
	switch n := v.(type) {
	case nil:
		return 0
	case uint32:
		return n
	case uint:
		return clamp(uint64(n))
	case uint64:
		return clamp(n)
	case int:
		if n < 0 {
			return 0
		}
		return clamp(uint64(n))
	case int64:
		if n < 0 {
			return 0
		}
		return clamp(uint64(n))
	case float64:
		// Non-finite (NaN / +/-Inf) MUST short-circuit to 0: uint64(NaN)
		// and uint64(+Inf) are undefined in Go and would yield garbage
		// (#439). A finite positive value clamps to the uint32 range.
		if math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 {
			return 0
		}
		return clamp(uint64(n))
	case string:
		if n == "" {
			return 0
		}
		if parsed, err := strconv.ParseUint(n, 10, 32); err == nil {
			return uint32(parsed)
		}
		return 0
	default:
		return 0
	}
}

// floatOrZero coerces a numeric entry value into a FINITE float64, or 0
// when missing / malformed / non-finite (#439). A non-finite result (NaN /
// +/-Inf -- e.g. an adapter that already holds inf, or the string "inf"
// which strconv.ParseFloat accepts without error) MUST NOT escape: a
// non-finite estimated_cost_usd makes json.Marshal of the whole batch fail
// (Go errors on Inf/NaN), which would drop EVERY entry in that batch (the
// "one bad row cannot poison a batch" contract). Mirrors Node's
// Number.isFinite guard.
func floatOrZero(v any) float64 {
	finite := func(f float64) float64 {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0
		}
		return f
	}
	switch n := v.(type) {
	case nil:
		return 0
	case float64:
		return finite(n)
	case float32:
		return finite(float64(n))
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case uint32:
		return float64(n)
	case uint64:
		return float64(n)
	case string:
		if n == "" {
			return 0
		}
		if parsed, err := strconv.ParseFloat(n, 64); err == nil {
			return finite(parsed)
		}
		return 0
	default:
		return 0
	}
}

// jsonSafeMaxDepth bounds jsonSafe recursion so a cyclic / pathologically
// deep args map cannot blow the stack on the agent hot path.
const jsonSafeMaxDepth = 32

// jsonSafe returns a strict-JSON-serializable copy of v (#439). The
// forwarded args map is bug-/attacker-shaped: a nested non-finite float
// (NaN/Inf) or an unsupported type (func / chan / complex) would make
// json.Marshal of the whole batch body fail -- dropping EVERY entry in that
// batch (the "one bad row cannot poison a batch" contract). Mirrors the
// Python _json_safe helper. Coerces:
//   - map[string]any         -> map with sanitized values
//   - []any                  -> slice of sanitized values
//   - non-finite float       -> nil (dropped, never Inf/NaN)
//   - string/bool/int*/uint*/finite-float/nil -> kept
//   - anything else          -> fmt.Sprintf("%v") (or nil if even that is
//     not json-marshalable, verified by a final Marshal probe)
func jsonSafe(v any, depth int) any {
	if depth > jsonSafeMaxDepth {
		// At the depth limit return a CONSTANT marker rather than formatting
		// the subtree: a self-referential / cyclic map would otherwise keep
		// recursing (and even fmt.Sprintf on a cycle is needless work on the
		// hot path). The marker is always JSON-safe and terminates the walk.
		return "<max-depth>"
	}
	switch x := v.(type) {
	case nil:
		return nil
	case string, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return x
	case float32:
		f := float64(x)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil
		}
		return x
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = jsonSafe(val, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = jsonSafe(val, depth+1)
		}
		return out
	default:
		// Unknown / possibly non-marshalable (func, chan, complex, custom
		// struct): degrade to its string form, then probe that the result is
		// actually json-marshalable; if not, drop it.
		s := fmt.Sprintf("%v", x)
		if _, err := json.Marshal(s); err != nil {
			return nil
		}
		return s
	}
}
