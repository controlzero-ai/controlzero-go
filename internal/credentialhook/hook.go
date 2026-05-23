// Package credentialhook is the Go SDK port of the credential leak
// ingest hook (epic #666, PR-4).
//
// Mirrors the Python implementation at
// `sdks/python/controlzero/controlzero/_internal/credential_hook.py`
// and ships behaviour parity for warn / redact / block actions, HMAC
// value hashing, context-window masking, and the
// CONTROLZERO_CREDLEAK_OFF=1 operator break-glass override.
//
// Design notes:
//
//   - Redaction never echoes plaintext credentials back to the audit
//     row. The matched bytes are replaced with cz:credleak:<sha256_hex>
//     so the audit row can deterministically reference the same secret
//     across calls without holding it.
//   - `value_hash` is HMAC-SHA256(per-org key, plaintext bytes), first
//     16 hex chars. One-way; rotates with the org HMAC key. The
//     plaintext lives only on the stack during this call.
//   - The 16-byte context window surrounding each match is masked: the
//     literal `<MASKED>` replaces the credential body itself so the
//     audit row never carries any prefix or suffix of the secret
//     bytes.
//   - CONTROLZERO_CREDLEAK_OFF=1 in the environment downgrades any
//     configured action to warn, but still emits the audit row with
//     EnforcementDowngraded=true. The env override is the operator's
//     break-glass for a noisy false positive in production.
package credentialhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"controlzero.ai/sdk/go/internal/credentialscanner"
)

// Action selects the enforcement posture for a credential match.
type Action int

const (
	// ActionWarn emits the audit row and returns the original text
	// unmodified. The agent still sees the credential; the operator
	// dashboard records the detection.
	ActionWarn Action = iota
	// ActionRedact emits the audit row and replaces each match with
	// `cz:credleak:<sha256_hex>` in the returned text.
	ActionRedact
	// ActionBlock emits the audit row and then returns
	// ErrCredentialLeakBlocked. The agent never observes the redacted
	// or original output.
	ActionBlock
)

// String renders Action as the wire value the audit row carries.
// Matches the Python action enum values bit-for-bit so the backend
// can dedupe on enforcement_action across SDKs.
func (a Action) String() string {
	switch a {
	case ActionWarn:
		return "warn"
	case ActionRedact:
		return "redact"
	case ActionBlock:
		return "block"
	default:
		return "unknown"
	}
}

// Source labels the origin of the text being scanned. Matches the
// Python Source literal: tool_output | tool_stderr | file_read |
// grep_match. Free-form strings are accepted on the wire so a future
// surface can ship without an SDK rev.
type Source string

const (
	SourceToolOutput Source = "tool_output"
	SourceToolStderr Source = "tool_stderr"
	SourceFileRead   Source = "file_read"
	SourceGrepMatch  Source = "grep_match"
)

// offEnvVar is the operator break-glass: when set to the literal "1"
// the handler downgrades any non-warn action to warn and stamps the
// audit row with EnforcementDowngraded=true. Other truthy values
// ("true", "yes") are NOT honoured so a misconfigured operator value
// cannot silently bypass enforcement.
const offEnvVar = "CONTROLZERO_CREDLEAK_OFF"

// maskToken is the sentinel that replaces the credential body in the
// context window. Sixteen bytes on either side are preserved as
// ambient context; the credential itself is never echoed.
const maskToken = "<MASKED>"

// minHMACKeyLen is the minimum accepted HMAC key length. Shorter
// keys offer no security benefit and almost always indicate a
// configuration bug (e.g. operator passed a hex string instead of
// the bytes).
const minHMACKeyLen = 16

// ErrCredentialLeakBlocked is returned by Handler.Handle when the
// configured action is ActionBlock and the scanner found at least
// one credential match. Wrapping callers can `errors.Is` against
// this sentinel to branch on the leak-block class.
//
// The corresponding SDK error code is E2001, matching the Python
// catalog. See sdks/go/controlzero/errors.go for the typed wrapper.
var ErrCredentialLeakBlocked = errors.New("controlzero: credential leak detected; tool output blocked")

// Sink is the minimal contract the handler needs to forward an audit
// row. The Go SDK's BearerAuditSink already satisfies it via its
// `Log(entry map[string]any)` method. Best-effort: a Sink may be nil,
// and any panic or returned error is swallowed so the hook never
// crashes a user's tool call because an audit delivery failed.
type Sink interface {
	Log(entry map[string]any)
}

// HandleInput carries every per-call argument the handler needs.
type HandleInput struct {
	Source     Source
	Text       string
	ToolName   string
	ToolCallID string
	AgentName  string
}

// AuditRow is the wire-shape map the handler emits per match. Kept as
// a map[string]any (not a typed struct) so it folds cleanly onto the
// existing BearerAuditSink batch payload without a separate schema
// migration. The backend ingest accepts unknown extra fields per the
// additive-schema contract; PR-5 lands the matching analytical-store
// columns.
type AuditRow = map[string]any

// HandleOutput is the post-scan return value. Text is the
// possibly-redacted body; AuditRows holds the rows that were emitted
// to the configured sink.
type HandleOutput struct {
	Text      string
	AuditRows []AuditRow
}

// Handler wires the scanner, redactor, and audit emit into one call.
//
// Instantiated per-client (not per-call) so the same configuration --
// project id, action posture, HMAC key -- applies across every
// tool-output scan from a given agent. The struct holds no per-call
// state and is safe to share across goroutines.
type Handler struct {
	scanner   *credentialscanner.Scanner
	sink      Sink
	projectID string
	action    Action
	hmacKey   []byte
}

// Config captures the constructor parameters. Sink may be nil for
// local-only mode; the scanner runs and rows are returned to the
// caller but never forwarded over the wire.
type Config struct {
	Scanner   *credentialscanner.Scanner
	Sink      Sink
	ProjectID string
	Action    Action
	HMACKey   []byte
}

// New constructs a Handler. Returns an error when Action is outside
// the warn/redact/block range or when HMACKey is shorter than 16
// bytes. The failure surfaces at construction so a misconfigured
// hook lands the error near the wiring code rather than on the first
// scan.
func New(cfg Config) (*Handler, error) {
	switch cfg.Action {
	case ActionWarn, ActionRedact, ActionBlock:
	default:
		return nil, fmt.Errorf("credentialhook: Action must be warn|redact|block, got %d", int(cfg.Action))
	}
	if len(cfg.HMACKey) < minHMACKeyLen {
		return nil, fmt.Errorf("credentialhook: HMACKey must be at least %d bytes (got %d)", minHMACKeyLen, len(cfg.HMACKey))
	}
	if cfg.Scanner == nil {
		return nil, errors.New("credentialhook: Scanner is required (use credentialscanner.Default() or hooks.BuildHandler)")
	}
	keyCopy := make([]byte, len(cfg.HMACKey))
	copy(keyCopy, cfg.HMACKey)
	return &Handler{
		scanner:   cfg.Scanner,
		sink:      cfg.Sink,
		projectID: cfg.ProjectID,
		action:    cfg.Action,
		hmacKey:   keyCopy,
	}, nil
}

// Handle scans `in.Text`, emits one audit row per match through the
// configured sink, and returns the possibly-redacted text plus the
// emitted rows. Zero matches -> the original text is returned verbatim
// and AuditRows is empty.
//
// When the effective action resolves to ActionBlock the function
// emits every audit row first and then returns ErrCredentialLeakBlocked
// (wrapped with the match count). The caller never sees a redacted
// text in the block path.
func (h *Handler) Handle(_ context.Context, in HandleInput) (HandleOutput, error) {
	matches := h.scanner.Scan(in.Text)
	if len(matches) == 0 {
		return HandleOutput{Text: in.Text}, nil
	}

	effective, downgraded := h.resolveEffectiveAction()

	rows := make([]AuditRow, 0, len(matches))
	for _, m := range matches {
		rows = append(rows, h.buildAuditRow(m, in, effective, downgraded))
	}

	for _, row := range rows {
		h.emit(row)
	}

	if effective == ActionBlock {
		// Audit rows are emitted BEFORE the error so the operator
		// dashboard always sees the detection even when the agent
		// never observes the output.
		return HandleOutput{AuditRows: rows}, fmt.Errorf(
			"%w: %d match(es) in %s (tool=%s)",
			ErrCredentialLeakBlocked, len(matches), in.Source, in.ToolName,
		)
	}
	if effective == ActionRedact {
		return HandleOutput{
			Text:      redactText(in.Text, matches),
			AuditRows: rows,
		}, nil
	}
	// Remaining case is ActionWarn (validated by New).
	return HandleOutput{Text: in.Text, AuditRows: rows}, nil
}

// resolveEffectiveAction applies the CONTROLZERO_CREDLEAK_OFF=1
// operator override. Returns the effective action plus a downgraded
// flag that feeds into the audit row so the dashboard can highlight
// rows whose intended posture was bypassed.
func (h *Handler) resolveEffectiveAction() (Action, bool) {
	if os.Getenv(offEnvVar) == "1" {
		if h.action != ActionWarn {
			return ActionWarn, true
		}
	}
	return h.action, false
}

// emit forwards one audit row to the configured sink. Best-effort:
// nil sink -> drop, panic in Log -> swallow.
func (h *Handler) emit(row AuditRow) {
	if h.sink == nil {
		return
	}
	defer func() {
		// The audit pipeline is best-effort by design (matches the
		// existing BearerAuditSink contract). The hook must never
		// crash a user's tool call because an audit delivery failed.
		_ = recover()
	}()
	h.sink.Log(row)
}

// buildAuditRow constructs the wire-shape row the BearerAuditSink
// already accepts. The sink folds additional keys onto the existing
// batch payload (`/api/audit/batch` accepts unknown extra fields per
// the additive-schema contract); backend storage lands in PR-5.
func (h *Handler) buildAuditRow(m credentialscanner.Match, in HandleInput, effective Action, downgraded bool) AuditRow {
	plaintext := in.Text[m.Start:m.End]
	return AuditRow{
		// Mark the row as a credential leak so the backend ingest
		// can route it to the rotation tracker view in PR-5.
		"event_kind":             "credential_leak_detected",
		"pattern_id":             m.PatternID,
		"severity":               m.Severity,
		"value_hash":             HMACValueHash(h.hmacKey, []byte(plaintext)),
		"context_window":         BuildContextWindow(in.Text, m.Start, m.End),
		"source":                 string(in.Source),
		"tool_name":              in.ToolName,
		"tool_call_id":           in.ToolCallID,
		"agent_name":             in.AgentName,
		"project_id":             h.projectID,
		"enforcement_action":     effective.String(),
		"enforcement_downgraded": downgraded,
	}
}

// HMACValueHash returns the first 16 hex chars of
// HMAC-SHA256(hmacKey, plaintext).
//
// The truncation is deliberate: 64 bits is sufficient de-duplication
// granularity for credential matches per org, and the shorter string
// keeps the audit_logs.metadata column LOW-cardinality friendly.
// The key MUST be the per-org HMAC key issued at enrollment; never
// reuse across orgs because cross-org hash equality would leak
// "same secret" membership across tenants.
func HMACValueHash(hmacKey, plaintext []byte) string {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(plaintext)
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum)[:16]
}

// BuildContextWindow returns sixteen bytes of ambient text on either
// side of the credential, with the credential body itself replaced
// by the literal "<MASKED>" sentinel.
//
// Computed on the input string (byte offsets). On ASCII text -- the
// dominant case for tool output of secrets -- the result is
// byte-equivalent across the Python and Go implementations.
func BuildContextWindow(text string, start, end int) string {
	textLen := len(text)
	leftStart := start - 16
	if leftStart < 0 {
		leftStart = 0
	}
	rightEnd := end + 16
	if rightEnd > textLen {
		rightEnd = textLen
	}
	left := text[leftStart:start]
	right := text[end:rightEnd]
	var b strings.Builder
	b.Grow(len(left) + len(maskToken) + len(right))
	b.WriteString(left)
	b.WriteString(maskToken)
	b.WriteString(right)
	return b.String()
}

// redactText replaces each match with `cz:credleak:<sha256_hex>`.
// Processed right-to-left so a redaction never invalidates the byte
// offsets of earlier (lower-index) matches.
//
// The hex digest is SHA-256 of the plaintext credential, NOT the
// HMAC-keyed hash. The redaction lives inside the agent's local
// output; the HMAC hash lives in the audit row that leaves the host.
// Keeping them distinct means a leak of the local log file does not
// let an attacker correlate a previous local redaction with a
// cross-org audit row.
func redactText(text string, matches []credentialscanner.Match) string {
	ordered := make([]credentialscanner.Match, len(matches))
	copy(ordered, matches)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Start > ordered[j].Start
	})

	out := text
	for _, m := range ordered {
		// The scanner only emits matches whose [start, end) falls
		// inside the input string; right-to-left ordering means a
		// prior replacement cannot shift these bounds either. No
		// defensive bounds check needed here.
		plaintext := out[m.Start:m.End]
		sum := sha256.Sum256([]byte(plaintext))
		replacement := "cz:credleak:" + hex.EncodeToString(sum[:])
		out = out[:m.Start] + replacement + out[m.End:]
	}
	return out
}
