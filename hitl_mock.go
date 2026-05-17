// HITL-6c slice-5a port. In-process mock backend for the HITL approval
// workflow.
//
// Provides a deterministic, dependency-free fake of the two real
// endpoints used by the SDK's approval-poller:
//
//	POST /api/approval-requests       -> MockApprovalBackend.CreateRequest
//	GET  /api/approval-requests/{id}  -> MockApprovalBackend.GetRequest
//
// Five fixed modes (MockModes) emulate the terminal outcomes the
// design doc enumerates. Each mode flips the returned request to its
// terminal state after delayS seconds have elapsed since creation,
// measured with a monotonic clock so tests are immune to wall-clock
// skew.
//
// stdlib only + thread-safe -- callers may share a single
// MockApprovalBackend across goroutines.

package controlzero

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// MockModes lists the exact mode strings the design doc specifies.
// Order is for human readability only; lookups go through the map.
var MockModes = map[string]struct{}{
	"approve_after_2s":          {},
	"approve_timed_after_2s":    {},
	"approve_forever_after_2s":  {},
	"deny_after_2s":             {},
	"timeout":                   {},
}

// MockModesList returns the modes as a sorted slice for stable error
// messages and docs strings.
func MockModesList() []string {
	out := []string{
		"approve_after_2s",
		"approve_forever_after_2s",
		"approve_timed_after_2s",
		"deny_after_2s",
		"timeout",
	}
	return out
}

// terminalByMode mirrors the Python _TERMINAL_BY_MODE table. The deny
// mode deliberately has no decision_kind (the real backend sets none
// either). The timeout mode has no entry -- get_request stays
// "pending" forever and the caller's Wait loop hits its own cap.
type terminalShape struct {
	state        string
	decisionKind string // "" means "do not set"
}

var terminalByMode = map[string]terminalShape{
	"approve_after_2s":         {state: "approved", decisionKind: "approved_once"},
	"approve_timed_after_2s":   {state: "approved", decisionKind: "approved_timed"},
	"approve_forever_after_2s": {state: "approved", decisionKind: "approved_forever_grant"},
	"deny_after_2s":            {state: "denied", decisionKind: ""},
}

// approvedTimedWindow is how far the approved_timed mode extends the
// grant past resolution. Mirrors Python's _APPROVED_TIMED_WINDOW_SECONDS.
const approvedTimedWindow = 3600 * time.Second

// ErrMockRequestNotFound mirrors the real backend's 404. Returned by
// GetRequest when the request_id is unknown.
var ErrMockRequestNotFound = errors.New("controlzero: mock approval request not found")

// MockApprovalBackend is the in-process fake.
type MockApprovalBackend struct {
	mode    string
	delayS  float64
	mu      sync.Mutex
	records map[string]map[string]any
	created map[string]time.Time // monotonic anchors
}

// NewMockApprovalBackend constructs a mock backend in the given mode.
// delayS may be 0 to mean "use the default of 2.0s"; tests usually
// pass something like 0.05.
func NewMockApprovalBackend(mode string, delayS float64) (*MockApprovalBackend, error) {
	if _, ok := MockModes[mode]; !ok {
		return nil, fmt.Errorf(
			"unknown mock mode %q; expected one of %v",
			mode, MockModesList(),
		)
	}
	if delayS < 0 {
		return nil, errors.New("delayS must be >= 0")
	}
	if delayS == 0 {
		delayS = 2.0
	}
	return &MockApprovalBackend{
		mode:    mode,
		delayS:  delayS,
		records: make(map[string]map[string]any),
		created: make(map[string]time.Time),
	}, nil
}

// Mode returns the configured mock mode. Useful for tests.
func (m *MockApprovalBackend) Mode() string { return m.mode }

// DelayS returns the configured delay in seconds.
func (m *MockApprovalBackend) DelayS() float64 { return m.delayS }

// CreateRequest mirrors POST /api/approval-requests. Extra fields in
// `extras` are echoed back on the response so callers can smuggle the
// same context fields the real backend persists (project_id, agent_id,
// resource, args_hash, args_redacted, reason, context). ttl_seconds
// controls expires_at and defaults to 600.
//
// Returns a defensive DEEP copy so callers can mutate freely without
// corrupting the internal store visible to other pollers.
func (m *MockApprovalBackend) CreateRequest(canonicalAction string, extras map[string]any) (map[string]any, error) {
	ttlSeconds := 600
	if extras != nil {
		if v, ok := extras["ttl_seconds"]; ok {
			switch n := v.(type) {
			case int:
				ttlSeconds = n
			case int64:
				ttlSeconds = int(n)
			case float64:
				ttlSeconds = int(n)
			}
		}
	}
	now := time.Now().UTC()
	requestID, err := uuidV4()
	if err != nil {
		return nil, err
	}
	record := map[string]any{
		"id":               requestID,
		"state":            "pending",
		"canonical_action": canonicalAction,
		"created_at":       now.Format(time.RFC3339Nano),
		"expires_at":       now.Add(time.Duration(ttlSeconds) * time.Second).Format(time.RFC3339Nano),
		"resolved_at":      nil,
	}
	// Echo extras that don't collide with canonical fields. Mirrors
	// Python's "user kwargs cannot clobber id/state/created_at, etc."
	canonicalKeys := map[string]struct{}{
		"id": {}, "state": {}, "canonical_action": {},
		"created_at": {}, "expires_at": {}, "resolved_at": {},
		"ttl_seconds": {},
	}
	for k, v := range extras {
		if _, isCanonical := canonicalKeys[k]; isCanonical {
			continue
		}
		record[k] = v
	}

	m.mu.Lock()
	// Store an internal deep copy so caller mutations to nested
	// containers do not leak. We then make ANOTHER deep copy for the
	// returned snapshot to keep the two paths isolated.
	m.records[requestID] = deepCopyMap(record)
	m.created[requestID] = time.Now()
	m.mu.Unlock()

	return deepCopyMap(record), nil
}

// GetRequest mirrors GET /api/approval-requests/{id}. Returns
// ErrMockRequestNotFound when request_id is unknown.
//
// State transitions from "pending" to the mode's terminal value once
// delayS has elapsed since CreateRequest was called; "timeout" mode
// stays pending forever and the caller's Wait loop applies the cap.
func (m *MockApprovalBackend) GetRequest(requestID string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	record, ok := m.records[requestID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMockRequestNotFound, requestID)
	}
	createdMonotonic := m.created[requestID]
	elapsed := time.Since(createdMonotonic).Seconds()

	currentState, _ := record["state"].(string)
	if m.mode != "timeout" && currentState == "pending" {
		if elapsed >= m.delayS {
			terminal := terminalByMode[m.mode]
			record["state"] = terminal.state
			if terminal.decisionKind != "" {
				record["decision_kind"] = terminal.decisionKind
			}
			resolved := time.Now().UTC()
			record["resolved_at"] = resolved.Format(time.RFC3339Nano)
			if terminal.decisionKind == "approved_timed" {
				record["expires_at"] = resolved.Add(approvedTimedWindow).Format(time.RFC3339Nano)
			}
		}
	}

	return deepCopyMap(record), nil
}

// AsPollFunc adapts the mock backend so it can be passed directly to
// PendingApproval.Wait. Useful for integration tests.
func (m *MockApprovalBackend) AsPollFunc() PollFunc {
	return func(requestID string) (PollResponse, error) {
		got, err := m.GetRequest(requestID)
		if err != nil {
			return nil, err
		}
		return PollResponse(got), nil
	}
}

// deepCopyMap clones a map[string]any recursively. Nested maps,
// []any, and []map[string]any are cloned; scalars are passed through.
// Any other container type slips through unchanged -- the mock backend
// only ever holds JSON-shaped data so this is sufficient.
func deepCopyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = deepCopyAny(v)
	}
	return out
}

func deepCopyAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return deepCopyMap(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopyAny(e)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(x))
		for i, e := range x {
			out[i] = deepCopyMap(e)
		}
		return out
	default:
		return v
	}
}
