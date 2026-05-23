// HITL-6c. PendingApproval state machine + Wait / WaitContext polling
// loops, mirroring Python controlzero.hitl.pending_approval.
//
// PendingApproval is what Client.RequestApproval returns when a rule
// needs human approval. The caller drives the state machine by calling
// Wait(poll_fn) (blocking) or WaitContext(ctx, poll_fn) (cancellable).
//
// Cadence per the HITL-6a design doc:
//
//   - First 10 polls: fixed 1.0s interval.
//   - Polls 11+:      exponential backoff (x2 per tick), capped at 10s.
//   - Hard stop:      DeadlineAt (UTC). Reaching it while still pending
//                     transitions to "timed_out" and returns a
//                     HITLTimeoutError.
//
// Terminal outcomes:
//
//   - "approved" -> synth allow PolicyDecision, return nil.
//   - "denied"   -> synth deny PolicyDecision, return *PolicyDeniedError.
//   - timeout    -> synth deny, return *HITLTimeoutError.
//
// poll_fn errors are NOT swallowed; they propagate so the caller sees
// the underlying network error.

package controlzero

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// HITL status string values. Wire format from
// GET /api/approval-requests/{id}.
//
// StatusExpired is the wire-level value the backend approval sweeper
// writes when an `approval_requests` row passes its `expires_at` while
// still pending. It is NOT a distinct SDK terminal state -- the
// polling loop maps it onto StatusTimedOut so consumers see a single
// *HITLTimeoutError for any timeout source (server sweeper or local
// deadline). gh#707.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusTimedOut = "timed_out"
	StatusExpired  = "expired"
)

// Cadence constants per the design doc. Held as package vars so tests
// could theoretically nudge them; today they are read-only.
const (
	DefaultTimeoutS         = 300.0
	DefaultPollIntervalS    = 1.0
	hitlLinearPollCount     = 10
	hitlMaxPollIntervalS    = 10.0
	hitlBackoffMultiplier   = 2.0
)

// validStatuses is the set of legal Status values.
var validStatuses = map[string]struct{}{
	StatusPending:  {},
	StatusApproved: {},
	StatusDenied:   {},
	StatusTimedOut: {},
}

// terminalStatuses is the set of absorbing states.
var terminalStatuses = map[string]struct{}{
	StatusApproved: {},
	StatusDenied:   {},
	StatusTimedOut: {},
}

// IsValidStatus reports whether s is a known HITL status string.
func IsValidStatus(s string) bool {
	_, ok := validStatuses[s]
	return ok
}

// IsTerminalStatus reports whether s is one of the absorbing terminal
// statuses (approved, denied, timed_out).
func IsTerminalStatus(s string) bool {
	_, ok := terminalStatuses[s]
	return ok
}

// uuidV4 generates a RFC-4122 v4 UUID using crypto/rand. Returned as
// the canonical 36-char hyphenated form so it round-trips through the
// backend's Idempotency-Key column.
func uuidV4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Set version (4) and variant (RFC 4122) bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]), nil
}

// mustUUIDv4 panics on a crypto/rand failure. Used only inside .New()
// where a runtime entropy outage is treated as catastrophic; callers
// that need to handle the error reach for uuidV4() directly.
func mustUUIDv4() string {
	s, err := uuidV4()
	if err != nil {
		panic(fmt.Sprintf("controlzero: crypto/rand failure: %v", err))
	}
	return s
}

// PendingApproval is returned by Client.RequestApproval when a rule
// requires human approval. The struct is mutable -- Wait/WaitContext
// flip Status and write Decision as the lifecycle plays out.
type PendingApproval struct {
	// RequestID is the backend's approval-request UUID.
	RequestID string

	// DeadlineAt is the hard timeout cutoff (UTC).
	DeadlineAt time.Time

	// IdempotencyKey is the UUIDv4 the SDK sent on the original POST;
	// retries reuse this so the backend's unique index can dedupe.
	IdempotencyKey string

	// Status starts as "pending" and transitions to one of the
	// terminal absorbing states.
	Status string

	// PollIntervalS is updated by Wait/WaitContext after every sleep
	// so callers (and tests) can observe the schedule.
	PollIntervalS float64

	// Decision is nil until Status flips terminal. On approve it is
	// a synthetic allow decision; on deny / timeout it is a synthetic
	// deny so audit hooks have a stable shape to read.
	Decision *PolicyDecision

	// mu guards Status / PollIntervalS / Decision against concurrent
	// Wait* calls. Callers should not share a single PendingApproval
	// across goroutines, but the guard catches accidental misuse
	// without much cost.
	mu sync.Mutex
}

// NewPendingApproval builds a fresh pending approval with a `timeoutS`
// deadline. Mirrors Python's PendingApproval.new(...). idempotencyKey
// may be empty -- a UUIDv4 is generated in that case.
//
// Returns an error rather than panicking on bad inputs (timeoutS <= 0
// or now with invalid offset).
func NewPendingApproval(requestID string, timeoutS float64, idempotencyKey string, now time.Time) (*PendingApproval, error) {
	if requestID == "" {
		return nil, errors.New("request_id must be a non-empty string")
	}
	if timeoutS <= 0 {
		return nil, errors.New("timeout_s must be > 0")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if idempotencyKey == "" {
		idempotencyKey = mustUUIDv4()
	}
	return &PendingApproval{
		RequestID:      requestID,
		DeadlineAt:     now.Add(time.Duration(timeoutS * float64(time.Second))).UTC(),
		IdempotencyKey: idempotencyKey,
		Status:         StatusPending,
		PollIntervalS:  DefaultPollIntervalS,
	}, nil
}

// NewPendingApprovalRaw is the explicit-constructor form used by
// Client.RequestApproval when the backend hands back the deadline
// directly. Validates the same invariants as Python's __post_init__.
func NewPendingApprovalRaw(requestID string, deadlineAt time.Time, idempotencyKey string, status string, pollIntervalS float64) (*PendingApproval, error) {
	if requestID == "" {
		return nil, errors.New("request_id must be a non-empty string")
	}
	if idempotencyKey == "" {
		return nil, errors.New("idempotency_key must be a non-empty string")
	}
	if pollIntervalS <= 0 {
		return nil, errors.New("poll_interval_s must be > 0")
	}
	if deadlineAt.IsZero() {
		return nil, errors.New("deadline_at must be a datetime")
	}
	// Go time.Time always carries a Location. Reject Local-zone
	// times so the deadline stays unambiguously UTC.
	if deadlineAt.Location() != time.UTC {
		deadlineAt = deadlineAt.UTC()
	}
	if status == "" {
		status = StatusPending
	}
	if !IsValidStatus(status) {
		return nil, fmt.Errorf("status must be one of [approved denied pending timed_out]; got %q", status)
	}
	return &PendingApproval{
		RequestID:      requestID,
		DeadlineAt:     deadlineAt,
		IdempotencyKey: idempotencyKey,
		Status:         status,
		PollIntervalS:  pollIntervalS,
	}, nil
}

// IsTerminal reports whether the approval has reached an absorbing
// terminal state.
func (p *PendingApproval) IsTerminal() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return IsTerminalStatus(p.Status)
}

// TransitionTo moves the dataclass to newStatus if the transition is
// legal. Legal: pending -> {approved, denied, timed_out}. Anything
// else returns an error so a slice-3 response parser or a slice-4
// poll loop cannot silently clobber a previously-decided approval.
func (p *PendingApproval) TransitionTo(newStatus string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.transitionToLocked(newStatus)
}

func (p *PendingApproval) transitionToLocked(newStatus string) error {
	if !IsValidStatus(newStatus) {
		return fmt.Errorf("new_status must be one of [approved denied pending timed_out]; got %q", newStatus)
	}
	if IsTerminalStatus(p.Status) {
		return fmt.Errorf("cannot transition from terminal status %q to %q", p.Status, newStatus)
	}
	if newStatus == StatusPending {
		return fmt.Errorf("cannot transition to %q; terminal states are absorbing and pending is the initial state", StatusPending)
	}
	p.Status = newStatus
	return nil
}

// RemainingS returns seconds until DeadlineAt, clamped at 0. `now` is
// the reference instant (pass zero-value to use the current time).
func (p *PendingApproval) RemainingS(now time.Time) float64 {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	delta := p.DeadlineAt.Sub(now).Seconds()
	if delta < 0 {
		return 0
	}
	return delta
}

// nextInterval computes the sleep before poll #pollsDone using the
// design-doc cadence. Pure helper, exposed for tests.
func nextInterval(pollsDone int) float64 {
	if pollsDone <= hitlLinearPollCount {
		return DefaultPollIntervalS
	}
	// pollsDone == 11 should yield 2.0s, hence the exponent starts at 1.
	exponent := pollsDone - hitlLinearPollCount
	raw := DefaultPollIntervalS
	for i := 0; i < exponent; i++ {
		raw *= hitlBackoffMultiplier
	}
	if raw > hitlMaxPollIntervalS {
		return hitlMaxPollIntervalS
	}
	return raw
}

// PollResponse is the wire-shape every poll_fn returns. Keys mirror
// the backend's JSON response from GET /api/approval-requests/{id}.
type PollResponse map[string]any

// PollFunc is the callable the caller provides to Wait/WaitContext.
// It should issue the actual HTTP GET (or test fake) and return the
// parsed response or an error. Errors are propagated unchanged.
type PollFunc func(requestID string) (PollResponse, error)

// makeDenyDecision builds a synthetic deny PolicyDecision for a HITL
// outcome. Parity with Python's _make_deny_decision.
func makeDenyDecision(reason string) *PolicyDecision {
	return &PolicyDecision{
		Effect:   "deny",
		PolicyID: "",
		Reason:   reason,
	}
}

// makeApproveDecision builds a synthetic allow PolicyDecision for a
// HITL outcome. Parity with Python's _make_approve_decision.
func makeApproveDecision(reason string) *PolicyDecision {
	return &PolicyDecision{
		Effect:   "allow",
		PolicyID: "",
		Reason:   reason,
	}
}

// applyPollResponse processes a single poll_fn response. Returns
// (terminal, error):
//
//	terminal == true, err == nil       -> Wait returns self.
//	terminal == false, err == nil      -> keep polling.
//	err != nil                         -> propagate up.
//
// On a deny response, the returned error is *PolicyDeniedError so the
// caller can errors.As / errors.Is on it.
//
// On a wire-level "expired" response (backend sweeper authoritatively
// flipped the row to expired -- gh#707), the returned error is
// *HITLTimeoutError so the SDK does not idle until its own deadline.
func (p *PendingApproval) applyPollResponse(resp PollResponse) (bool, error) {
	state, _ := resp["state"].(string)
	switch state {
	case StatusApproved:
		p.mu.Lock()
		defer p.mu.Unlock()
		p.Decision = makeApproveDecision("HITL approver approved request")
		if err := p.transitionToLocked(StatusApproved); err != nil {
			return false, err
		}
		return true, nil
	case StatusDenied:
		p.mu.Lock()
		decision := makeDenyDecision("HITL approver denied request")
		p.Decision = decision
		err := p.transitionToLocked(StatusDenied)
		p.mu.Unlock()
		if err != nil {
			return false, err
		}
		return false, &PolicyDeniedError{Decision: *decision}
	case StatusExpired:
		// Backend sweeper authoritatively marked this row expired
		// (apps/control-zero-platform/backend/internal/workers/
		// approval_sweeper.go). Collapse onto the same StatusTimedOut
		// terminal + *HITLTimeoutError the local deadline path
		// produces; consumers see a single error type for any
		// timeout regardless of source. gh#707.
		return false, p.triggerTimeout()
	default:
		// Pending, unknown state, or missing key. Keep looping;
		// deadline enforcement bails the loop out.
		return false, nil
	}
}

// triggerTimeout flips status to timed_out and returns *HITLTimeoutError.
func (p *PendingApproval) triggerTimeout() error {
	p.mu.Lock()
	p.Decision = makeDenyDecision("HITL approval request timed out")
	err := p.transitionToLocked(StatusTimedOut)
	p.mu.Unlock()
	if err != nil {
		return err
	}
	return NewHITLTimeoutError("")
}

// SleepFunc is the sleep primitive Wait uses; injectable for tests.
type SleepFunc func(time.Duration)

// Wait blocks the calling goroutine until the approval reaches a
// terminal state or DeadlineAt elapses. pollFn is invoked repeatedly;
// the response is expected to expose a "state" key with one of
// {pending, approved, denied}.
//
// Already-terminal at entry returns (self, nil) immediately without
// calling pollFn -- mirrors Python's wait().
//
// Returns:
//
//	(self, nil)                               on approve.
//	(nil, *PolicyDeniedError)                 on deny.
//	(nil, *HITLTimeoutError)                  on timeout.
//	(nil, original error)                     on a pollFn error.
func (p *PendingApproval) Wait(pollFn PollFunc) (*PendingApproval, error) {
	return p.waitInternal(context.Background(), pollFn, time.Sleep)
}

// WaitContext is Wait with a caller-supplied context. The context's
// Done channel is checked between polls so a caller can cancel the
// wait early. Cancellation returns ctx.Err() unchanged.
func (p *PendingApproval) WaitContext(ctx context.Context, pollFn PollFunc) (*PendingApproval, error) {
	return p.waitInternal(ctx, pollFn, time.Sleep)
}

// waitInternal is the shared core. sleepFn is injected by tests via
// the unexported WaitInjected entry point.
func (p *PendingApproval) waitInternal(ctx context.Context, pollFn PollFunc, sleepFn func(time.Duration)) (*PendingApproval, error) {
	if p.IsTerminal() {
		return p, nil
	}
	if pollFn == nil {
		return nil, errors.New("controlzero: pollFn must not be nil")
	}
	if sleepFn == nil {
		sleepFn = time.Sleep
	}

	pollsDone := 0
	for {
		// Honour context cancellation before each poll. A cancel
		// after a poll but before the sleep completes is also
		// honoured below.
		if ctx != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}

		resp, err := pollFn(p.RequestID)
		pollsDone++
		if err != nil {
			return nil, err
		}
		terminal, err := p.applyPollResponse(resp)
		if err != nil {
			return nil, err
		}
		if terminal {
			return p, nil
		}

		remaining := p.RemainingS(time.Time{})
		if remaining <= 0 {
			return nil, p.triggerTimeout()
		}

		interval := nextInterval(pollsDone)
		sleepFor := interval
		if remaining < sleepFor {
			sleepFor = remaining
		}
		p.mu.Lock()
		p.PollIntervalS = sleepFor
		p.mu.Unlock()

		// Sleep with cancellation awareness when a real ctx is
		// supplied. Falls back to plain sleepFn when ctx is the
		// background ctx (no Done channel work to do).
		if ctx != nil && ctx.Done() != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-timerC(sleepFor):
			}
		} else {
			sleepFn(time.Duration(sleepFor * float64(time.Second)))
		}
	}
}

// WaitInjected is an internal test seam: same as Wait but accepts an
// injected sleep function so the cadence schedule can be observed
// without burning real wall time. Not part of the public API.
func (p *PendingApproval) WaitInjected(pollFn PollFunc, sleepFn func(time.Duration)) (*PendingApproval, error) {
	return p.waitInternal(context.Background(), pollFn, sleepFn)
}

// timerC returns a channel that fires after seconds. Wraps
// time.NewTimer so the timer is freed promptly on cancellation.
func timerC(seconds float64) <-chan time.Time {
	t := time.NewTimer(time.Duration(seconds * float64(time.Second)))
	return t.C
}
