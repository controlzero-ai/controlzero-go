// HITL-6c PendingApproval tests. Mirror Python's
// test_hitl_6a_pending_approval.py + test_hitl_6a_wait.py 1:1.

package controlzero

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// Status helpers
// -----------------------------------------------------------------------

func TestIsValidStatus(t *testing.T) {
	for _, s := range []string{StatusPending, StatusApproved, StatusDenied, StatusTimedOut} {
		if !IsValidStatus(s) {
			t.Errorf("%q must be a valid status", s)
		}
	}
	if IsValidStatus("garbage") {
		t.Error("garbage must not be valid")
	}
}

func TestIsTerminalStatus(t *testing.T) {
	if IsTerminalStatus(StatusPending) {
		t.Error("pending must not be terminal")
	}
	for _, s := range []string{StatusApproved, StatusDenied, StatusTimedOut} {
		if !IsTerminalStatus(s) {
			t.Errorf("%q must be terminal", s)
		}
	}
}

func TestUUIDv4Format(t *testing.T) {
	u, err := uuidV4()
	if err != nil {
		t.Fatalf("uuidV4: %v", err)
	}
	if len(u) != 36 {
		t.Errorf("uuid length: got %d, want 36", len(u))
	}
	// Should contain 4 dashes at canonical positions.
	for _, pos := range []int{8, 13, 18, 23} {
		if u[pos] != '-' {
			t.Errorf("uuid dash position %d: got %q in %q", pos, u[pos], u)
		}
	}
	// Version nibble = 4
	if u[14] != '4' {
		t.Errorf("uuid version nibble: got %q want 4", u[14])
	}
}

func TestUUIDv4Distinct(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 32; i++ {
		u, err := uuidV4()
		if err != nil {
			t.Fatalf("uuidV4: %v", err)
		}
		if seen[u] {
			t.Errorf("duplicate uuid: %s", u)
		}
		seen[u] = true
	}
}

// -----------------------------------------------------------------------
// Constructor validation
// -----------------------------------------------------------------------

func TestNewPendingApprovalDefaults(t *testing.T) {
	pa, err := NewPendingApproval("req-1", DefaultTimeoutS, "", time.Time{})
	if err != nil {
		t.Fatalf("NewPendingApproval: %v", err)
	}
	if pa.RequestID != "req-1" {
		t.Errorf("RequestID = %q, want req-1", pa.RequestID)
	}
	if pa.Status != StatusPending {
		t.Errorf("Status = %q, want pending", pa.Status)
	}
	if pa.PollIntervalS != DefaultPollIntervalS {
		t.Errorf("PollIntervalS = %v, want %v", pa.PollIntervalS, DefaultPollIntervalS)
	}
	if pa.IdempotencyKey == "" {
		t.Error("IdempotencyKey must auto-generate when empty")
	}
	if pa.Decision != nil {
		t.Errorf("Decision must default to nil, got %v", pa.Decision)
	}
}

func TestNewPendingApprovalCustomTimeoutPicksFutureDeadline(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	pa, err := NewPendingApproval("req-1", 42.5, "key", now)
	if err != nil {
		t.Fatalf("NewPendingApproval: %v", err)
	}
	want := now.Add(time.Duration(42.5 * float64(time.Second)))
	if !pa.DeadlineAt.Equal(want) {
		t.Errorf("DeadlineAt = %v, want %v", pa.DeadlineAt, want)
	}
}

func TestNewPendingApprovalIdempotencyKeyPreserved(t *testing.T) {
	pa, err := NewPendingApproval("req-1", 60, "fixed-key", time.Time{})
	if err != nil {
		t.Fatalf("NewPendingApproval: %v", err)
	}
	if pa.IdempotencyKey != "fixed-key" {
		t.Errorf("IdempotencyKey = %q, want fixed-key", pa.IdempotencyKey)
	}
}

func TestNewPendingApprovalRejectsEmptyRequestID(t *testing.T) {
	_, err := NewPendingApproval("", 60, "k", time.Time{})
	if err == nil {
		t.Fatal("expected error for empty request_id")
	}
}

func TestNewPendingApprovalRejectsNonPositiveTimeout(t *testing.T) {
	for _, tv := range []float64{0, -1, -100} {
		_, err := NewPendingApproval("r", tv, "k", time.Time{})
		if err == nil {
			t.Errorf("expected error for timeout=%v", tv)
		}
	}
}

func TestNewPendingApprovalDefaultNow(t *testing.T) {
	before := time.Now().UTC()
	pa, err := NewPendingApproval("r", 10, "k", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()
	if pa.DeadlineAt.Before(before.Add(10 * time.Second)) {
		t.Errorf("DeadlineAt %v is too early (expected >= %v)", pa.DeadlineAt, before.Add(10*time.Second))
	}
	if pa.DeadlineAt.After(after.Add(10 * time.Second)) {
		t.Errorf("DeadlineAt %v is too late", pa.DeadlineAt)
	}
}

// -----------------------------------------------------------------------
// Raw constructor validation
// -----------------------------------------------------------------------

func TestNewPendingApprovalRawHappyPath(t *testing.T) {
	deadline := time.Now().Add(60 * time.Second).UTC()
	pa, err := NewPendingApprovalRaw("r", deadline, "k", "", 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if pa.Status != StatusPending {
		t.Errorf("default status = %q, want pending", pa.Status)
	}
}

func TestNewPendingApprovalRawRejectsEmptyRequestID(t *testing.T) {
	_, err := NewPendingApprovalRaw("", time.Now().Add(60*time.Second), "k", "pending", 1.0)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewPendingApprovalRawRejectsEmptyIdempotencyKey(t *testing.T) {
	_, err := NewPendingApprovalRaw("r", time.Now().Add(60*time.Second), "", "pending", 1.0)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewPendingApprovalRawRejectsZeroDeadline(t *testing.T) {
	_, err := NewPendingApprovalRaw("r", time.Time{}, "k", "pending", 1.0)
	if err == nil {
		t.Fatal("expected error for zero deadline")
	}
}

func TestNewPendingApprovalRawRejectsNonPositivePollInterval(t *testing.T) {
	_, err := NewPendingApprovalRaw("r", time.Now().Add(60*time.Second), "k", "pending", 0)
	if err == nil {
		t.Fatal("expected error for poll_interval_s = 0")
	}
	_, err = NewPendingApprovalRaw("r", time.Now().Add(60*time.Second), "k", "pending", -1)
	if err == nil {
		t.Fatal("expected error for poll_interval_s = -1")
	}
}

func TestNewPendingApprovalRawRejectsInvalidStatus(t *testing.T) {
	_, err := NewPendingApprovalRaw("r", time.Now().Add(60*time.Second), "k", "garbage", 1.0)
	if err == nil {
		t.Fatal("expected error for unknown status")
	}
}

func TestNewPendingApprovalRawAcceptsAnyValidStatus(t *testing.T) {
	for _, s := range []string{StatusPending, StatusApproved, StatusDenied, StatusTimedOut} {
		_, err := NewPendingApprovalRaw("r", time.Now().Add(60*time.Second), "k", s, 1.0)
		if err != nil {
			t.Errorf("status %q rejected: %v", s, err)
		}
	}
}

func TestNewPendingApprovalRawNonUTCNormalizedToUTC(t *testing.T) {
	// Construct a deadline in a non-UTC location.
	tz, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tz not available: %v", err)
	}
	deadline := time.Now().In(tz).Add(60 * time.Second)
	pa, err := NewPendingApprovalRaw("r", deadline, "k", "pending", 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if pa.DeadlineAt.Location() != time.UTC {
		t.Errorf("DeadlineAt location = %v, want UTC", pa.DeadlineAt.Location())
	}
}

// -----------------------------------------------------------------------
// State machine
// -----------------------------------------------------------------------

func makeApproval(t *testing.T) *PendingApproval {
	t.Helper()
	pa, err := NewPendingApproval("req-1", 60, "k", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return pa
}

func TestIsTerminalTrueForAllTerminalStates(t *testing.T) {
	for _, s := range []string{StatusApproved, StatusDenied, StatusTimedOut} {
		pa := makeApproval(t)
		pa.Status = s
		if !pa.IsTerminal() {
			t.Errorf("status %q must be terminal", s)
		}
	}
}

func TestIsTerminalFalseForPending(t *testing.T) {
	pa := makeApproval(t)
	if pa.IsTerminal() {
		t.Errorf("status pending must not be terminal")
	}
}

func TestTransitionToHappyPaths(t *testing.T) {
	for _, target := range []string{StatusApproved, StatusDenied, StatusTimedOut} {
		pa := makeApproval(t)
		if err := pa.TransitionTo(target); err != nil {
			t.Errorf("transition pending -> %q: %v", target, err)
		}
		if pa.Status != target {
			t.Errorf("expected status %q, got %q", target, pa.Status)
		}
	}
}

func TestTransitionToRejectsBackToPending(t *testing.T) {
	pa := makeApproval(t)
	err := pa.TransitionTo(StatusPending)
	if err == nil {
		t.Fatal("expected error transitioning to pending")
	}
	if !strings.Contains(err.Error(), "pending") {
		t.Errorf("error must mention pending: %v", err)
	}
}

func TestTransitionToRejectsFromTerminal(t *testing.T) {
	pa := makeApproval(t)
	if err := pa.TransitionTo(StatusApproved); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{StatusApproved, StatusDenied, StatusTimedOut} {
		err := pa.TransitionTo(target)
		if err == nil {
			t.Errorf("expected error transitioning from terminal -> %q", target)
		}
	}
}

func TestTransitionToRejectsUnknownStatus(t *testing.T) {
	pa := makeApproval(t)
	if err := pa.TransitionTo("queued"); err == nil {
		t.Fatal("expected error for unknown status")
	}
}

// -----------------------------------------------------------------------
// remaining_s
// -----------------------------------------------------------------------

func TestRemainingSPositiveBeforeDeadline(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pa, _ := NewPendingApprovalRaw("r", anchor.Add(42*time.Second), "k", "pending", 1.0)
	got := pa.RemainingS(anchor)
	if got != 42 {
		t.Errorf("RemainingS = %v, want 42", got)
	}
}

func TestRemainingSZeroAfterDeadline(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pa, _ := NewPendingApprovalRaw("r", anchor.Add(-10*time.Second), "k", "pending", 1.0)
	if got := pa.RemainingS(anchor); got != 0 {
		t.Errorf("RemainingS = %v, want 0", got)
	}
}

func TestRemainingSExactlyAtDeadlineIsZero(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pa, _ := NewPendingApprovalRaw("r", anchor, "k", "pending", 1.0)
	if got := pa.RemainingS(anchor); got != 0 {
		t.Errorf("RemainingS = %v, want 0", got)
	}
}

func TestRemainingSDefaultsToNow(t *testing.T) {
	pa, _ := NewPendingApproval("r", 60, "k", time.Time{})
	got := pa.RemainingS(time.Time{})
	if got <= 0 || got > 60 {
		t.Errorf("RemainingS = %v, want in (0, 60]", got)
	}
}

// -----------------------------------------------------------------------
// Cadence (next_interval)
// -----------------------------------------------------------------------

func TestNextIntervalLinearZone(t *testing.T) {
	for i := 1; i <= 10; i++ {
		if got := nextInterval(i); got != DefaultPollIntervalS {
			t.Errorf("nextInterval(%d) = %v, want %v", i, got, DefaultPollIntervalS)
		}
	}
}

func TestNextIntervalDoublesAfterLinear(t *testing.T) {
	if got := nextInterval(11); got != 2.0 {
		t.Errorf("nextInterval(11) = %v, want 2.0", got)
	}
	if got := nextInterval(12); got != 4.0 {
		t.Errorf("nextInterval(12) = %v, want 4.0", got)
	}
	if got := nextInterval(13); got != 8.0 {
		t.Errorf("nextInterval(13) = %v, want 8.0", got)
	}
}

func TestNextIntervalCapsAtTen(t *testing.T) {
	for _, n := range []int{14, 20, 100} {
		if got := nextInterval(n); got != 10.0 {
			t.Errorf("nextInterval(%d) = %v, want 10.0", n, got)
		}
	}
}

// -----------------------------------------------------------------------
// synthetic decision helpers
// -----------------------------------------------------------------------

func TestMakeDenyDecisionShape(t *testing.T) {
	d := makeDenyDecision("user denied")
	if d.Effect != "deny" {
		t.Errorf("Effect = %q, want deny", d.Effect)
	}
	if d.Reason != "user denied" {
		t.Errorf("Reason = %q", d.Reason)
	}
	if !d.Denied() {
		t.Error("Denied() must be true")
	}
}

func TestMakeApproveDecisionShape(t *testing.T) {
	d := makeApproveDecision("ok")
	if d.Effect != "allow" {
		t.Errorf("Effect = %q, want allow", d.Effect)
	}
	if !d.Allowed() {
		t.Error("Allowed() must be true")
	}
}

// -----------------------------------------------------------------------
// Wait -- blocking
// -----------------------------------------------------------------------

func TestWaitHappyApprove(t *testing.T) {
	pa := makeApproval(t)
	sleepCalls := []time.Duration{}
	pollCalls := 0
	responses := []PollResponse{
		{"id": "req-1", "state": "pending"},
		{"id": "req-1", "state": "pending"},
		{"id": "req-1", "state": "pending"},
		{"id": "req-1", "state": "approved"},
	}
	pollFn := func(rid string) (PollResponse, error) {
		if rid != pa.RequestID {
			t.Errorf("poll rid = %q, want %q", rid, pa.RequestID)
		}
		r := responses[pollCalls]
		pollCalls++
		return r, nil
	}
	sleepFn := func(d time.Duration) {
		sleepCalls = append(sleepCalls, d)
	}
	result, err := pa.WaitInjected(pollFn, sleepFn)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result != pa {
		t.Error("Wait must return self")
	}
	if pa.Status != StatusApproved {
		t.Errorf("Status = %q, want approved", pa.Status)
	}
	if pollCalls != 4 {
		t.Errorf("pollCalls = %d, want 4", pollCalls)
	}
	if len(sleepCalls) != 3 {
		t.Errorf("sleepCalls = %d, want 3", len(sleepCalls))
	}
	for _, d := range sleepCalls {
		if d != 1*time.Second {
			t.Errorf("sleep = %v, want 1s", d)
		}
	}
	if pa.Decision == nil || pa.Decision.Effect != "allow" {
		t.Errorf("Decision missing or wrong: %+v", pa.Decision)
	}
}

func TestWaitHappyDeny(t *testing.T) {
	pa := makeApproval(t)
	pollCalls := 0
	responses := []PollResponse{
		{"id": "r", "state": "pending"},
		{"id": "r", "state": "denied"},
	}
	pollFn := func(rid string) (PollResponse, error) {
		r := responses[pollCalls]
		pollCalls++
		return r, nil
	}
	_, err := pa.WaitInjected(pollFn, func(time.Duration) {})
	if err == nil {
		t.Fatal("expected PolicyDeniedError")
	}
	var pde *PolicyDeniedError
	if !errors.As(err, &pde) {
		t.Errorf("expected *PolicyDeniedError, got %T: %v", err, err)
	}
	if pa.Status != StatusDenied {
		t.Errorf("Status = %q, want denied", pa.Status)
	}
	if pa.Decision == nil || pa.Decision.Effect != "deny" {
		t.Errorf("Decision missing or wrong: %+v", pa.Decision)
	}
	if !errors.Is(err, ErrPolicyDenied) {
		t.Error("deny error must satisfy errors.Is(err, ErrPolicyDenied)")
	}
}

func TestWaitTimeoutPath(t *testing.T) {
	// Tiny deadline; first poll returns pending and the wait loop
	// should bail via deadline check after the (also capped) sleep.
	pa, _ := NewPendingApproval("r", 0.05, "k", time.Time{})
	pollFn := func(string) (PollResponse, error) {
		return PollResponse{"state": "pending"}, nil
	}
	_, err := pa.Wait(pollFn)
	if err == nil {
		t.Fatal("expected HITLTimeoutError")
	}
	var hto *HITLTimeoutError
	if !errors.As(err, &hto) {
		t.Errorf("expected *HITLTimeoutError, got %T: %v", err, err)
	}
	if pa.Status != StatusTimedOut {
		t.Errorf("Status = %q, want timed_out", pa.Status)
	}
	if !errors.Is(err, ErrPolicyDenied) {
		t.Error("timeout error must satisfy errors.Is(err, ErrPolicyDenied)")
	}
}

func TestWaitAlreadyTerminalShortCircuits(t *testing.T) {
	pa := makeApproval(t)
	if err := pa.TransitionTo(StatusApproved); err != nil {
		t.Fatal(err)
	}
	called := false
	pollFn := func(string) (PollResponse, error) {
		called = true
		return nil, nil
	}
	result, err := pa.WaitInjected(pollFn, func(time.Duration) {
		t.Error("sleep must not be called when already terminal")
	})
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("pollFn must not be called when already terminal")
	}
	if result != pa {
		t.Error("Wait must return self")
	}
}

func TestWaitCadenceFirstBackoffAfterTenPolls(t *testing.T) {
	pa := makeApproval(t)
	pollCalls := 0
	pollFn := func(string) (PollResponse, error) {
		pollCalls++
		if pollCalls <= 11 {
			return PollResponse{"state": "pending"}, nil
		}
		return PollResponse{"state": "approved"}, nil
	}
	intervals := []time.Duration{}
	_, err := pa.WaitInjected(pollFn, func(d time.Duration) {
		intervals = append(intervals, d)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(intervals) != 11 {
		t.Fatalf("intervals = %d, want 11", len(intervals))
	}
	for i := 0; i < 10; i++ {
		if intervals[i] != 1*time.Second {
			t.Errorf("intervals[%d] = %v, want 1s", i, intervals[i])
		}
	}
	if intervals[10] != 2*time.Second {
		t.Errorf("intervals[10] = %v, want 2s", intervals[10])
	}
}

func TestWaitBackoffCeilingAtTenSeconds(t *testing.T) {
	pa, _ := NewPendingApproval("r", 600, "k", time.Time{})
	pollCalls := 0
	pollFn := func(string) (PollResponse, error) {
		pollCalls++
		if pollCalls <= 20 {
			return PollResponse{"state": "pending"}, nil
		}
		return PollResponse{"state": "approved"}, nil
	}
	intervals := []time.Duration{}
	_, err := pa.WaitInjected(pollFn, func(d time.Duration) {
		intervals = append(intervals, d)
	})
	if err != nil {
		t.Fatal(err)
	}
	// 10 polls -> 10 sleeps at 1.0s; then 2,4,8,then capped 10.
	if intervals[10] != 2*time.Second {
		t.Errorf("intervals[10] = %v, want 2s", intervals[10])
	}
	if intervals[11] != 4*time.Second {
		t.Errorf("intervals[11] = %v, want 4s", intervals[11])
	}
	if intervals[12] != 8*time.Second {
		t.Errorf("intervals[12] = %v, want 8s", intervals[12])
	}
	for i := 13; i < len(intervals); i++ {
		if intervals[i] != 10*time.Second {
			t.Errorf("intervals[%d] = %v, want 10s", i, intervals[i])
		}
	}
}

func TestWaitPollFnErrorPropagates(t *testing.T) {
	pa := makeApproval(t)
	myErr := errors.New("boom")
	_, err := pa.Wait(func(string) (PollResponse, error) {
		return nil, myErr
	})
	if !errors.Is(err, myErr) {
		t.Errorf("expected myErr, got %v", err)
	}
	if pa.Status != StatusPending {
		t.Errorf("Status must stay pending on poll error, got %q", pa.Status)
	}
}

func TestWaitUnknownStateKeepsPollingUntilTimeout(t *testing.T) {
	pa, _ := NewPendingApproval("r", 0.05, "k", time.Time{})
	pollFn := func(string) (PollResponse, error) {
		return PollResponse{"state": "in_review"}, nil
	}
	_, err := pa.Wait(pollFn)
	var hto *HITLTimeoutError
	if !errors.As(err, &hto) {
		t.Errorf("expected timeout, got %T: %v", err, err)
	}
}

// gh#707: backend sweeper marks the row state='expired'. The wait loop
// must surface *HITLTimeoutError on the first poll that observes that
// state, NOT idle through its own backoff schedule until DeadlineAt.
func TestWaitExpiredStateRaisesTimeoutWithinOnePoll(t *testing.T) {
	// Generous 5-minute deadline: a regression that "keeps polling"
	// would surface as multiple poll calls and nonzero sleeps; the
	// fix is observable as exactly 1 poll, 0 sleeps.
	pa, err := NewPendingApproval("r", 300.0, "k", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	pollCalls := 0
	pollFn := func(string) (PollResponse, error) {
		pollCalls++
		return PollResponse{"id": "r", "state": StatusExpired}, nil
	}
	sleepCalls := 0
	_, err = pa.WaitInjected(pollFn, func(time.Duration) {
		sleepCalls++
	})
	if err == nil {
		t.Fatal("expected *HITLTimeoutError")
	}
	var hto *HITLTimeoutError
	if !errors.As(err, &hto) {
		t.Errorf("expected *HITLTimeoutError, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrPolicyDenied) {
		t.Error("expired -> timeout error must satisfy errors.Is(err, ErrPolicyDenied)")
	}
	if pa.Status != StatusTimedOut {
		t.Errorf("Status = %q, want timed_out", pa.Status)
	}
	if pollCalls != 1 {
		t.Errorf("pollCalls = %d, want 1 (sweeper-driven expired must bail immediately)", pollCalls)
	}
	if sleepCalls != 0 {
		t.Errorf("sleepCalls = %d, want 0 (no idle after expired)", sleepCalls)
	}
	if pa.Decision == nil || pa.Decision.Effect != "deny" {
		t.Errorf("Decision missing or wrong: %+v", pa.Decision)
	}
}

// gh#707: pending tick followed by expired tick still bails on the
// expired observation, not on the local deadline.
func TestWaitExpiredAfterPendingBailsOnExpiredTick(t *testing.T) {
	pa, err := NewPendingApproval("r", 300.0, "k", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	pollCalls := 0
	pollFn := func(string) (PollResponse, error) {
		pollCalls++
		if pollCalls == 1 {
			return PollResponse{"id": "r", "state": StatusPending}, nil
		}
		return PollResponse{"id": "r", "state": StatusExpired}, nil
	}
	sleepCalls := 0
	_, err = pa.WaitInjected(pollFn, func(time.Duration) {
		sleepCalls++
	})
	var hto *HITLTimeoutError
	if !errors.As(err, &hto) {
		t.Errorf("expected *HITLTimeoutError, got %T: %v", err, err)
	}
	if pa.Status != StatusTimedOut {
		t.Errorf("Status = %q, want timed_out", pa.Status)
	}
	if pollCalls != 2 {
		t.Errorf("pollCalls = %d, want 2", pollCalls)
	}
	// One sleep between the two polls; no further sleeps after
	// the expired observation.
	if sleepCalls != 1 {
		t.Errorf("sleepCalls = %d, want 1", sleepCalls)
	}
}

func TestStatusExpiredWireConstant(t *testing.T) {
	// gh#707: wire-level constant exposed for callers that match
	// against the backend's sweeper output. NOT part of validStatuses
	// (the SDK has no `expired` terminal -- it collapses onto
	// timed_out).
	if StatusExpired != "expired" {
		t.Errorf("StatusExpired = %q, want %q", StatusExpired, "expired")
	}
	if IsValidStatus(StatusExpired) {
		t.Error("StatusExpired must NOT be a valid SDK status (it is wire-only)")
	}
	if IsTerminalStatus(StatusExpired) {
		t.Error("StatusExpired must NOT be a terminal SDK status (mapped onto timed_out)")
	}
}

func TestWaitNilPollFnErrors(t *testing.T) {
	pa := makeApproval(t)
	_, err := pa.WaitInjected(nil, func(time.Duration) {})
	if err == nil {
		t.Fatal("expected error for nil pollFn")
	}
}

func TestWaitInjectedNilSleepFnFallsBackToRealSleep(t *testing.T) {
	pa, _ := NewPendingApproval("r", 0.05, "k", time.Time{})
	// passing nil for sleepFn must fall back to time.Sleep silently
	pollFn := func(string) (PollResponse, error) {
		return PollResponse{"state": "pending"}, nil
	}
	_, err := pa.WaitInjected(pollFn, nil)
	var hto *HITLTimeoutError
	if !errors.As(err, &hto) {
		t.Errorf("expected timeout, got %T: %v", err, err)
	}
}

// -----------------------------------------------------------------------
// WaitContext -- cancellation
// -----------------------------------------------------------------------

func TestWaitContextCancelBeforeFirstPoll(t *testing.T) {
	pa := makeApproval(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := pa.WaitContext(ctx, func(string) (PollResponse, error) {
		t.Error("pollFn must not be called after ctx cancel")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestWaitContextCancelMidSleep(t *testing.T) {
	pa, _ := NewPendingApproval("r", 60, "k", time.Time{})
	ctx, cancel := context.WithCancel(context.Background())
	// First poll returns pending; cancel during the 1s sleep.
	called := atomic.Int32{}
	pollFn := func(string) (PollResponse, error) {
		called.Add(1)
		return PollResponse{"state": "pending"}, nil
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := pa.WaitContext(ctx, pollFn)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if called.Load() < 1 {
		t.Error("pollFn should have run once")
	}
}

func TestWaitContextHappyApproveOnFirstPoll(t *testing.T) {
	pa := makeApproval(t)
	ctx := context.Background()
	result, err := pa.WaitContext(ctx, func(string) (PollResponse, error) {
		return PollResponse{"state": "approved"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result != pa {
		t.Error("Wait must return self")
	}
}

func TestWaitContextAlreadyTerminal(t *testing.T) {
	pa := makeApproval(t)
	if err := pa.TransitionTo(StatusDenied); err != nil {
		t.Fatal(err)
	}
	result, err := pa.WaitContext(context.Background(), func(string) (PollResponse, error) {
		t.Error("pollFn must not be called when already terminal")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result != pa {
		t.Error("Wait must return self")
	}
}

func TestWaitContextDeadlineExceeded(t *testing.T) {
	pa, _ := NewPendingApproval("r", 0.05, "k", time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err := pa.WaitContext(ctx, func(string) (PollResponse, error) {
		return PollResponse{"state": "pending"}, nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
	// Either context.DeadlineExceeded (the ctx fired first) or
	// *HITLTimeoutError (the approval deadline fired first) is
	// acceptable; both indicate termination of the wait.
	if !errors.Is(err, context.DeadlineExceeded) {
		var hto *HITLTimeoutError
		if !errors.As(err, &hto) {
			t.Errorf("expected DeadlineExceeded or *HITLTimeoutError, got %T: %v", err, err)
		}
	}
}

// -----------------------------------------------------------------------
// Concurrency smoke -- one goroutine per Wait, no torn reads.
// -----------------------------------------------------------------------

func TestWaitConcurrentApprovals(t *testing.T) {
	const N = 8
	approvals := make([]*PendingApproval, N)
	for i := 0; i < N; i++ {
		pa, _ := NewPendingApproval("r", 60, "k", time.Time{})
		approvals[i] = pa
	}
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(pa *PendingApproval) {
			defer wg.Done()
			_, _ = pa.WaitInjected(func(string) (PollResponse, error) {
				return PollResponse{"state": "approved"}, nil
			}, func(time.Duration) {})
		}(approvals[i])
	}
	wg.Wait()
	for i, pa := range approvals {
		if pa.Status != StatusApproved {
			t.Errorf("approval[%d] status = %q, want approved", i, pa.Status)
		}
	}
}

// -----------------------------------------------------------------------
// Integration: drive Wait against MockApprovalBackend
// -----------------------------------------------------------------------

func TestWaitAgainstMockBackend(t *testing.T) {
	be, err := NewMockApprovalBackend("approve_after_2s", 0.02)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := be.CreateRequest("delete_file", nil)
	if err != nil {
		t.Fatal(err)
	}
	pa, err := NewPendingApprovalRaw(
		rec["id"].(string),
		time.Now().Add(5*time.Second).UTC(),
		"k", "pending", 1.0,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := pa.Wait(be.AsPollFunc())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result != pa {
		t.Error("Wait must return self")
	}
	if pa.Status != StatusApproved {
		t.Errorf("Status = %q, want approved", pa.Status)
	}
}

func TestTimerCFiresAfterInterval(t *testing.T) {
	start := time.Now()
	<-timerC(0.01)
	elapsed := time.Since(start)
	if elapsed < 8*time.Millisecond {
		t.Errorf("timerC fired too early: %v", elapsed)
	}
}

// Cover transitionToLocked's "from terminal" branch via applyPollResponse
// when status is somehow already terminal. Calling applyPollResponse on
// a terminal approval should still attempt transition; transitionToLocked
// catches and returns an error.
func TestApplyPollResponseOnAlreadyTerminalReturnsError(t *testing.T) {
	pa := makeApproval(t)
	if err := pa.TransitionTo(StatusDenied); err != nil {
		t.Fatal(err)
	}
	// Now an approve response should hit the "from terminal"
	// guard inside transitionToLocked.
	_, err := pa.applyPollResponse(PollResponse{"state": "approved"})
	if err == nil {
		t.Fatal("expected error transitioning from terminal")
	}
}

func TestApplyPollResponseDenyOnAlreadyTerminalReturnsError(t *testing.T) {
	pa := makeApproval(t)
	if err := pa.TransitionTo(StatusApproved); err != nil {
		t.Fatal(err)
	}
	_, err := pa.applyPollResponse(PollResponse{"state": "denied"})
	if err == nil {
		t.Fatal("expected error transitioning from terminal")
	}
}

func TestTriggerTimeoutOnAlreadyTerminalReturnsError(t *testing.T) {
	pa := makeApproval(t)
	if err := pa.TransitionTo(StatusApproved); err != nil {
		t.Fatal(err)
	}
	err := pa.triggerTimeout()
	if err == nil {
		t.Fatal("expected error triggering timeout on terminal approval")
	}
}
