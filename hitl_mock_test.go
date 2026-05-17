// HITL-6c MockApprovalBackend tests. Mirror Python
// test_hitl_6a_mock_backend.py 1:1.

package controlzero

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// Mode validation
// -----------------------------------------------------------------------

func TestMockModesSetMatchesDesignDoc(t *testing.T) {
	want := []string{
		"approve_after_2s",
		"approve_forever_after_2s",
		"approve_timed_after_2s",
		"deny_after_2s",
		"timeout",
	}
	got := MockModesList()
	if len(got) != len(want) {
		t.Fatalf("MockModesList: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("MockModesList[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestUnknownModeReturnsError(t *testing.T) {
	_, err := NewMockApprovalBackend("approve_eventually", 0.05)
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
	if !strings.Contains(err.Error(), "approve_eventually") {
		t.Errorf("error must mention the bad mode: %v", err)
	}
	if !strings.Contains(err.Error(), "approve_after_2s") {
		t.Errorf("error must list allowed modes: %v", err)
	}
}

func TestNegativeDelaySRejected(t *testing.T) {
	_, err := NewMockApprovalBackend("approve_after_2s", -1)
	if err == nil {
		t.Fatal("expected error for negative delay")
	}
}

func TestDefaultDelayIsTwoSeconds(t *testing.T) {
	be, err := NewMockApprovalBackend("approve_after_2s", 0)
	if err != nil {
		t.Fatal(err)
	}
	if be.DelayS() != 2.0 {
		t.Errorf("DelayS = %v, want 2.0", be.DelayS())
	}
}

func TestModeAccessor(t *testing.T) {
	be, _ := NewMockApprovalBackend("deny_after_2s", 0.01)
	if be.Mode() != "deny_after_2s" {
		t.Errorf("Mode = %q, want deny_after_2s", be.Mode())
	}
}

// -----------------------------------------------------------------------
// CreateRequest shape
// -----------------------------------------------------------------------

func TestCreateRequestThenImmediateGetReturnsPending(t *testing.T) {
	for _, mode := range MockModesList() {
		be, err := NewMockApprovalBackend(mode, 10.0)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := be.CreateRequest("delete_file", map[string]any{"project_id": "p1"})
		if err != nil {
			t.Fatal(err)
		}
		if rec["state"] != "pending" {
			t.Errorf("mode %s: state = %v, want pending", mode, rec["state"])
		}
		fetched, err := be.GetRequest(rec["id"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if fetched["state"] != "pending" {
			t.Errorf("mode %s: fetched state = %v, want pending", mode, fetched["state"])
		}
	}
}

func TestCreateRequestReturnsUUIDID(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.01)
	rec, _ := be.CreateRequest("delete_file", nil)
	id, ok := rec["id"].(string)
	if !ok {
		t.Fatalf("id is not string: %T", rec["id"])
	}
	if len(id) != 36 {
		t.Errorf("id length = %d, want 36", len(id))
	}
	if id[14] != '4' {
		t.Errorf("id version nibble = %q, want 4", id[14])
	}
}

func TestCreateRequestPopulatesWireFields(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.01)
	extras := map[string]any{
		"project_id":    "proj-1",
		"agent_id":      "agent-1",
		"resource":      "/tmp/x",
		"args_redacted": map[string]any{"path": "/tmp/x"},
		"args_hash":     "abc123",
		"ttl_seconds":   900,
	}
	rec, err := be.CreateRequest("delete_file", extras)
	if err != nil {
		t.Fatal(err)
	}
	if rec["canonical_action"] != "delete_file" {
		t.Errorf("canonical_action = %v", rec["canonical_action"])
	}
	if rec["project_id"] != "proj-1" {
		t.Errorf("project_id = %v", rec["project_id"])
	}
	if rec["resource"] != "/tmp/x" {
		t.Errorf("resource = %v", rec["resource"])
	}
	// expires_at - created_at should be ~900s.
	createdAt, err := time.Parse(time.RFC3339Nano, rec["created_at"].(string))
	if err != nil {
		t.Fatalf("created_at parse: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, rec["expires_at"].(string))
	if err != nil {
		t.Fatalf("expires_at parse: %v", err)
	}
	delta := expiresAt.Sub(createdAt).Seconds()
	if delta < 899 || delta > 901 {
		t.Errorf("expires-created delta = %v, want ~900", delta)
	}
	if rec["resolved_at"] != nil {
		t.Errorf("resolved_at should be nil until terminal, got %v", rec["resolved_at"])
	}
}

func TestCreateRequestDefaultTTLIs600s(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.01)
	rec, _ := be.CreateRequest("delete_file", nil)
	createdAt, _ := time.Parse(time.RFC3339Nano, rec["created_at"].(string))
	expiresAt, _ := time.Parse(time.RFC3339Nano, rec["expires_at"].(string))
	delta := expiresAt.Sub(createdAt).Seconds()
	if delta < 599 || delta > 601 {
		t.Errorf("default ttl delta = %v, want ~600", delta)
	}
}

func TestCreateRequestTTLAcceptsInt64AndFloat64(t *testing.T) {
	for _, v := range []any{int64(120), float64(120.0)} {
		be, _ := NewMockApprovalBackend("approve_after_2s", 0.01)
		rec, _ := be.CreateRequest("x", map[string]any{"ttl_seconds": v})
		createdAt, _ := time.Parse(time.RFC3339Nano, rec["created_at"].(string))
		expiresAt, _ := time.Parse(time.RFC3339Nano, rec["expires_at"].(string))
		delta := expiresAt.Sub(createdAt).Seconds()
		if delta < 119 || delta > 121 {
			t.Errorf("ttl_seconds=%v: delta = %v, want ~120", v, delta)
		}
	}
}

func TestCreateRequestKwargsCannotOverrideCanonicalFields(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.01)
	rec, _ := be.CreateRequest("delete_file", map[string]any{
		"id":         "hacker-supplied",
		"state":      "approved",
		"created_at": "1970-01-01T00:00:00Z",
	})
	if rec["id"] == "hacker-supplied" {
		t.Error("id must not be overridable")
	}
	if rec["state"] != "pending" {
		t.Errorf("state = %v, want pending", rec["state"])
	}
	// created_at must parse to a recent UTC instant, not the epoch.
	createdAt, err := time.Parse(time.RFC3339Nano, rec["created_at"].(string))
	if err != nil {
		t.Fatalf("created_at parse: %v", err)
	}
	if time.Since(createdAt) > 5*time.Second {
		t.Errorf("created_at = %v is not recent", createdAt)
	}
}

func TestCreateRequestReturnsDefensiveCopy(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 10.0)
	rec, _ := be.CreateRequest("delete_file", nil)
	rec["state"] = "approved"
	refetched, _ := be.GetRequest(rec["id"].(string))
	if refetched["state"] != "pending" {
		t.Errorf("internal state must not be mutated, got %v", refetched["state"])
	}
}

func TestCreateRequestNestedDictDeepCopy(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 10.0)
	nested := map[string]any{"x-api-key": "REDACTED"}
	rec, _ := be.CreateRequest("delete_file", map[string]any{"args_redacted": nested})
	rec["args_redacted"].(map[string]any)["x-api-key"] = "leaked-via-shallow-copy"
	refetched, _ := be.GetRequest(rec["id"].(string))
	if refetched["args_redacted"].(map[string]any)["x-api-key"] != "REDACTED" {
		t.Errorf("nested dict deep copy failed")
	}
}

func TestGetRequestNestedDictDeepCopy(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 10.0)
	nested := map[string]any{"reason": "policy-blocked"}
	rec, _ := be.CreateRequest("delete_file", map[string]any{"context": nested})
	snapA, _ := be.GetRequest(rec["id"].(string))
	snapA["context"].(map[string]any)["reason"] = "tampered"
	snapB, _ := be.GetRequest(rec["id"].(string))
	if snapB["context"].(map[string]any)["reason"] != "policy-blocked" {
		t.Errorf("get_request nested deep copy failed")
	}
}

// -----------------------------------------------------------------------
// Terminal-state behaviour per mode
// -----------------------------------------------------------------------

func waitForTerminal(t *testing.T, be *MockApprovalBackend, id string, capS float64) map[string]any {
	t.Helper()
	deadline := time.Now().Add(time.Duration(capS * float64(time.Second)))
	last, err := be.GetRequest(id)
	if err != nil {
		t.Fatal(err)
	}
	for last["state"] == "pending" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		last, _ = be.GetRequest(id)
	}
	return last
}

func TestApproveAfter2sFlipsToApprovedOnce(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.05)
	rec, _ := be.CreateRequest("delete_file", nil)
	term := waitForTerminal(t, be, rec["id"].(string), 2.0)
	if term["state"] != "approved" {
		t.Errorf("state = %v, want approved", term["state"])
	}
	if term["decision_kind"] != "approved_once" {
		t.Errorf("decision_kind = %v, want approved_once", term["decision_kind"])
	}
	if term["resolved_at"] == nil {
		t.Error("resolved_at must be set on terminal transition")
	}
}

func TestApproveTimedAfter2sExtendsExpiresAt(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_timed_after_2s", 0.05)
	rec, _ := be.CreateRequest("delete_file", map[string]any{"ttl_seconds": 60})
	originalExpires, _ := time.Parse(time.RFC3339Nano, rec["expires_at"].(string))
	term := waitForTerminal(t, be, rec["id"].(string), 2.0)
	if term["state"] != "approved" {
		t.Errorf("state = %v", term["state"])
	}
	if term["decision_kind"] != "approved_timed" {
		t.Errorf("decision_kind = %v", term["decision_kind"])
	}
	newExpires, _ := time.Parse(time.RFC3339Nano, term["expires_at"].(string))
	if !newExpires.After(originalExpires) {
		t.Errorf("new expires (%v) must be after original (%v)", newExpires, originalExpires)
	}
	if !newExpires.After(time.Now().UTC()) {
		t.Error("new expires must be in the future")
	}
}

func TestApproveForeverAfter2sMarksGrant(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_forever_after_2s", 0.05)
	rec, _ := be.CreateRequest("delete_file", nil)
	term := waitForTerminal(t, be, rec["id"].(string), 2.0)
	if term["state"] != "approved" {
		t.Errorf("state = %v", term["state"])
	}
	if term["decision_kind"] != "approved_forever_grant" {
		t.Errorf("decision_kind = %v", term["decision_kind"])
	}
}

func TestDenyAfter2sFlipsToDeniedNoDecisionKind(t *testing.T) {
	be, _ := NewMockApprovalBackend("deny_after_2s", 0.05)
	rec, _ := be.CreateRequest("delete_file", nil)
	term := waitForTerminal(t, be, rec["id"].(string), 2.0)
	if term["state"] != "denied" {
		t.Errorf("state = %v, want denied", term["state"])
	}
	if _, has := term["decision_kind"]; has {
		t.Errorf("denied terminal must not carry decision_kind, got %v", term["decision_kind"])
	}
	if term["resolved_at"] == nil {
		t.Error("resolved_at must be set on deny")
	}
}

func TestTimeoutModeStaysPendingForever(t *testing.T) {
	be, _ := NewMockApprovalBackend("timeout", 0.01)
	rec, _ := be.CreateRequest("delete_file", nil)
	time.Sleep(100 * time.Millisecond)
	fetched, _ := be.GetRequest(rec["id"].(string))
	if fetched["state"] != "pending" {
		t.Errorf("timeout mode must stay pending forever, got %v", fetched["state"])
	}
	if _, has := fetched["decision_kind"]; has {
		t.Errorf("timeout mode must not set decision_kind")
	}
	if fetched["resolved_at"] != nil {
		t.Errorf("timeout mode must keep resolved_at=nil, got %v", fetched["resolved_at"])
	}
}

func TestTerminalStateIsSticky(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.05)
	rec, _ := be.CreateRequest("delete_file", nil)
	first := waitForTerminal(t, be, rec["id"].(string), 2.0)
	second, _ := be.GetRequest(rec["id"].(string))
	third, _ := be.GetRequest(rec["id"].(string))
	if second["state"] != "approved" || third["state"] != "approved" {
		t.Error("terminal state not sticky")
	}
	if second["resolved_at"] != first["resolved_at"] {
		t.Error("resolved_at must not move once terminal")
	}
}

// -----------------------------------------------------------------------
// id stability + unknown-id contract
// -----------------------------------------------------------------------

func TestRequestIDRoundTrips(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.01)
	rec, _ := be.CreateRequest("delete_file", nil)
	fetched, _ := be.GetRequest(rec["id"].(string))
	if fetched["id"] != rec["id"] {
		t.Errorf("id round-trip failed")
	}
}

func TestGetRequestUnknownIDReturnsErrMockRequestNotFound(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.01)
	_, err := be.GetRequest("not-a-real-id")
	if err == nil {
		t.Fatal("expected error for unknown id")
	}
	if !errors.Is(err, ErrMockRequestNotFound) {
		t.Errorf("expected ErrMockRequestNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), "not-a-real-id") {
		t.Errorf("error must mention the unknown id: %v", err)
	}
}

func TestDistinctCreateCallsGetDistinctIDs(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.01)
	ids := map[string]bool{}
	for i := 0; i < 10; i++ {
		rec, _ := be.CreateRequest("delete_file", nil)
		ids[rec["id"].(string)] = true
	}
	if len(ids) != 10 {
		t.Errorf("got %d distinct ids, want 10", len(ids))
	}
}

// -----------------------------------------------------------------------
// AsPollFunc -- end-to-end with Wait path
// -----------------------------------------------------------------------

func TestAsPollFuncReturnsCurrentSnapshot(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.05)
	rec, _ := be.CreateRequest("delete_file", nil)
	poll := be.AsPollFunc()
	resp, err := poll(rec["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if resp["state"] != "pending" {
		t.Errorf("immediate poll state = %v, want pending", resp["state"])
	}
}

func TestAsPollFuncPropagatesUnknownID(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.05)
	poll := be.AsPollFunc()
	_, err := poll("missing")
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------
// Thread safety
// -----------------------------------------------------------------------

func TestConcurrentPollersConsistentTerminal(t *testing.T) {
	be, _ := NewMockApprovalBackend("approve_after_2s", 0.1)
	rec, _ := be.CreateRequest("delete_file", nil)
	id := rec["id"].(string)

	stop := make(chan struct{})
	failed := atomic.Int32{}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap, err := be.GetRequest(id)
				if err != nil {
					failed.Add(1)
					return
				}
				if snap["state"] == "approved" {
					if snap["decision_kind"] != "approved_once" {
						failed.Add(1)
					}
					if snap["resolved_at"] == nil {
						failed.Add(1)
					}
				} else if snap["state"] != "pending" {
					failed.Add(1)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}

	term := waitForTerminal(t, be, id, 2.0)
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	if failed.Load() != 0 {
		t.Errorf("pollers saw inconsistent snapshots (%d failures)", failed.Load())
	}
	if term["state"] != "approved" {
		t.Errorf("terminal state = %v, want approved", term["state"])
	}
}

// -----------------------------------------------------------------------
// deepCopyAny edge cases (slice/nil)
// -----------------------------------------------------------------------

func TestDeepCopyMapNil(t *testing.T) {
	if got := deepCopyMap(nil); got != nil {
		t.Errorf("deepCopyMap(nil) = %v, want nil", got)
	}
}

func TestDeepCopyAnyHandlesSlices(t *testing.T) {
	src := []any{1, "two", []any{3, 4}, map[string]any{"k": "v"}}
	cloned := deepCopyAny(src).([]any)
	cloned[2].([]any)[0] = 999
	if src[2].([]any)[0] != 3 {
		t.Errorf("deep copy of []any inner slice failed")
	}
	cloned[3].(map[string]any)["k"] = "mutated"
	if src[3].(map[string]any)["k"] != "v" {
		t.Errorf("deep copy of map-in-slice failed")
	}
}

func TestDeepCopyAnyHandlesSliceOfMaps(t *testing.T) {
	src := []map[string]any{{"a": 1}, {"b": 2}}
	cloned := deepCopyAny(src).([]map[string]any)
	cloned[0]["a"] = 999
	if src[0]["a"] != 1 {
		t.Errorf("[]map[string]any deep copy failed")
	}
}

func TestDeepCopyAnyPassesThroughScalar(t *testing.T) {
	if got := deepCopyAny(42); got != 42 {
		t.Errorf("deepCopyAny(42) = %v, want 42", got)
	}
	if got := deepCopyAny("hi"); got != "hi" {
		t.Errorf("deepCopyAny(\"hi\") = %v", got)
	}
}
