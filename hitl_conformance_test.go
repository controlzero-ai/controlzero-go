// HITL SDK conformance harness -- Go runner (issues #542 / #543 / #544).
//
// SCAFFOLD ONLY. Mirrors sdks/python/controlzero/tests/test_hitl_conformance.py
// and sdks/node/controlzero/tests/hitl-conformance.test.ts line-for-line in
// shape. Drives every scenario in tests/hitl-conformance/fixtures/sample.jsonl
// (or any file pointed at by CONTROLZERO_HITL_VECTOR) against the SDK's
// in-process MockApprovalBackend.
//
// Mirror runners:
//   - sdks/python/controlzero/tests/test_hitl_conformance.py
//   - sdks/node/controlzero/tests/hitl-conformance.test.ts
//
// All three runners consume the SAME JSONL file. A scenario that passes
// on Go but fails on Python or Node isolates the drift to the failing
// SDK -- the vector is the byte-level contract.
//
// When customer-supplied conformance vectors arrive (currently blocked
// on customer delivery), drop a new fixture file under
// tests/hitl-conformance/fixtures/ and point this runner at it via
// CONTROLZERO_HITL_VECTOR. No code change required.

package controlzero

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Vector discovery + loading
// ---------------------------------------------------------------------------

func findHITLVectorPath(t *testing.T) string {
	t.Helper()
	if override := os.Getenv("CONTROLZERO_HITL_VECTOR"); override != "" {
		abs, err := filepath.Abs(override)
		if err != nil {
			t.Fatalf("resolve CONTROLZERO_HITL_VECTOR: %v", err)
		}
		return abs
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "tests", "hitl-conformance", "fixtures", "sample.jsonl")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("tests/hitl-conformance/fixtures/sample.jsonl not found")
	return ""
}

type hitlExpected struct {
	TerminalState  *string `json:"terminal_state"`
	DecisionKind   *string `json:"decision_kind,omitempty"`
	Raises         *string `json:"raises"`
	AlreadyExpired *bool   `json:"already_expired,omitempty"`
}

type hitlScenario struct {
	ID             string       `json:"id"`
	Description    string       `json:"description"`
	MockMode       string       `json:"mock_mode"`
	DelayS         float64      `json:"delay_s"`
	TimeoutS       float64      `json:"timeout_s"`
	TTLSeconds     *int         `json:"ttl_seconds,omitempty"`
	PollUnknownID  bool         `json:"poll_unknown_id,omitempty"`
	MinSDKVersion  string       `json:"min_sdk_version,omitempty"`
	Tags           []string     `json:"tags,omitempty"`
	Expected       hitlExpected `json:"expected"`
}

func loadHITLScenarios(t *testing.T, path string) []hitlScenario {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open vector: %v", err)
	}
	defer f.Close()

	var scenarios []hitlScenario
	scanner := bufio.NewScanner(f)
	// JSONL lines can grow if scenario descriptions are long; bump
	// the buffer to a sensible ceiling.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		var s hitlScenario
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			t.Fatalf("malformed JSONL at %s:%d: %v", path, lineNum, err)
		}
		scenarios = append(scenarios, s)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan vector: %v", err)
	}
	return scenarios
}

// ---------------------------------------------------------------------------
// Per-scenario driver
// ---------------------------------------------------------------------------

// hitlObserved is the normalized outcome the harness compares against
// the scenario's expected block.
type hitlObserved struct {
	Raised                  string // "" means no exception
	TerminalState           string
	DecisionKind            string
	AlreadyExpired          bool
	ConstructedUnknownMode  bool
}

// waitForTerminalState polls the mock backend until it returns a
// non-pending state or the timeout elapses. Returns hitlObserved-style
// `(state, decisionKind, error)` -- error is non-nil only on
// timeout / unknown id.
func waitForTerminalState(
	backend *MockApprovalBackend,
	requestID string,
	timeoutS float64,
	pollIntervalS float64,
) (string, string, error) {
	deadline := time.Now().Add(time.Duration(timeoutS * float64(time.Second)))
	for {
		record, err := backend.GetRequest(requestID)
		if err != nil {
			return "", "", err
		}
		state, _ := record["state"].(string)
		if state != "pending" {
			kind, _ := record["decision_kind"].(string)
			return state, kind, nil
		}
		if time.Now().After(deadline) {
			return "", "", NewHITLTimeoutError(fmt.Sprintf(
				"approval request %s timed out after %.3fs", requestID, timeoutS,
			))
		}
		time.Sleep(time.Duration(pollIntervalS * float64(time.Second)))
	}
}

func driveHITLScenario(scenario hitlScenario) hitlObserved {
	// Unknown-mode scenario: construction is the test.
	if _, ok := MockModes[scenario.MockMode]; !ok {
		_, err := NewMockApprovalBackend(scenario.MockMode, scenario.DelayS)
		if err != nil {
			return hitlObserved{Raised: "ValueError"}
		}
		return hitlObserved{Raised: "", ConstructedUnknownMode: true}
	}

	backend, err := NewMockApprovalBackend(scenario.MockMode, scenario.DelayS)
	if err != nil {
		return hitlObserved{Raised: "ValueError"}
	}

	extras := map[string]any{}
	if scenario.TTLSeconds != nil {
		extras["ttl_seconds"] = *scenario.TTLSeconds
	}
	record, err := backend.CreateRequest("delete_file", extras)
	if err != nil {
		// Surface as a neutral "RequestNotFound"-like to keep the
		// vector-name space consistent across SDKs. Realistically only
		// hits if uuidV4() fails, which is vanishingly unlikely.
		return hitlObserved{Raised: "RequestNotFound"}
	}

	createdAt, _ := record["created_at"].(string)
	expiresAt, _ := record["expires_at"].(string)
	alreadyExpired := expiresAt <= createdAt

	requestID, _ := record["id"].(string)
	pollID := requestID
	if scenario.PollUnknownID {
		pollID = "00000000-0000-0000-0000-000000000000"
	}

	state, kind, waitErr := waitForTerminalState(backend, pollID, scenario.TimeoutS, 0.01)
	if waitErr != nil {
		if errors.Is(waitErr, ErrMockRequestNotFound) {
			return hitlObserved{Raised: "RequestNotFound", AlreadyExpired: alreadyExpired}
		}
		var timeoutErr *HITLTimeoutError
		if errors.As(waitErr, &timeoutErr) {
			return hitlObserved{Raised: "HITLTimeoutError", AlreadyExpired: alreadyExpired}
		}
		// Unexpected error shape -- surface raw so the assertion fails
		// loudly instead of swallowing.
		return hitlObserved{Raised: fmt.Sprintf("unexpected:%T", waitErr)}
	}

	observed := hitlObserved{
		TerminalState:  state,
		DecisionKind:   kind,
		AlreadyExpired: alreadyExpired,
	}
	if state == "denied" {
		observed.Raised = "PolicyDeniedError"
	}
	return observed
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

func ptrToString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func assertHITLMatches(t *testing.T, scenario hitlScenario, observed hitlObserved) {
	t.Helper()
	expectedRaises := ptrToString(scenario.Expected.Raises)
	if observed.Raised != expectedRaises {
		t.Fatalf("scenario %q: raises drift. expected=%q observed=%q",
			scenario.ID, expectedRaises, observed.Raised)
	}
	if scenario.Expected.AlreadyExpired != nil {
		if observed.AlreadyExpired != *scenario.Expected.AlreadyExpired {
			t.Fatalf("scenario %q: already_expired drift. expected=%v observed=%v",
				scenario.ID, *scenario.Expected.AlreadyExpired, observed.AlreadyExpired)
		}
	}
	if scenario.Expected.TerminalState != nil {
		if observed.TerminalState != *scenario.Expected.TerminalState {
			t.Fatalf("scenario %q: terminal_state drift. expected=%q observed=%q",
				scenario.ID, *scenario.Expected.TerminalState, observed.TerminalState)
		}
	}
	if scenario.Expected.DecisionKind != nil {
		if observed.DecisionKind != *scenario.Expected.DecisionKind {
			t.Fatalf("scenario %q: decision_kind drift. expected=%q observed=%q",
				scenario.ID, *scenario.Expected.DecisionKind, observed.DecisionKind)
		}
	}
}

// ---------------------------------------------------------------------------
// Test entry points
// ---------------------------------------------------------------------------

// knownRaises mirrors the Python/Node maps. Forward-compat: a scenario
// expecting a name not in this set is skipped with t.Skip so the
// fixture can carry future-feature scenarios without breaking the run.
var knownRaises = map[string]struct{}{
	"HITLTimeoutError":  {},
	"PolicyDeniedError": {},
	"RequestNotFound":   {},
	"ValueError":        {},
}

func TestHITLConformanceFixtureExists(t *testing.T) {
	path := findHITLVectorPath(t)
	scenarios := loadHITLScenarios(t, path)
	if len(scenarios) == 0 {
		t.Fatal("HITL conformance fixture is empty")
	}
	seen := map[string]bool{}
	for _, s := range scenarios {
		if seen[s.ID] {
			t.Fatalf("duplicate scenario id: %q", s.ID)
		}
		seen[s.ID] = true
	}
}

func TestHITLConformanceFixtureSchemaIsComplete(t *testing.T) {
	path := findHITLVectorPath(t)
	scenarios := loadHITLScenarios(t, path)
	for _, s := range scenarios {
		if s.ID == "" {
			t.Fatalf("scenario missing id: %+v", s)
		}
		if s.Description == "" {
			t.Fatalf("scenario %q missing description", s.ID)
		}
		if s.MockMode == "" {
			t.Fatalf("scenario %q missing mock_mode", s.ID)
		}
		// `raises` and `terminal_state` are both optional individually,
		// but the `expected` block must be non-empty -- at least one of
		// raises, terminal_state, or already_expired must be set so the
		// scenario is actually testing something observable.
		if s.Expected.Raises == nil &&
			s.Expected.TerminalState == nil &&
			s.Expected.AlreadyExpired == nil {
			t.Fatalf("scenario %q expected block needs raises, terminal_state, or already_expired",
				s.ID)
		}
	}
}

func TestHITLConformance(t *testing.T) {
	path := findHITLVectorPath(t)
	scenarios := loadHITLScenarios(t, path)
	if len(scenarios) == 0 {
		t.Fatal("no scenarios loaded from fixture")
	}

	for _, scenario := range scenarios {
		scenario := scenario // capture for closure
		t.Run("scenario:"+scenario.ID, func(t *testing.T) {
			if scenario.Expected.Raises != nil {
				if _, ok := knownRaises[*scenario.Expected.Raises]; !ok {
					t.Skipf("unknown raises=%q -- extend knownRaises to enable",
						*scenario.Expected.Raises)
				}
			}
			observed := driveHITLScenario(scenario)
			assertHITLMatches(t, scenario, observed)
		})
	}
}
