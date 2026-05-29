// HITL Phase 2d Go-SDK protocol port. Mirrors the Python (Phase 2b)
// and Node (Phase 2c) implementations of the grants protocol.
//
// When a PolicyDecision lands with RequiresApproval=true, the SDK
// posts a grant request to /api/grants and then polls
// /api/grants/{id} until the grant is approved, denied, expired, or
// the caller's context is cancelled. Same defaults as the other two
// SDKs: 5 min default timeout (configurable via
// CONTROLZERO_HITL_TIMEOUT_SECS, capped at 30 min), 1->10 s
// exponential poll backoff, fail-closed on every error path.
//
// The protocol does NOT touch the existing approval-request flow in
// client_request_approval.go -- that is the older HITL-6c port. This
// file is the forward-looking grants surface that the new policy
// engine uses when a rule says "requires_approval".

package controlzero

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// Grant protocol tunables. Mirror the Python and Node ports.
const (
	// grantDefaultTimeoutSecs is the default deadline the SDK waits
	// for a grant decision when the caller does not override.
	grantDefaultTimeoutSecs = 5 * 60

	// grantMaxTimeoutSecs caps the effective deadline so a runaway
	// env var or rule cannot hold a worker indefinitely.
	grantMaxTimeoutSecs = 30 * 60

	// grantPollInitialSecs is the first sleep between polls.
	grantPollInitialSecs = 1

	// grantPollMaxSecs is the cap on the exponential backoff.
	grantPollMaxSecs = 10

	// grantPollBackoffMultiplier is the factor applied each poll
	// until the cap is reached. 1 -> 2 -> 4 -> 8 -> 10 -> 10 ...
	grantPollBackoffMultiplier = 2

	// grantHTTPTimeoutSecs is the per-request HTTP timeout. Distinct
	// from the wait deadline above: every individual POST / GET must
	// finish inside this window or the SDK treats it as a network
	// error and fails closed.
	grantHTTPTimeoutSecs = 10

	// grantTimeoutEnvVar is the env var that overrides
	// grantDefaultTimeoutSecs. Documented in CHANGELOG.
	grantTimeoutEnvVar = "CONTROLZERO_HITL_TIMEOUT_SECS"
)

// GrantStatus is the wire-level status returned by
// GET /api/grants/{id}.
const (
	GrantStatusPending  = "pending"
	GrantStatusApproved = "approved"
	GrantStatusDenied   = "denied"
	GrantStatusExpired  = "expired"
)

// GrantProtocolOpts configures a single MaybeAwaitGrant call.
//
// Zero value is valid -- it uses the package defaults and an internal
// HTTP client. Tests inject their own client + clock to exercise the
// poll cadence without burning real seconds.
type GrantProtocolOpts struct {
	// TimeoutSecs overrides grantDefaultTimeoutSecs. Capped at
	// grantMaxTimeoutSecs. Zero falls through to the env var, then
	// to the default.
	TimeoutSecs int

	// HTTPClient lets tests inject a custom client. Nil falls back
	// to defaultHITLClient.
	HTTPClient *http.Client

	// SleepFn lets tests skip real sleeps. Nil uses time.Sleep.
	SleepFn func(time.Duration)
}

// GrantOutcome is the terminal result of a grant flow. Exactly one
// of Approved / Denied / Expired is true. Failures (network error,
// context cancel, malformed response) DO NOT produce a GrantOutcome;
// they return a non-nil error and the caller must treat the original
// decision as deny.
type GrantOutcome struct {
	GrantID   string
	Status    string
	Approved  bool
	Denied    bool
	Expired   bool
	RawBody   map[string]any
}

// resolveGrantTimeoutSecs picks the effective wait deadline. Order:
// explicit opts -> env var -> package default. Always clamped to
// (0, grantMaxTimeoutSecs].
func resolveGrantTimeoutSecs(opts GrantProtocolOpts) int {
	if opts.TimeoutSecs > 0 {
		return clampTimeout(opts.TimeoutSecs)
	}
	if raw := os.Getenv(grantTimeoutEnvVar); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			return clampTimeout(parsed)
		}
	}
	return grantDefaultTimeoutSecs
}

func clampTimeout(v int) int {
	if v > grantMaxTimeoutSecs {
		return grantMaxTimeoutSecs
	}
	if v < 1 {
		return 1
	}
	return v
}

// nextGrantPollSecs walks the backoff schedule. Pure helper, exposed
// for tests via the package-internal seam.
func nextGrantPollSecs(prev int) int {
	if prev <= 0 {
		return grantPollInitialSecs
	}
	nxt := prev * grantPollBackoffMultiplier
	if nxt > grantPollMaxSecs {
		return grantPollMaxSecs
	}
	return nxt
}

// MaybeAwaitGrant inspects the PolicyDecision, and if
// RequiresApproval is true, drives the grants protocol. Returns the
// terminal GrantOutcome on a clean approve / deny / expire, or a
// non-nil error on any failure path (network, timeout, ctx-cancel,
// malformed response). Callers MUST treat a non-nil error as deny.
//
// When decision.RequiresApproval is false the method returns
// (nil, nil) immediately -- the decision stands as-is.
func (c *Client) MaybeAwaitGrant(ctx context.Context, decision PolicyDecision, opts GrantProtocolOpts) (*GrantOutcome, error) {
	if !decision.RequiresApproval {
		return nil, nil
	}
	if c.apiKey == "" {
		return nil, NewHITLBackendUnreachableError(
			"grants protocol requires an API key",
		)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	grantID, expiresAt, err := c.requestGrant(ctx, decision, opts)
	if err != nil {
		return nil, err
	}
	return c.pollGrant(ctx, grantID, expiresAt, opts)
}

// requestGrant POSTs /api/grants with the canonical_action drawn
// from decision.ApprovalAction (or the policy_id as a fallback) and
// returns the grant_id plus the backend-authoritative expires_at.
//
// Fail-closed semantics: any non-2xx, any network error, any
// malformed body returns HITLBackendUnreachableError so the caller
// treats it as deny.
func (c *Client) requestGrant(ctx context.Context, decision PolicyDecision, opts GrantProtocolOpts) (string, time.Time, error) {
	timeoutSecs := resolveGrantTimeoutSecs(opts)

	action := ""
	if decision.ApprovalAction != nil {
		action = *decision.ApprovalAction
	}
	if action == "" {
		action = decision.PolicyID
	}

	body := map[string]any{
		"canonical_action": action,
		"policy_id":        decision.PolicyID,
		"reason":           decision.Reason,
		"reason_code":      decision.ReasonCode,
		"ttl_seconds":      timeoutSecs,
		"surface":          "go-sdk",
	}
	if err := RaiseOnLeak(body, "grant request body"); err != nil {
		return "", time.Time{}, err
	}
	idempotencyKey, err := uuidV4()
	if err != nil {
		return "", time.Time{}, NewHITLBackendUnreachableErrorWithCause(
			"could not generate idempotency key",
			err,
		)
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", time.Time{}, NewHITLBackendUnreachableErrorWithCause(
			"could not marshal grant request body",
			err,
		)
	}

	reqCtx, cancel := context.WithTimeout(ctx, grantHTTPTimeoutSecs*time.Second)
	defer cancel()

	url := GetAPIURL() + "/api/grants"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return "", time.Time{}, NewHITLBackendUnreachableErrorWithCause(
			"could not build grant request",
			err,
		)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)
	if email := readEmailFromConfig(); email != "" {
		req.Header.Set("X-CZ-Requestor-Email", email)
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = defaultHITLClient()
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Distinguish ctx-cancel from network for a cleaner error
		// chain; either way the SDK fails closed and the caller
		// must treat the decision as deny.
		if errors.Is(err, context.Canceled) {
			return "", time.Time{}, NewHITLBackendUnreachableErrorWithCause(
				"grant request cancelled by caller", ctx.Err(),
			)
		}
		return "", time.Time{}, NewHITLBackendUnreachableErrorWithCause(
			fmt.Sprintf("POST /api/grants failed: %s", err.Error()), err,
		)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", time.Time{}, NewHITLBackendUnreachableError(
			fmt.Sprintf("POST /api/grants returned HTTP %d", resp.StatusCode),
		)
	}
	var parsed map[string]any
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return "", time.Time{}, NewHITLBackendUnreachableError(
			"POST /api/grants returned non-JSON body",
		)
	}
	grantID, _ := parsed["grant_id"].(string)
	if grantID == "" {
		// Backend may also use "id" as the canonical field name.
		grantID, _ = parsed["id"].(string)
	}
	if grantID == "" {
		return "", time.Time{}, NewHITLBackendUnreachableError(
			"POST /api/grants response missing grant_id",
		)
	}
	expiresAt := time.Time{}
	if raw, ok := parsed["expires_at"].(string); ok && raw != "" {
		if parsedTime, perr := parseISO8601UTC(raw); perr == nil {
			expiresAt = parsedTime
		}
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(time.Duration(timeoutSecs) * time.Second)
	}
	return grantID, expiresAt, nil
}

// pollGrant drives the GET /api/grants/{id} loop with the documented
// 1 -> 10 s exponential backoff, capped at the resolved wait
// deadline. Honours ctx.Done at every loop tick and before each
// sleep. Returns:
//
//	(*GrantOutcome, nil)   on approve / deny / expire.
//	(nil, error)           on ctx-cancel, deadline, network, or
//	                       malformed response. Caller MUST deny.
func (c *Client) pollGrant(ctx context.Context, grantID string, expiresAt time.Time, opts GrantProtocolOpts) (*GrantOutcome, error) {
	timeoutSecs := resolveGrantTimeoutSecs(opts)
	deadline := time.Now().UTC().Add(time.Duration(timeoutSecs) * time.Second)
	if !expiresAt.IsZero() && expiresAt.Before(deadline) {
		deadline = expiresAt
	}

	sleepFn := opts.SleepFn
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = defaultHITLClient()
	}
	url := GetAPIURL() + "/api/grants/" + grantID

	currentSleep := 0
	for {
		// Honour context cancellation before each network call.
		select {
		case <-ctx.Done():
			return nil, NewHITLBackendUnreachableErrorWithCause(
				"grant poll cancelled by caller", ctx.Err(),
			)
		default:
		}

		outcome, terminal, err := c.pollGrantOnce(ctx, httpClient, url)
		if err != nil {
			return nil, err
		}
		if terminal {
			return outcome, nil
		}

		// Not terminal. Check deadline before sleeping.
		now := time.Now().UTC()
		if !now.Before(deadline) {
			return nil, NewHITLTimeoutError(
				fmt.Sprintf("grant %s did not resolve before deadline", grantID),
			)
		}
		currentSleep = nextGrantPollSecs(currentSleep)
		sleepDur := time.Duration(currentSleep) * time.Second
		if remaining := deadline.Sub(now); remaining < sleepDur {
			sleepDur = remaining
		}

		// Sleep with ctx awareness. Tests can replace sleepFn for
		// the deadline-cap path; the ctx-cancel path is exercised
		// via real ctx cancellation.
		if sleepFn != nil {
			sleepFn(sleepDur)
		} else {
			timer := time.NewTimer(sleepDur)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, NewHITLBackendUnreachableErrorWithCause(
					"grant poll cancelled by caller during sleep",
					ctx.Err(),
				)
			case <-timer.C:
			}
		}
	}
}

// pollGrantOnce issues a single GET. Returns (outcome, terminal,
// err). terminal=true means the loop should return outcome to the
// caller; terminal=false + err==nil means keep polling.
func (c *Client) pollGrantOnce(ctx context.Context, httpClient *http.Client, url string) (*GrantOutcome, bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, grantHTTPTimeoutSecs*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, NewHITLBackendUnreachableErrorWithCause(
			"could not build grant poll request", err,
		)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, false, NewHITLBackendUnreachableErrorWithCause(
				"grant poll cancelled by caller", ctx.Err(),
			)
		}
		return nil, false, NewHITLBackendUnreachableErrorWithCause(
			fmt.Sprintf("GET %s failed: %s", url, err.Error()), err,
		)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false, NewHITLBackendUnreachableError(
			fmt.Sprintf("GET %s returned HTTP %d", url, resp.StatusCode),
		)
	}
	var parsed map[string]any
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, false, NewHITLBackendUnreachableError(
			"grant poll returned non-JSON body",
		)
	}
	status, _ := parsed["status"].(string)
	if status == "" {
		// Backend may put the value under "state" -- accept both
		// shapes so a v0 / v1 endpoint switch does not break the
		// SDK silently.
		status, _ = parsed["state"].(string)
	}
	grantID, _ := parsed["grant_id"].(string)
	if grantID == "" {
		grantID, _ = parsed["id"].(string)
	}
	switch status {
	case GrantStatusApproved:
		return &GrantOutcome{
			GrantID: grantID, Status: status,
			Approved: true, RawBody: parsed,
		}, true, nil
	case GrantStatusDenied:
		return &GrantOutcome{
			GrantID: grantID, Status: status,
			Denied: true, RawBody: parsed,
		}, true, nil
	case GrantStatusExpired:
		return &GrantOutcome{
			GrantID: grantID, Status: status,
			Expired: true, RawBody: parsed,
		}, true, nil
	case GrantStatusPending, "":
		return nil, false, nil
	default:
		// Unknown status from the backend -- fail closed.
		return nil, false, NewHITLBackendUnreachableError(
			fmt.Sprintf("grant poll returned unknown status %q", status),
		)
	}
}
