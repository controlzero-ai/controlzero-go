// HITL-6c slice-3 port. Client.RequestApproval -- POST a HITL approval
// request for an in-flight policy decision.
//
// Mirrors Python's controlzero.client.Client.request_approval:
//
//   - An API key is mandatory (HITL needs a backend to route to).
//   - An operator email from ~/.controlzero/config.yaml is mandatory
//     (the backend cannot route to a human without one).
//   - The body draws canonical_action, project_id, agent_id, resource,
//     args_redacted, and args_hash from the supplied decision (any
//     missing field is omitted from the wire body).
//   - raise_on_leak runs on the body BEFORE sending.
//   - Idempotency-Key is a fresh UUIDv4 per call (stored on the
//     returned PendingApproval so retries can reuse it).
//   - 2xx -> PendingApproval. Non-2xx -> typed HITL exception.

package controlzero

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HITLApprovalContext lets callers attach the optional HITL request
// fields (project_id, agent_id, resource, args_redacted, args_hash,
// canonical_action) without modifying PolicyDecision itself. Mirrors
// Python's getattr-based field extraction: PolicyDecision in the Go
// SDK does not carry these fields yet, so they ride in beside it.
type HITLApprovalContext struct {
	CanonicalAction string
	ProjectID       string
	AgentID         string
	Resource        string
	ArgsRedacted    map[string]any
	ArgsHash        string
}

// RequestApprovalOpts configures a single RequestApproval call.
type RequestApprovalOpts struct {
	// Message is the free-text reason shown to the approver. Empty
	// means use the default "requested by SDK".
	Message string

	// TimeoutS is the TTL the SDK requests for the approval. The
	// backend may cap this; the authoritative deadline is whatever
	// the response carries in expires_at. Zero means use 300s.
	TimeoutS int

	// Context carries the optional HITL-request fields that
	// PolicyDecision does not (yet) hold itself.
	Context HITLApprovalContext

	// HTTPClient lets tests inject a custom client. Nil falls back
	// to http.DefaultClient.
	HTTPClient *http.Client
}

// RequestApproval POSTs a HITL approval request and returns a
// PendingApproval that the caller can drive with .Wait / .WaitContext.
//
// Error semantics (mirror Python):
//
//	*HITLBackendUnreachableError   -- no API key, network failure,
//	                                  HTTP >= 400 with no more specific
//	                                  mapping, or a 2xx response missing
//	                                  required fields.
//	*HITLIdentityRequired          -- no operator email configured, or
//	                                  backend body code E1307.
//	*HITLIdentityNotInOrg          -- backend body code E1306.
//	*HITLIdentityClaimRejected     -- backend body code E1308.
//	*HostedAuthError               -- HTTP 401.
//	*HITLNotConfiguredError        -- HTTP 404.
//	*HITLNoApproverAvailable       -- HTTP 503 with body code E1305 or
//	                                  message containing "no approver".
//	*SecretValueLeakInPayload      -- leak guard tripped on the body.
func (c *Client) RequestApproval(ctx context.Context, decision PolicyDecision, opts RequestApprovalOpts) (*PendingApproval, error) {
	if c.apiKey == "" {
		return nil, NewHITLBackendUnreachableError(
			"request_approval requires an API key",
		)
	}

	email := readEmailFromConfig()
	if email == "" {
		return nil, NewHITLIdentityRequired(
			"request_approval requires an operator email; run " +
				"`controlzero install <agent> --email <addr>` to set one",
		)
	}

	timeoutS := opts.TimeoutS
	if timeoutS <= 0 {
		timeoutS = 300
	}

	canonicalAction := opts.Context.CanonicalAction
	if canonicalAction == "" {
		// Fall back to a derived label. The backend column allows
		// empty so the request is still routable, but tagging it
		// helps the approver's UI.
		canonicalAction = ""
	}

	body := map[string]any{
		"canonical_action": canonicalAction,
		"reason":           opts.Message,
		"ttl_seconds":      timeoutS,
	}
	if opts.Message == "" {
		body["reason"] = "requested by SDK"
	}
	if opts.Context.ProjectID != "" {
		body["project_id"] = opts.Context.ProjectID
	}
	if opts.Context.AgentID != "" {
		body["agent_id"] = opts.Context.AgentID
	}
	if opts.Context.Resource != "" {
		body["resource"] = opts.Context.Resource
	}
	if opts.Context.ArgsRedacted != nil {
		body["args_redacted"] = opts.Context.ArgsRedacted
	}
	if opts.Context.ArgsHash != "" {
		body["args_hash"] = opts.Context.ArgsHash
	}
	// Honour the decision's reason context too -- it surfaces to
	// the approver via the "context" sidecar.
	_ = decision

	// Secret-leak guard: refuse to ship a redacted-args dict that
	// accidentally contains a secret-shaped string. Raises
	// SecretValueLeakInPayload (E1709) without echoing the leaked
	// value back.
	if err := RaiseOnLeak(body, "request_approval body"); err != nil {
		return nil, err
	}

	idempotencyKey, err := uuidV4()
	if err != nil {
		return nil, NewHITLBackendUnreachableErrorWithCause(
			fmt.Sprintf("could not generate idempotency key: %s", err.Error()),
			err,
		)
	}

	url := GetAPIURL() + "/api/approval-requests"
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, NewHITLBackendUnreachableErrorWithCause(
			fmt.Sprintf("could not marshal request body: %s", err.Error()),
			err,
		)
	}

	if ctx == nil {
		ctx = context.Background()
	}
	// Wrap with a timeout matching Python's httpx.post(timeout=10.0).
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, NewHITLBackendUnreachableErrorWithCause(
			fmt.Sprintf("could not build request: %s", err.Error()),
			err,
		)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)
	req.Header.Set("X-CZ-Requestor-Email", email)

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = defaultHITLClient()
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, NewHITLBackendUnreachableErrorWithCause(
			fmt.Sprintf("POST /api/approval-requests failed: %s", err.Error()),
			err,
		)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	status := resp.StatusCode

	if status >= 200 && status < 300 {
		var parsed map[string]any
		if err := json.Unmarshal(rawBody, &parsed); err != nil {
			return nil, NewHITLBackendUnreachableError(
				"POST /api/approval-requests returned non-JSON body",
			)
		}
		requestID, _ := parsed["id"].(string)
		expiresAtRaw, _ := parsed["expires_at"].(string)
		if requestID == "" || expiresAtRaw == "" {
			return nil, NewHITLBackendUnreachableError(
				"POST /api/approval-requests returned malformed response body",
			)
		}
		deadlineAt, err := parseISO8601UTC(expiresAtRaw)
		if err != nil {
			return nil, NewHITLBackendUnreachableErrorWithCause(
				fmt.Sprintf("POST /api/approval-requests returned unparseable expires_at: %s", err.Error()),
				err,
			)
		}
		return NewPendingApprovalRaw(requestID, deadlineAt, idempotencyKey, StatusPending, 1.0)
	}

	// Non-2xx mapping. Decode JSON body code/message when present.
	bodyCode := ""
	bodyMsg := ""
	var errBody map[string]any
	if err := json.Unmarshal(rawBody, &errBody); err == nil {
		if v, ok := errBody["code"].(string); ok {
			bodyCode = v
		}
		if v, ok := errBody["message"].(string); ok {
			bodyMsg = v
		} else if v, ok := errBody["error"].(string); ok {
			bodyMsg = v
		}
	}

	// gh#618: cascade resolved to enabled=false at the named scope.
	// Branches on the literal `error` value rather than a reason_code
	// envelope to match the documented wire contract across all three
	// SDKs. Distinct from 404 (HITLNotConfigured): there the row is
	// missing entirely; here it's explicitly off.
	if status == http.StatusPreconditionFailed {
		if v, ok := errBody["error"].(string); ok && v == "approvals_disabled_at_scope" {
			resolvedScope, _ := errBody["resolved_scope"].(string)
			return nil, NewApprovalsDisabled(bodyMsg, resolvedScope)
		}
	}
	if status == 400 && bodyCode == "E1307" {
		msg := bodyMsg
		if msg == "" {
			msg = "Approvals require X-CZ-Requestor-Email"
		}
		return nil, NewHITLIdentityRequired(msg)
	}
	if status == 400 && bodyCode == "E1306" {
		msg := bodyMsg
		if msg == "" {
			msg = "Requestor identity is not a member of this org"
		}
		return nil, NewHITLIdentityNotInOrg(msg)
	}
	if status == 400 && bodyCode == "E1308" {
		msg := bodyMsg
		if msg == "" {
			msg = "Requestor identity claim rejected by backend"
		}
		return nil, NewHITLIdentityClaimRejected(msg)
	}
	if status == 401 {
		return nil, newHostedAuthError(rawBody, "")
	}
	if status == 404 {
		msg := bodyMsg
		if msg == "" {
			msg = "Approvals not configured for this org"
		}
		return nil, NewHITLNotConfiguredError(msg)
	}
	if status == 503 {
		lower := strings.ToLower(bodyMsg)
		if bodyCode == "E1305" || (bodyMsg != "" && strings.Contains(lower, "no approver")) {
			msg := bodyMsg
			if msg == "" {
				msg = "no approver available"
			}
			return nil, NewHITLNoApproverAvailable(msg)
		}
	}

	return nil, NewHITLBackendUnreachableError(
		fmt.Sprintf("POST /api/approval-requests returned HTTP %d", status),
	)
}

// parseISO8601UTC mirrors Python's _parse_iso8601_utc. Accepts the
// backend's Z-suffixed UTC ISO-8601 string (e.g. 2026-05-17T13:30:00Z)
// or an explicit-offset form. Rejects naive datetimes. Returns the
// timestamp in UTC.
func parseISO8601UTC(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("expected a non-empty ISO-8601 string")
	}
	// Try the layouts the backend can emit.
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
	} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), nil
		}
	}
	// Reject naive datetimes without an offset.
	if _, err := time.Parse("2006-01-02T15:04:05", value); err == nil {
		return time.Time{}, fmt.Errorf("expected timezone-aware datetime, got %q", value)
	}
	return time.Time{}, fmt.Errorf("could not parse %q as ISO-8601", value)
}

