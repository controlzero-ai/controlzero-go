// HITL-6c slice-6b port. Client.GetSecret -- fetch a secret value by
// name, gating on policy first.
//
// Mirrors Python's controlzero.client.Client.get_secret:
//
//	policy effect    outcome
//	-----------------------------------------------------------------
//	allow            GET /api/secrets/{name} returns the value.
//	hitl_required    Returns *SecretApprovalRequired with .Pending,
//	                 caller can Wait on it. Secret NOT fetched.
//	deny             Returns *PolicyDeniedError. Secret NOT fetched.
//
// On the allow path:
//
//	HTTP 200 -> string value.
//	HTTP 404 -> *SecretNotFound (E1711).
//	HTTP 401 -> *HostedAuthError (E1101).
//	anything else / network -> *HITLBackendUnreachableError (E1702).
//
// Defense-in-depth: RaiseOnLeak runs against the audit payload BEFORE
// it can hit any sink, so a logic bug elsewhere can never accidentally
// publish a secret value to the audit log. Only the secret NAME is
// logged.

package controlzero

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GetSecretOpts configures a GetSecret call.
type GetSecretOpts struct {
	// TimeoutS is the TTL the SDK requests for the HITL approval when
	// the policy demands one. Zero falls back to 300s.
	TimeoutS int

	// HTTPClient lets tests inject a custom client. Nil falls back to
	// http.DefaultClient.
	HTTPClient *http.Client

	// Decision lets callers override the policy decision used for the
	// gate. Mainly a test seam -- production callers omit this and
	// the SDK calls c.Guard("Secrets", ...).
	Decision *PolicyDecision

	// SkipGuard, if true, bypasses the policy gate. Tests set this
	// alongside Decision to mock the gate path deterministically.
	// Production callers should always leave this false.
	SkipGuard bool
}

// GetSecret fetches a secret value by name, after gating on policy.
func (c *Client) GetSecret(ctx context.Context, name string, opts GetSecretOpts) (string, error) {
	if name == "" {
		return "", errors.New("controlzero: get_secret(name) requires a non-empty string name")
	}

	// 1. Policy gate. Canonical action is "Secrets:read".
	var decision PolicyDecision
	if opts.SkipGuard && opts.Decision != nil {
		decision = *opts.Decision
	} else {
		d, err := c.Guard("Secrets", GuardOptions{
			Args:    map[string]any{"secret_name": name},
			Method:  "read",
			Context: &EvalContext{Resource: name},
		})
		if err != nil {
			// Guard only errors with RaiseOnDeny; we never set it.
			return "", err
		}
		decision = d
	}

	// 2. HITL-required branch. Engine signals it three ways:
	//    (a) effect == "hitl_required" (future first-class effect),
	//    (b) deny + reason_code starting with HITL_ (today's path),
	//    (c) deny + opts.Decision marked as hitl-eligible via the
	//        synthetic HITL_* reason code.
	isHITLRequired := decision.Effect == "hitl_required" ||
		(decision.Effect == "deny" && hasHITLReasonCode(decision.ReasonCode))

	if isHITLRequired {
		// Reason message intentionally short + low-entropy: the
		// secret-leak guard inside RequestApproval runs the message
		// through IsLikelySecretValue, and any 24+ char string with
		// > 3.5 bits/char entropy trips it. Concatenating the secret
		// name would trip that bar on realistic names.
		pending, err := c.RequestApproval(ctx, decision, RequestApprovalOpts{
			Message:  "secret read",
			TimeoutS: opts.TimeoutS,
			Context: HITLApprovalContext{
				CanonicalAction: "Secrets:read",
				Resource:        name,
				ArgsRedacted:    map[string]any{"secret_name": name},
			},
			HTTPClient: opts.HTTPClient,
		})
		if err != nil {
			// Propagate the typed error unchanged so the caller can
			// errors.As / errors.Is on the original cause.
			return "", err
		}
		return "", NewSecretApprovalRequired(
			fmt.Sprintf("HITL approval required to read secret %q", name),
			pending,
		)
	}

	// 3. Static deny path.
	if decision.Effect == "deny" {
		return "", &PolicyDeniedError{Decision: decision}
	}

	// 4. Allow path: fetch the value. Requires an API key.
	if c.apiKey == "" {
		return "", NewHITLBackendUnreachableError(
			"get_secret requires an API key (backend owns the secret store)",
		)
	}

	url := fmt.Sprintf("%s/api/secrets/%s", GetAPIURL(), name)
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return "", NewHITLBackendUnreachableError(
			fmt.Sprintf("could not build request: %v", err),
		)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = defaultHITLClient()
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", NewHITLBackendUnreachableError(
			fmt.Sprintf("GET /api/secrets/%s failed: %v", name, err),
		)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	status := resp.StatusCode

	if status == 404 {
		return "", NewSecretNotFound(fmt.Sprintf("secret %q not found", name))
	}
	if status == 401 {
		return "", &HostedAuthError{Msg: "hosted API key rejected by backend"}
	}
	if status < 200 || status >= 300 {
		return "", NewHITLBackendUnreachableError(
			fmt.Sprintf("GET /api/secrets/%s returned HTTP %d", name, status),
		)
	}

	var parsed map[string]any
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return "", NewHITLBackendUnreachableError(
			fmt.Sprintf("GET /api/secrets/%s returned non-JSON body", name),
		)
	}
	rawValue, hasValue := parsed["value"]
	if !hasValue {
		return "", NewHITLBackendUnreachableError(
			fmt.Sprintf("GET /api/secrets/%s returned malformed response body", name),
		)
	}
	value, ok := rawValue.(string)
	if !ok {
		return "", NewHITLBackendUnreachableError(
			fmt.Sprintf("GET /api/secrets/%s returned non-string value", name),
		)
	}

	// 5. Defense-in-depth: scan the audit-shaped payload before any
	//    sink can ship it. The args we sent through Guard above are
	//    {"secret_name": name} only, but a future code path might
	//    leak extra context -- catch it here BEFORE it crosses the
	//    wire.
	auditPayload := map[string]any{
		"tool":   "Secrets",
		"method": "read",
		"args":   map[string]any{"secret_name": name},
	}
	if err := RaiseOnLeak(auditPayload, "get_secret audit row"); err != nil {
		return "", err
	}

	return value, nil
}

// GetSecretPollFunc builds a poll_fn for PendingApproval.Wait that
// GETs /api/approval-requests/{requestID}. Exposed so a caller
// catching *SecretApprovalRequired can do:
//
//	err := cz.GetSecret(ctx, "prod_api_key", opts)
//	var sar *SecretApprovalRequired
//	if errors.As(err, &sar) {
//	    poll, _ := cz.GetSecretPollFunc(sar.Pending.RequestID, nil)
//	    sar.Pending.WaitContext(ctx, poll)
//	    // retry GetSecret after approval
//	}
//
// The returned closure issues a synchronous HTTP GET on each call.
// Returns *HITLBackendUnreachableError on any network or non-2xx
// response so Wait surfaces a stable exception type.
func (c *Client) GetSecretPollFunc(requestID string, httpClient *http.Client) (PollFunc, error) {
	if c.apiKey == "" {
		return nil, NewHITLBackendUnreachableError(
			"get_secret_poll_fn requires an API key",
		)
	}
	if httpClient == nil {
		httpClient = defaultHITLClient()
	}
	url := fmt.Sprintf("%s/api/approval-requests/%s", GetAPIURL(), requestID)
	apiKey := c.apiKey
	return func(_ string) (PollResponse, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, NewHITLBackendUnreachableError(
				fmt.Sprintf("could not build request: %v", err),
			)
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Accept", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, NewHITLBackendUnreachableError(
				fmt.Sprintf("GET /api/approval-requests/%s failed: %v", requestID, err),
			)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, NewHITLBackendUnreachableError(
				fmt.Sprintf("GET /api/approval-requests/%s returned HTTP %d",
					requestID, resp.StatusCode),
			)
		}
		rawBody, _ := io.ReadAll(resp.Body)
		var parsed map[string]any
		if err := json.Unmarshal(rawBody, &parsed); err != nil {
			return nil, NewHITLBackendUnreachableError(
				fmt.Sprintf("GET /api/approval-requests/%s returned non-JSON body",
					requestID),
			)
		}
		return PollResponse(parsed), nil
	}, nil
}

// hasHITLReasonCode reports whether `code` is one of the canonical
// HITL_* reason codes that signal "this deny is HITL-eligible".
// Mirrors Python's `reason_code.startswith("HITL_")` check.
func hasHITLReasonCode(code string) bool {
	const prefix = "HITL_"
	if len(code) < len(prefix) {
		return false
	}
	return code[:len(prefix)] == prefix
}
