package controlzero

// #1254: a dead/revoked/placeholder/unknown API key returned a bare
// "API key rejected (401)" that told the user neither WHY nor what to do.
// These tests pin that HostedAuthError.Error() is now actionable, that a
// structured backend 401 body is surfaced (Reason + Remediation), and that
// nothing in the user-facing message leaks which keys exist.

import (
	"strings"
	"testing"
)

func TestHostedAuthError_DefaultIsActionable(t *testing.T) {
	e := &HostedAuthError{}
	msg := e.Error()
	if !strings.Contains(strings.ToLower(msg), "rejected") {
		t.Errorf("message must say the key was rejected, got %q", msg)
	}
	if !strings.Contains(msg, "CONTROLZERO_API_KEY") {
		t.Errorf("message must name the env var, got %q", msg)
	}
	if !strings.Contains(msg, "settings/api-keys") {
		t.Errorf("message must point at the dashboard api-keys page, got %q", msg)
	}
}

func TestHostedAuthError_CustomHeadlineKeepsRemediation(t *testing.T) {
	e := &HostedAuthError{Msg: "custom headline"}
	msg := e.Error()
	if !strings.Contains(msg, "custom headline") {
		t.Errorf("custom headline must be preserved, got %q", msg)
	}
	if !strings.Contains(msg, "CONTROLZERO_API_KEY") {
		t.Errorf("remediation must still be appended, got %q", msg)
	}
}

func TestNewHostedAuthError_SurfacesBackendReasonAndRemediation(t *testing.T) {
	body := []byte(`{
		"error": {"code":"INVALID_API_KEY","message":"invalid API key"},
		"error_code":"E1101",
		"reason":"invalid_or_revoked",
		"remediation":"This API key is unknown, revoked, or expired. Create a new key at https://app.controlzero.ai/settings/api-keys and set CONTROLZERO_API_KEY to it."
	}`)
	e := newHostedAuthError(body, "")
	if e.Reason != "invalid_or_revoked" {
		t.Errorf("reason must be invalid_or_revoked, got %q", e.Reason)
	}
	if !strings.Contains(e.Remediation, "settings/api-keys") {
		t.Errorf("remediation must come from the backend body, got %q", e.Remediation)
	}
	if !strings.Contains(e.Error(), "CONTROLZERO_API_KEY") {
		t.Errorf("Error() must include the remediation, got %q", e.Error())
	}
}

func TestNewHostedAuthError_ReadsNestedErrorObject(t *testing.T) {
	body := []byte(`{"error":{"code":"INVALID_API_KEY","reason":"invalid_or_revoked","remediation":"Create a new key at https://app.controlzero.ai/settings/api-keys."}}`)
	e := newHostedAuthError(body, "")
	if e.Reason != "invalid_or_revoked" {
		t.Errorf("nested reason must be read, got %q", e.Reason)
	}
	if !strings.Contains(e.Remediation, "settings/api-keys") {
		t.Errorf("nested remediation must be read, got %q", e.Remediation)
	}
}

func TestNewHostedAuthError_ToleratesMalformedBody(t *testing.T) {
	for _, body := range [][]byte{nil, []byte(""), []byte("not json"), []byte("[1,2,3]"), []byte(`{"error":"weird"}`)} {
		e := newHostedAuthError(body, "")
		if e.Reason != "" {
			t.Errorf("no reason should be claimed for malformed body %q, got %q", body, e.Reason)
		}
		if !strings.Contains(e.Error(), "CONTROLZERO_API_KEY") {
			t.Errorf("malformed body %q must still yield an actionable message, got %q", body, e.Error())
		}
	}
}

func TestNewHostedAuthError_NoEnumerationLeakInMessage(t *testing.T) {
	body := []byte(`{"error_code":"E1101","reason":"invalid_or_revoked","remediation":"Create a new key at https://app.controlzero.ai/settings/api-keys."}`)
	e := newHostedAuthError(body, "")
	msg := strings.ToLower(e.Error())
	for _, leak := range []string{"no such key", "key not found", "never existed", "was revoked"} {
		if strings.Contains(msg, leak) {
			t.Errorf("message must not leak a specific cause (%q), got %q", leak, msg)
		}
	}
	if e.Reason != "invalid_or_revoked" {
		t.Errorf("the single coarse reason must be invalid_or_revoked, got %q", e.Reason)
	}
}

func TestNewHostedAuthError_KeepsContextPhrase(t *testing.T) {
	e := newHostedAuthError(nil, "during bundle pull")
	if !strings.Contains(e.Error(), "during bundle pull") {
		t.Errorf("context phrase must appear in the message, got %q", e.Error())
	}
}
