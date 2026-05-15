// Regression tests for the masked API-key hint shown in the active-source
// stderr notification (T103 follow-up, v1.7.1 security fix).
//
// Before v1.7.1 the SDK printed apiKey[:14] to stderr on every Client
// construction in hosted mode. For a cz_live_abcdef123456... key that
// meant 6 characters of the customer secret leaked to terminals, screen
// shares, support transcripts, and CI logs.
//
// The mask MUST:
//   - preserve the public cz_live_ / cz_test_ prefix as a mode signal
//   - NEVER emit any character beyond that prefix from the input key

package controlzero

import (
	"strings"
	"testing"
)

func TestApiKeyPrefix_Live(t *testing.T) {
	got := apiKeyPrefix("cz_live_7ebef6b600015e3eaeda9149bf6d9c29a")
	if got != "cz_live_***" {
		t.Fatalf("want cz_live_***, got %q", got)
	}
}

func TestApiKeyPrefix_Test(t *testing.T) {
	got := apiKeyPrefix("cz_test_abcdef0123456789abcdef0123456789")
	if got != "cz_test_***" {
		t.Fatalf("want cz_test_***, got %q", got)
	}
}

func TestApiKeyPrefix_UnknownPrefix(t *testing.T) {
	got := apiKeyPrefix("plain-token-1234567890")
	if got != "***" {
		t.Fatalf("want ***, got %q", got)
	}
}

func TestApiKeyPrefix_Empty(t *testing.T) {
	got := apiKeyPrefix("")
	if got != "***" {
		t.Fatalf("want ***, got %q", got)
	}
}

// TestApiKeyPrefix_NoSecretLeak scans every 4-char substring of the
// secret tail and asserts it does NOT appear in the masked output. A
// future regression that switches back to a length-prefix slice fails
// this test loudly.
func TestApiKeyPrefix_NoSecretLeak(t *testing.T) {
	// Anonymised: a real production key was leaked via
	// stderr on 2026-05-12. The customer rotated it after the
	// v1.7.0 -> v1.7.1 incident.
	secretTail := "7ebef6b600015e3eaeda9149bf6d9c29a3a2a7a3075209112afde20888280de0"
	for _, prefix := range []string{"cz_live_", "cz_test_"} {
		key := prefix + secretTail
		masked := apiKeyPrefix(key)
		for i := 0; i+4 <= len(secretTail); i++ {
			window := secretTail[i : i+4]
			if strings.Contains(masked, window) {
				t.Fatalf("secret bytes %q leaked into masked output %q (prefix %q)", window, masked, prefix)
			}
		}
	}
}
