// Regression tests for the masked API-key hint shown in the active-source
// stderr notification (T103 follow-up, v1.7.1 security fix).
//
// Before v1.7.1 the SDK printed apiKey[:14] to stderr on every Client
// construction in hosted mode. For a cz_live_<...> key that meant 6
// characters of the customer secret leaked to terminals, screen shares,
// support transcripts, and CI logs.
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
	got := apiKeyPrefix("cz_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if got != "cz_live_***" {
		t.Fatalf("want cz_live_***, got %q", got)
	}
}

func TestApiKeyPrefix_Test(t *testing.T) {
	got := apiKeyPrefix("cz_test_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
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
	// Obviously-synthetic fixture (64 'c' bytes). The 4-char window
	// test remains meaningful: "cccc" must not appear in the masked
	// output (it cannot, since the mask is `cz_<mode>_***`). The
	// previous fixture in this file was a 64-hex string whose format
	// mimicked a customer secret too closely; replaced 2026-05-16
	// per the Publishing_Rules.md mandate.
	secretTail := strings.Repeat("c", 64)
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
