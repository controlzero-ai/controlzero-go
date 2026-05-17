// HITL-6c secret-leak-guard tests. Mirror Python
// test_hitl_6a_secret_leak_guard.py 1:1.

package controlzero

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

func buildJWT(header, payload map[string]any) string {
	enc := func(o map[string]any) string {
		b, _ := json.Marshal(o)
		return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
	}
	return enc(header) + "." + enc(payload) + ".signaturepart"
}

// -----------------------------------------------------------------------
// IsLikelySecretValue
// -----------------------------------------------------------------------

func TestIsLikelyNonString(t *testing.T) {
	if IsLikelySecretValue(12345) {
		t.Error("non-string must return false")
	}
	if IsLikelySecretValue(nil) {
		t.Error("nil must return false")
	}
	if IsLikelySecretValue([]byte("bytes")) {
		t.Error("[]byte must return false")
	}
}

func TestIsLikelyEmptyString(t *testing.T) {
	if IsLikelySecretValue("") {
		t.Error("empty string must return false")
	}
}

func TestIsLikelyShortString(t *testing.T) {
	if IsLikelySecretValue("hello") {
		t.Error("short string must return false")
	}
}

func TestIsLikelyLowEntropyLongString(t *testing.T) {
	// 30 chars with only 2 distinct chars -> ~1 bit/char.
	if IsLikelySecretValue("aaaaaaaaaaaaaaabbbbbbbbbbbbbbb") {
		t.Error("low-entropy long string must return false")
	}
}

func TestIsLikelyRandom32CharHex(t *testing.T) {
	value := "0123456789abcdef0123456789abcdef"
	if !IsLikelySecretValue(value) {
		t.Error("32-char hex must trip entropy floor")
	}
}

func TestIsLikelyVendorPrefixes(t *testing.T) {
	for _, v := range []string{
		"sk-abc",
		"pk-zzz",
		"cz_live_abcdefghij",
		"cz_test_xxx",
		"ghp_fakebody",
		"ghu_fake",
		"gho_fake",
		"ghs_fake",
		"ghr_fake",
		"xoxb-fake-body",
		"xoxp-fake-body",
		"AKIAFAKEFAKEFAKE",
		"ASIAFAKEFAKEFAKE",
		"AIzaFakeFakeFake",
	} {
		if !IsLikelySecretValue(v) {
			t.Errorf("vendor prefix %q must trip the guard", v)
		}
	}
}

func TestIsLikelyJWTWithAlgInPayload(t *testing.T) {
	jwt := buildJWT(map[string]any{"typ": "JWT"}, map[string]any{"alg": "HS256", "sub": "u1"})
	if !IsLikelySecretValue(jwt) {
		t.Error("JWT with alg in payload must trip the guard")
	}
}

func TestIsLikelyJWTWithTypInPayload(t *testing.T) {
	jwt := buildJWT(map[string]any{"x": "y"}, map[string]any{"typ": "session"})
	if !IsLikelySecretValue(jwt) {
		t.Error("JWT with typ in payload must trip the guard")
	}
}

func TestIsLikelyJWTWithAlgInHeader(t *testing.T) {
	jwt := buildJWT(map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "user123"})
	if !IsLikelySecretValue(jwt) {
		t.Error("JWT with alg in header must trip the guard (gemini-fix)")
	}
}

func TestIsLikelyJWTShapeNonJSONMiddleReturnsFalseUnlessTooLong(t *testing.T) {
	chunk := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte("plain")), "=")
	candidate := chunk + "." + chunk + "." + chunk
	// Short candidate -> no entropy / b64 trips.
	if len(candidate) >= 40 {
		// Long enough to trip the long-b64 regex; not testable here.
		return
	}
	if IsLikelySecretValue(candidate) {
		t.Error("JWT shape with non-JSON middle and short length must return false")
	}
}

func TestIsLikelyJWTMiddleIsJSONArrayReturnsFalse(t *testing.T) {
	arr := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte("[1,2,3]")), "=")
	head := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte("ab")), "=")
	candidate := head + "." + arr + "." + head
	if len(candidate) >= 40 {
		return
	}
	if IsLikelySecretValue(candidate) {
		t.Error("JWT shape with JSON array middle must return false")
	}
}

func TestIsLikelyNonJWTShape(t *testing.T) {
	if IsLikelySecretValue("foo.bar") {
		t.Error("foo.bar (one dot) must return false")
	}
}

func TestIsLikelyPEMBlock(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
	if !IsLikelySecretValue(pem) {
		t.Error("PEM block must trip the guard")
	}
}

func TestIsLikelyLongStandardBase64(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(make([]byte, 36))
	if len(b64) < 40 {
		t.Fatalf("b64 sample too short for test: %d", len(b64))
	}
	if !IsLikelySecretValue(b64) {
		t.Errorf("long standard base64 must trip the guard, got %q", b64)
	}
}

func TestIsLikelyLongURLSafeBase64(t *testing.T) {
	urlSafe := "abc-def_ghi-jkl_mno-pqr_stu-vwx_yz0-123_456-789"
	if len(urlSafe) < 40 {
		t.Fatalf("sample too short: %d", len(urlSafe))
	}
	if !IsLikelySecretValue(urlSafe) {
		t.Error("long URL-safe base64 must trip the guard (gemini-fix)")
	}
}

// -----------------------------------------------------------------------
// ScanPayloadForSecretLeak
// -----------------------------------------------------------------------

func TestScanEmptyMap(t *testing.T) {
	if got := ScanPayloadForSecretLeak(map[string]any{}); len(got) != 0 {
		t.Errorf("scan empty map = %v, want empty", got)
	}
}

func TestScanEmptyList(t *testing.T) {
	if got := ScanPayloadForSecretLeak([]any{}); len(got) != 0 {
		t.Errorf("scan empty list = %v, want empty", got)
	}
}

func TestScanCleanPayload(t *testing.T) {
	payload := map[string]any{"name": "alice", "age": "30", "active": "yes"}
	if got := ScanPayloadForSecretLeak(payload); len(got) != 0 {
		t.Errorf("clean payload found leaks: %v", got)
	}
}

func TestScanTopLevelStringLeak(t *testing.T) {
	got := ScanPayloadForSecretLeak("sk-abc123fake")
	if len(got) != 1 || got[0] != "" {
		t.Errorf("got %v, want [\"\"]", got)
	}
}

func TestScanTopLevelStringClean(t *testing.T) {
	if got := ScanPayloadForSecretLeak("hello world"); len(got) != 0 {
		t.Errorf("clean string flagged: %v", got)
	}
}

func TestScanNestedDictWithLeak(t *testing.T) {
	payload := map[string]any{
		"headers": map[string]any{"x-api-key": "cz_live_fakebody"},
	}
	got := ScanPayloadForSecretLeak(payload)
	if len(got) != 1 || got[0] != "/headers/x-api-key" {
		t.Errorf("got %v, want [/headers/x-api-key]", got)
	}
}

func TestScanListWithIndexedLeak(t *testing.T) {
	payload := []any{map[string]any{"token": "ghp_fakebody123"}}
	got := ScanPayloadForSecretLeak(payload)
	if len(got) != 1 || got[0] != "/0/token" {
		t.Errorf("got %v, want [/0/token]", got)
	}
}

func TestScanMultipleLeaks(t *testing.T) {
	payload := map[string]any{
		"key1": "ghp_fakebody1",
		"key2": "cz_test_fakebody",
		"safe": "ok",
	}
	got := ScanPayloadForSecretLeak(payload)
	sort.Strings(got)
	want := []string{"/key1", "/key2"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestScanNonStringLeavesSkipped(t *testing.T) {
	payload := map[string]any{
		"a": 1, "b": 3.14, "c": true, "d": nil, "e": false,
	}
	if got := ScanPayloadForSecretLeak(payload); len(got) != 0 {
		t.Errorf("non-string leaves flagged: %v", got)
	}
}

func TestScanCircularDictDoesNotInfiniteLoop(t *testing.T) {
	payload := map[string]any{"k": "ok"}
	payload["self"] = payload
	got := ScanPayloadForSecretLeak(payload)
	// Tolerate either empty (cycle detected on first descent) or a
	// path that depended on iteration order; the key contract is
	// "terminates quickly".
	if len(got) > 1 {
		t.Errorf("got %v, expected at most 1", got)
	}
}

func TestScanPointerEscapingForSlashAndTilde(t *testing.T) {
	payload := map[string]any{
		"a/b": "AKIAFAKEFAKEFAKE",
		"c~d": "AKIAFAKEFAKE2222",
	}
	got := ScanPayloadForSecretLeak(payload)
	sort.Strings(got)
	want := []string{"/a~1b", "/c~0d"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestScanSliceOfStrings(t *testing.T) {
	payload := []string{"safe", "AKIAFAKEFAKEFAKE"}
	got := ScanPayloadForSecretLeak(payload)
	if len(got) != 1 || got[0] != "/1" {
		t.Errorf("got %v, want [/1]", got)
	}
}

func TestScanSliceOfMaps(t *testing.T) {
	payload := []map[string]any{
		{"safe": "ok"},
		{"leak": "AKIAFAKEFAKEFAKE"},
	}
	got := ScanPayloadForSecretLeak(payload)
	if len(got) != 1 || got[0] != "/1/leak" {
		t.Errorf("got %v, want [/1/leak]", got)
	}
}

func TestScanUnknownLeafTypeSkipped(t *testing.T) {
	type opaque struct{}
	payload := map[string]any{"obj": &opaque{}, "safe": "hi"}
	if got := ScanPayloadForSecretLeak(payload); len(got) != 0 {
		t.Errorf("unknown leaf flagged: %v", got)
	}
}

// -----------------------------------------------------------------------
// RaiseOnLeak
// -----------------------------------------------------------------------

func TestRaiseOnLeakCleanPayload(t *testing.T) {
	if err := RaiseOnLeak(map[string]any{"a": "ok", "b": 1}, ""); err != nil {
		t.Errorf("clean payload raised: %v", err)
	}
}

func TestRaiseOnLeakLeakRaises(t *testing.T) {
	err := RaiseOnLeak(map[string]any{"x-api-key": "sk-abc123fake"}, "")
	var leak *SecretValueLeakInPayload
	if !errors.As(err, &leak) {
		t.Errorf("expected *SecretValueLeakInPayload, got %T: %v", err, err)
	}
}

func TestRaiseOnLeakMessageListsPathNotValue(t *testing.T) {
	leakValue := "sk-abc123fakedontecho"
	err := RaiseOnLeak(map[string]any{
		"headers": map[string]any{"auth": leakValue},
	}, "")
	if err == nil {
		t.Fatal("expected leak")
	}
	msg := err.Error()
	if !strings.Contains(msg, "/headers/auth") {
		t.Errorf("path missing from message: %q", msg)
	}
	if strings.Contains(msg, leakValue) {
		t.Errorf("leaked value appeared in error message: %q", msg)
	}
}

func TestRaiseOnLeakContextInMessage(t *testing.T) {
	err := RaiseOnLeak(map[string]any{"k": "AKIAFAKEFAKEFAKE"}, "get_secret reply")
	if err == nil {
		t.Fatal("expected leak")
	}
	if !strings.Contains(err.Error(), "get_secret reply") {
		t.Errorf("context missing from message: %v", err)
	}
}

func TestRaiseOnLeakDefaultContextIsWirePayload(t *testing.T) {
	err := RaiseOnLeak(map[string]any{"k": "AKIAFAKEFAKEFAKE"}, "")
	if err == nil {
		t.Fatal("expected leak")
	}
	if !strings.Contains(err.Error(), "wire payload") {
		t.Errorf("default context missing: %v", err)
	}
}

func TestRaiseOnLeakMultipleLeaksAllPathsInMessage(t *testing.T) {
	err := RaiseOnLeak(map[string]any{
		"a": "AKIAFAKEFAKEFAKE",
		"b": "cz_live_fakebody",
	}, "bundle")
	if err == nil {
		t.Fatal("expected leak")
	}
	msg := err.Error()
	if !strings.Contains(msg, "/a") {
		t.Errorf("/a missing: %q", msg)
	}
	if !strings.Contains(msg, "/b") {
		t.Errorf("/b missing: %q", msg)
	}
	if !strings.Contains(msg, "bundle") {
		t.Errorf("bundle context missing: %q", msg)
	}
}

func TestEntropyOfEmptyStringDoesNotPanic(t *testing.T) {
	// Defensive: shannonEntropy on an empty string is undefined math.
	// The caller (IsLikelySecretValue) short-circuits empties; this
	// just confirms there is no hidden path where we hit the divide.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic: %v", r)
		}
	}()
	_ = IsLikelySecretValue("")
}
