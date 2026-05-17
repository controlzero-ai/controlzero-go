// HITL-6c slice-6 port. Secret-value-leak guard for HITL wire payloads.
//
// Heuristics + a recursive walker to detect secret-shaped strings
// (API keys, JWTs, PEM blocks, OAuth tokens, long base64 chunks) in
// outbound payloads. The Client uses these helpers to abort BEFORE
// sending data that would leak a secret across the wire.
//
// stdlib only, no I/O. Mirrors Python's controlzero.hitl.secret_leak_guard
// 1:1, INCLUDING the gemini-fixed branches:
//
//   - JWT shape probe checks BOTH the header AND the payload segment
//     for "alg" / "typ" (the original Python impl probed payload only
//     and missed canonical JWTs).
//   - Long-b64 regex includes URL-safe characters '-' and '_' so JWT
//     payloads, OAuth tokens and GitHub PATs are caught.

package controlzero

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// _PREFIX_RE: known-vendor credential prefixes.
var prefixRe = regexp.MustCompile(
	`^(sk|pk|cz_live|cz_test|gh[pousr]_|xoxb-|xoxp-|AKIA|ASIA|AIza)`,
)

// _JWT_SHAPE_RE: three base64url segments separated by dots.
var jwtShapeRe = regexp.MustCompile(
	`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`,
)

// pemMarker: cheapest substring check; PEM blocks ALWAYS start with this.
const pemMarker = "-----BEGIN "

// _LONG_B64_RE: accepts BOTH standard base64 (`+`, `/`) AND URL-safe
// base64 (`-`, `_`). Catches modern API keys / JWTs / OAuth tokens.
// 40+ chars + optional '=' padding keeps false-positive risk low on
// natural-language text.
var longB64Re = regexp.MustCompile(`^[A-Za-z0-9+/_\-]{40,}={0,2}$`)

const (
	entropyLenFloor         = 24
	entropyBitsPerCharFloor = 3.5
)

// shannonEntropy returns bits per character. Caller must pass a
// non-empty string.
func shannonEntropy(value string) float64 {
	counts := make(map[rune]int)
	for _, ch := range value {
		counts[ch]++
	}
	total := float64(len([]rune(value)))
	entropy := 0.0
	for _, c := range counts {
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// b64urlPad appends the '=' padding base64url decoding expects.
func b64urlPad(seg string) string {
	missing := (4 - len(seg)%4) % 4
	return seg + strings.Repeat("=", missing)
}

// looksLikeJWT returns true if value has JWT shape AND either the
// header (segment 0) or the payload (segment 1) decodes to a JSON
// object containing "alg" or "typ". Mirrors Python's _looks_like_jwt
// post-gemini-fix: BOTH segments are probed, not just the payload.
func looksLikeJWT(value string) bool {
	if !jwtShapeRe.MatchString(value) {
		return false
	}
	parts := strings.Split(value, ".")
	for _, seg := range parts[:2] {
		decoded, err := base64.URLEncoding.DecodeString(b64urlPad(seg))
		if err != nil {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(decoded, &obj); err != nil {
			continue
		}
		if _, hasAlg := obj["alg"]; hasAlg {
			return true
		}
		if _, hasTyp := obj["typ"]; hasTyp {
			return true
		}
	}
	return false
}

// IsLikelySecretValue is the public heuristic. Returns true when
// `value` looks like a credential. Non-strings always return false.
func IsLikelySecretValue(value any) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	if s == "" {
		return false
	}
	if strings.Contains(s, pemMarker) {
		return true
	}
	if prefixRe.MatchString(s) {
		return true
	}
	if looksLikeJWT(s) {
		return true
	}
	if longB64Re.MatchString(s) {
		return true
	}
	if len([]rune(s)) >= entropyLenFloor {
		if shannonEntropy(s) > entropyBitsPerCharFloor {
			return true
		}
	}
	return false
}

// escapePointerToken: RFC 6901 JSON-pointer escaping.
func escapePointerToken(token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	token = strings.ReplaceAll(token, "/", "~1")
	return token
}

// ScanPayloadForSecretLeak walks `payload` recursively and returns
// JSON-pointer paths to every string leaf flagged by IsLikelySecretValue.
//
// Containers handled: map[string]any, []any, []map[string]any, []string.
// Other types (int, float, bool, nil, custom structs) are skipped
// silently -- the wire layer only carries strings as secret values.
// Circular references via map self-pointers are detected via a seen-set.
func ScanPayloadForSecretLeak(payload any) []string {
	findings := []string{}
	seen := make(map[uintptr]struct{})
	walkForLeak(payload, "", &findings, seen)
	return findings
}

// nodeID returns a pseudo-id used for cycle detection. We use the
// printed pointer value of the addressable header. For non-addressable
// values (rare in the JSON-shaped inputs we see) this returns 0,
// which means no cycle detection -- acceptable because JSON payloads
// cannot themselves contain cycles unless callers built them manually.
func nodeID(v any) uintptr {
	// fmt.Sprintf with %p formats the pointer address of any addressable
	// reference type. Strip the leading "0x" and parse. This is cheaper
	// than reflection.
	addr := fmt.Sprintf("%p", v)
	if addr == "" || addr == "0x0" {
		return 0
	}
	var p uintptr
	_, _ = fmt.Sscanf(addr, "0x%x", &p)
	return p
}

func walkForLeak(node any, path string, findings *[]string, seen map[uintptr]struct{}) {
	switch n := node.(type) {
	case string:
		if IsLikelySecretValue(n) {
			*findings = append(*findings, path)
		}
	case map[string]any:
		id := nodeID(n)
		if id != 0 {
			if _, ok := seen[id]; ok {
				return
			}
			seen[id] = struct{}{}
		}
		for key, value := range n {
			token := escapePointerToken(key)
			walkForLeak(value, path+"/"+token, findings, seen)
		}
	case []any:
		id := nodeID(n)
		if id != 0 {
			if _, ok := seen[id]; ok {
				return
			}
			seen[id] = struct{}{}
		}
		for idx, value := range n {
			walkForLeak(value, fmt.Sprintf("%s/%d", path, idx), findings, seen)
		}
	case []string:
		// Common in Go SDKs -- a list of strings. Walked like []any.
		for idx, value := range n {
			walkForLeak(value, fmt.Sprintf("%s/%d", path, idx), findings, seen)
		}
	case []map[string]any:
		for idx, value := range n {
			walkForLeak(value, fmt.Sprintf("%s/%d", path, idx), findings, seen)
		}
	default:
		// Silently skip int, float, bool, nil, custom structs, etc.
		// The wire layer can only carry strings as secret values.
	}
}

// RaiseOnLeak scans payload and returns *SecretValueLeakInPayload
// (E1709) if any string leaf looks like a secret. The error message
// lists JSON-pointer paths + the `context` string, but DELIBERATELY
// never includes the leaked values themselves. Echoing the secret
// back into an error message would defeat the point of catching it.
//
// Returns nil when the payload is clean.
func RaiseOnLeak(payload any, context string) error {
	if context == "" {
		context = "wire payload"
	}
	paths := ScanPayloadForSecretLeak(payload)
	if len(paths) == 0 {
		return nil
	}
	pathsStr := strings.Join(paths, ", ")
	return NewSecretValueLeakInPayload(
		fmt.Sprintf("secret-shaped value detected in %s at path(s): %s", context, pathsStr),
	)
}
