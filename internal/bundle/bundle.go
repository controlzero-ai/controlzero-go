// Package bundle parses the .czpolicy signed binary bundle format.
//
// See docs/designs/policy-bundle-format.md for the authoritative spec.
//
// This package is a pure-function parser: given bundle bytes plus the
// project encryption key and signing public key, it either returns the
// decrypted policy payload as a map[string]any, or a typed error.
//
// No I/O. No network. No global state. All fetching, caching, and
// retries live in the hosted_policy module.
//
// Wire format (little-endian):
//
//	offset  size  field
//	0       4     magic           ASCII "CZ01"
//	4       2     schema_version  uint16
//	6       8     created_at      uint64 UNIX seconds
//	14      2     policy_count    uint16 (informational)
//	16      4     sig_offset      uint32 (absolute byte offset of signature)
//	20      4     sig_len         uint32 (must be 64)
//	24      8     reserved        must be zero
//	32      N     payload         authenticated-encryption over zstd(json)
//	32+N    64    signature       detached signature over header[0:32] || payload
package bundle

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/klauspost/compress/zstd"
)

const (
	headerSize         = 32
	sigLen             = 64
	schemaVersionMax   = 1
	gcmNonceSize       = 12
	gcmTagSize         = 16
	defaultMaxBundleSz = 16 * 1024 * 1024
)

var magic = []byte("CZ01")

// Header carries the fixed fields at the front of a bundle.
type Header struct {
	SchemaVersion uint16
	CreatedAt     uint64
	PolicyCount   uint16
	SigOffset     uint32
	SigLen        uint32
}

// Parsed is the decoded output of Parse.
type Parsed struct {
	Header  Header
	Payload map[string]any
}

// FormatError is returned for wire-format problems (bad magic, wrong
// version, truncated, trailing bytes).
type FormatError struct{ Msg string }

func (e *FormatError) Error() string { return "bundle: " + e.Msg }

// SignatureError is returned for signature, AEAD, or crypto failures.
// Distinct from FormatError: both fail closed, but this one indicates
// the bundle was tampered with or we have the wrong keys.
type SignatureError struct{ Msg string }

func (e *SignatureError) Error() string { return "bundle: " + e.Msg }

// ParseOptions configures optional behavior.
type ParseOptions struct {
	// MaxBundleBytes bounds how big a blob we will accept. Zero means
	// the default (16 MiB).
	MaxBundleBytes int
}

// Parse verifies the signature, decrypts, and decodes a policy bundle.
//
// Returns:
//   - *FormatError for malformed wire format.
//   - *SignatureError for signature / AEAD failures.
func Parse(
	blob []byte,
	encryptionKey []byte,
	signingPubkey []byte,
	opts *ParseOptions,
) (*Parsed, error) {
	maxBytes := defaultMaxBundleSz
	if opts != nil && opts.MaxBundleBytes > 0 {
		maxBytes = opts.MaxBundleBytes
	}

	if len(blob) > maxBytes {
		return nil, &FormatError{
			Msg: fmt.Sprintf("bundle size %d exceeds max %d", len(blob), maxBytes),
		}
	}
	if len(signingPubkey) != ed25519.PublicKeySize {
		return nil, &SignatureError{
			Msg: fmt.Sprintf("signing public key must be %d bytes, got %d",
				ed25519.PublicKeySize, len(signingPubkey)),
		}
	}
	if len(encryptionKey) != 32 {
		return nil, &SignatureError{
			Msg: fmt.Sprintf("encryption key must be 32 bytes, got %d", len(encryptionKey)),
		}
	}

	header, encryptedPayload, signature, err := split(blob)
	if err != nil {
		return nil, err
	}

	// Verify signature BEFORE decrypt. Never touch ciphertext for an
	// unauthenticated blob.
	signedMsg := make([]byte, 0, headerSize+len(encryptedPayload))
	signedMsg = append(signedMsg, blob[:headerSize]...)
	signedMsg = append(signedMsg, encryptedPayload...)
	if !ed25519.Verify(signingPubkey, signedMsg, signature) {
		return nil, &SignatureError{Msg: "signature verification failed: bundle is not authentic"}
	}

	// Decrypt AEAD.
	compressed, err := decryptAESGCM(encryptionKey, encryptedPayload)
	if err != nil {
		return nil, err
	}

	// Zstd decompress.
	plaintextJSON, err := zstdDecompress(compressed)
	if err != nil {
		return nil, err
	}

	var payload map[string]any
	if err := json.Unmarshal(plaintextJSON, &payload); err != nil {
		return nil, &FormatError{Msg: fmt.Sprintf("payload is not valid JSON: %v", err)}
	}
	if payload == nil {
		return nil, &FormatError{Msg: "payload root must be an object"}
	}

	return &Parsed{Header: header, Payload: payload}, nil
}

func split(blob []byte) (Header, []byte, []byte, error) {
	if len(blob) < headerSize+sigLen {
		return Header{}, nil, nil, &FormatError{
			Msg: fmt.Sprintf("bundle too short: %d bytes, need at least %d",
				len(blob), headerSize+sigLen),
		}
	}
	if !bytes.Equal(blob[0:4], magic) {
		return Header{}, nil, nil, &FormatError{
			Msg: fmt.Sprintf("bad magic: expected CZ01, got %x", blob[0:4]),
		}
	}

	h := Header{
		SchemaVersion: binary.LittleEndian.Uint16(blob[4:6]),
		CreatedAt:     binary.LittleEndian.Uint64(blob[6:14]),
		PolicyCount:   binary.LittleEndian.Uint16(blob[14:16]),
		SigOffset:     binary.LittleEndian.Uint32(blob[16:20]),
		SigLen:        binary.LittleEndian.Uint32(blob[20:24]),
	}
	for i := 24; i < 32; i++ {
		if blob[i] != 0 {
			return Header{}, nil, nil, &FormatError{Msg: "reserved bytes must be zero"}
		}
	}
	if h.SchemaVersion < 1 || h.SchemaVersion > schemaVersionMax {
		return Header{}, nil, nil, &FormatError{
			Msg: fmt.Sprintf("unsupported schema version %d, this SDK supports 1..%d. Upgrade the SDK.",
				h.SchemaVersion, schemaVersionMax),
		}
	}
	if h.SigLen != sigLen {
		return Header{}, nil, nil, &FormatError{
			Msg: fmt.Sprintf("unexpected signature length %d, want %d", h.SigLen, sigLen),
		}
	}
	if h.SigOffset < headerSize {
		return Header{}, nil, nil, &FormatError{
			Msg: fmt.Sprintf("sig_offset %d must be >= header size %d", h.SigOffset, headerSize),
		}
	}
	if int(h.SigOffset)+int(h.SigLen) > len(blob) {
		return Header{}, nil, nil, &FormatError{Msg: "signature extends past end of bundle"}
	}
	if int(h.SigOffset)+int(h.SigLen) != len(blob) {
		return Header{}, nil, nil, &FormatError{
			Msg: fmt.Sprintf("trailing bytes after signature: sig_offset+sig_len=%d bundle_len=%d",
				int(h.SigOffset)+int(h.SigLen), len(blob)),
		}
	}
	encryptedPayload := blob[headerSize:h.SigOffset]
	signature := blob[h.SigOffset : h.SigOffset+h.SigLen]
	return h, encryptedPayload, signature, nil
}

func decryptAESGCM(key, encrypted []byte) ([]byte, error) {
	if len(encrypted) < gcmNonceSize+gcmTagSize {
		return nil, &FormatError{
			Msg: fmt.Sprintf("encrypted payload too short (%d bytes) to contain nonce and tag",
				len(encrypted)),
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &SignatureError{Msg: fmt.Sprintf("cipher init failed: %v", err)}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &SignatureError{Msg: fmt.Sprintf("GCM init failed: %v", err)}
	}
	nonce := encrypted[:gcmNonceSize]
	ct := encrypted[gcmNonceSize:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, &SignatureError{Msg: fmt.Sprintf("bundle decryption failed: %v", err)}
	}
	return plain, nil
}

func zstdDecompress(data []byte) ([]byte, error) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, &SignatureError{Msg: fmt.Sprintf("zstd init failed: %v", err)}
	}
	defer dec.Close()
	out, err := dec.DecodeAll(data, nil)
	if err != nil {
		return nil, &SignatureError{Msg: fmt.Sprintf("zstd decompress failed: %v", err)}
	}
	return out, nil
}

// TranslateToLocalPolicy converts a decrypted bundle payload to the
// local-mode policy map accepted by LoadPolicy. Sorts policies by
// `priority` ascending so every SDK produces identical decisions from
// identical input.
func TranslateToLocalPolicy(payload map[string]any) map[string]any {
	raw, _ := payload["policies"].([]any)
	type pol struct {
		id       string
		priority float64
		rules    []any
	}
	pols := make([]pol, 0, len(raw))
	for _, p := range raw {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		pr := 100.0
		if v, ok := m["priority"].(float64); ok {
			pr = v
		}
		id, _ := m["id"].(string)
		rules, _ := m["rules"].([]any)
		pols = append(pols, pol{id: id, priority: pr, rules: rules})
	}
	sort.SliceStable(pols, func(i, j int) bool { return pols[i].priority < pols[j].priority })

	flat := make([]map[string]any, 0)
	for _, p := range pols {
		for _, r := range p.rules {
			m, ok := r.(map[string]any)
			if !ok {
				continue
			}
			t := translateRule(m, p.id)
			if t != nil {
				flat = append(flat, t)
			}
		}
	}
	if len(flat) == 0 {
		flat = append(flat, map[string]any{
			"effect": "deny",
			"action": "*",
			"reason": "No active policies. Define one in the Control Zero dashboard.",
		})
	}
	rules := make([]any, len(flat))
	for i, r := range flat {
		rules[i] = r
	}
	return map[string]any{"version": "1", "rules": rules}
}

// isEffectWord reports whether v is one of the four canonical effect
// keywords. Used to disambiguate `rule.action` (a tool name) from
// `rule.action` used as a legacy effect fallback.
func isEffectWord(v string) bool {
	switch v {
	case "allow", "deny", "warn", "audit":
		return true
	}
	return false
}

// translateRule converts a backend-shaped bundle rule into the local
// policy loader shape.
//
// Shapes we accept (matches the Python + Node SDK reference
// implementations -- the three SDKs MUST agree on any given input so
// the cross-language parity tests pass):
//
//   1. Plural `actions` (backend wire format emitted by
//      bundle_handler.go PolicyRule.Actions). Takes precedence over
//      every legacy singular form.
//   2. Legacy singular `tool` / `pattern`.
//   3. Legacy singular `action` when NOT an effect keyword
//      (disambiguated via isEffectWord).
//   4. Nested `match.tool` / `match.action`.
//   5. Default "*" (universal match).
//
// Before this change the Go translator only handled shapes 2+4+5 --
// every backend-emitted deny rule ({"actions": ["database:execute"]})
// silently collapsed to {action: "*"}, turning a narrow deny into a
// universal deny-all. Same bug class as the Python SDK fix in #221.
func translateRule(rule map[string]any, policyID string) map[string]any {
	// Effect resolution: prefer explicit `rule.effect`. Fall back to
	// `rule.action` only when it is an effect keyword.
	effect, _ := rule["effect"].(string)
	if effect == "" {
		if a, ok := rule["action"].(string); ok && isEffectWord(a) {
			effect = a
		} else {
			effect = "allow"
		}
	}
	if !isEffectWord(effect) {
		effect = "allow"
	}

	// Tool pattern resolution. Collect into a list so we can preserve
	// multi-pattern deny rules end-to-end.
	var patterns []string
	if arr, ok := rule["actions"].([]any); ok {
		for _, a := range arr {
			if s, ok := a.(string); ok && s != "" {
				patterns = append(patterns, s)
			}
		}
	}
	if len(patterns) == 0 {
		if p, ok := rule["tool"].(string); ok && p != "" {
			patterns = append(patterns, p)
		} else if p, ok := rule["pattern"].(string); ok && p != "" {
			patterns = append(patterns, p)
		}
	}
	if len(patterns) == 0 {
		// Legacy singular `action` -- only when NOT an effect keyword
		// (already captured above).
		if p, ok := rule["action"].(string); ok && p != "" && !isEffectWord(p) {
			patterns = append(patterns, p)
		}
	}
	if len(patterns) == 0 {
		if m, ok := rule["match"].(map[string]any); ok {
			if p, ok := m["tool"].(string); ok && p != "" {
				patterns = append(patterns, p)
			} else if p, ok := m["action"].(string); ok && p != "" {
				patterns = append(patterns, p)
			}
		}
	}
	if len(patterns) == 0 {
		patterns = []string{"*"}
	}

	reason, _ := rule["reason"].(string)
	if reason == "" {
		reason = "policy:" + policyID
	}

	// Emit plural `actions` so policy_loader passes the full list
	// through to the enforcer. Emit the singular `action` alias when
	// there is exactly one pattern, for parity with the Python + Node
	// SDK outputs (cross-language golden tests compare action scalars).
	out := map[string]any{
		"effect":  effect,
		"actions": patterns,
		"reason":  reason,
	}
	if len(patterns) == 1 {
		out["action"] = patterns[0]
	}
	if r, ok := rule["resources"]; ok {
		out["resources"] = r
	} else if r, ok := rule["resource"]; ok {
		out["resources"] = r
	}
	return out
}

// Errors surface-level convenience (matches Python/Node API shape).
var (
	ErrBadMagic = errors.New("bundle: bad magic")
	_           = ErrBadMagic
)
