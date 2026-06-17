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

// Canonical bundle-default fallbacks. These mirror the Python SDK's
// enforcer constants (DEFAULT_BUNDLE_ACTION / _ON_MISSING / _ON_EMPTY /
// _ON_TAMPER) and the backend's canonical defaults so a bundle without
// an explicit knob gets the identical posture in every SDK.
//
//   - defaultBundleAction:    no-match path on a NON-empty bundle (deny).
//   - defaultBundleOnMissing: degraded/partial/stale bundle -> fail CLOSED
//     (deny). Also the effect of the synthetic BUNDLE_MISSING rule.
//   - defaultBundleOnEmpty:   GENUINELY-empty project posture. Canonical
//     "observe" (#1247): allow + loud OBSERVE_MODE_NO_POLICY signal so a
//     fresh hosted project is monitored-not-bricked day one.
//   - defaultBundleOnTamper:  tamper posture (warn).
const (
	defaultBundleAction    = "deny"
	defaultBundleOnMissing = "deny"
	defaultBundleOnEmpty   = "observe"
	defaultBundleOnTamper  = "warn"
)

// Valid enums for each bundle-level default knob. An absent or unknown
// value coerces to the canonical fallback above. Mirrors the Python SDK
// VALID_DEFAULT_* frozensets so cross-language validation is identical.
var (
	validDefaultActions   = map[string]bool{"deny": true, "allow": true, "warn": true}
	validDefaultOnMissing = map[string]bool{"deny": true, "allow": true}
	validDefaultOnEmpty   = map[string]bool{"observe": true, "deny": true, "allow": true, "warn": true}
	validDefaultOnTamper  = map[string]bool{"warn": true, "deny": true, "deny-all": true, "quarantine": true}
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

// --- Version gate (gh#602) -------------------------------------------------

// versionTuple is the cross-SDK comparable shape produced by
// parseVersionTuple. Layout matches the Python + Node parsers:
//
//	major, minor, patch, releaseSentinel, suffix
//
// releaseSentinel is 1 for a clean release ("1.5.8") and 0 for a
// prerelease ("1.5.5a1") so the prerelease sorts BELOW the matching
// release at the same numeric triple. Comparison is element-wise.
type versionTuple struct {
	major, minor, patch, releaseSentinel int
	suffix                               string
}

func less(a, b versionTuple) bool {
	switch {
	case a.major != b.major:
		return a.major < b.major
	case a.minor != b.minor:
		return a.minor < b.minor
	case a.patch != b.patch:
		return a.patch < b.patch
	case a.releaseSentinel != b.releaseSentinel:
		return a.releaseSentinel < b.releaseSentinel
	default:
		return a.suffix < b.suffix
	}
}

// ParseVersionTuple parses a SemVer-ish version string into a
// versionTuple. Stdlib only; no semver / golang.org/x/mod dep on
// the bundle-load hot path.
//
// Handles the three forms we ship across SDKs:
//
//	"1.5.8"   -> {1, 5, 8, 1, ""}    (release sentinel = 1)
//	"v1.7.6"  -> {1, 7, 6, 1, ""}    (Go SDK tag prefix)
//	"1.5.5a1" -> {1, 5, 5, 0, "a1"}  (PEP 440 prerelease)
//
// Mirrors the Python + Node parsers byte-for-byte so a floor stamped
// by the backend gets the same verdict in every SDK.
func ParseVersionTuple(v string) versionTuple {
	var vt versionTuple
	if v == "" {
		vt.releaseSentinel = 1
		return vt
	}
	if v[0] == 'v' || v[0] == 'V' {
		v = v[1:]
	}
	nums := []int{0, 0, 0}
	suffix := ""
	idx := 0
	cur := ""
	collecting := true
	for i := 0; i < len(v) && idx < 3; i++ {
		ch := v[i]
		if ch == '.' {
			if cur != "" {
				if n, err := parseIntSafe(cur); err == nil {
					nums[idx] = n
				}
				cur = ""
			}
			idx++
			continue
		}
		if ch >= '0' && ch <= '9' {
			if collecting {
				cur += string(ch)
			}
		} else {
			// Non-numeric tail on the CURRENT segment: capture as
			// suffix, then stop reading further segments (a suffix
			// on a non-final segment is malformed; treat the rest
			// as absent).
			if cur != "" {
				if n, err := parseIntSafe(cur); err == nil {
					nums[idx] = n
				}
			}
			suffix = v[i:]
			collecting = false
			break
		}
	}
	if cur != "" && collecting {
		if n, err := parseIntSafe(cur); err == nil {
			nums[idx] = n
		}
	}
	vt.major = nums[0]
	vt.minor = nums[1]
	vt.patch = nums[2]
	if suffix != "" {
		vt.releaseSentinel = 0
		vt.suffix = suffix
	} else {
		vt.releaseSentinel = 1
	}
	return vt
}

// parseIntSafe is a thin wrapper that never panics. Returns 0 on
// any parse error; the caller treats malformed numeric segments as
// "unknown" = 0.
func parseIntSafe(s string) (int, error) {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("non-digit %q in %q", ch, s)
		}
		n = n*10 + int(ch-'0')
	}
	return n, nil
}

// MinSDKResult is the structured outcome of CheckMinSDKVersion. The
// caller in hosted_policy.go inspects the Refuse flag and wraps the
// required/actual fields into a controlzero.BundleRequiresNewerSDKError
// at the package boundary. Keeping the internal API result-shaped
// (rather than returning the error directly) avoids importing the
// public controlzero package from the internal subpackage, which
// would create an import cycle.
type MinSDKResult struct {
	Refuse   bool
	Required string
	Actual   string
}

// CheckMinSDKVersion inspects payload["metadata"]["min_sdk_version"]
// and returns a MinSDKResult{Refuse: true, ...} when the bundle's
// floor exceeds sdkVersion. Bundles without the field return
// MinSDKResult{Refuse: false} (back-compat: every pre-#602 bundle).
//
// Pure function; no I/O.
func CheckMinSDKVersion(payload map[string]any, sdkVersion string) MinSDKResult {
	metaAny, ok := payload["metadata"]
	if !ok {
		return MinSDKResult{}
	}
	meta, ok := metaAny.(map[string]any)
	if !ok {
		return MinSDKResult{}
	}
	reqAny, ok := meta["min_sdk_version"]
	if !ok {
		return MinSDKResult{}
	}
	required, ok := reqAny.(string)
	if !ok || required == "" {
		return MinSDKResult{}
	}
	if !less(ParseVersionTuple(sdkVersion), ParseVersionTuple(required)) {
		return MinSDKResult{}
	}
	return MinSDKResult{Refuse: true, Required: required, Actual: sdkVersion}
}

// RecommendedSDKResult is the structured outcome of
// CheckRecommendedSDKVersion. Behind is true when the bundle's
// metadata.recommended_sdk_version is strictly higher than the running
// SDK version -- a SOFT signal (the caller prints one non-fatal warning),
// distinct from min_sdk_version which is the HARD floor that refuses to
// load. No-op (Behind:false) when the field is absent so every pre-existing
// bundle is unaffected.
type RecommendedSDKResult struct {
	Behind      bool
	Recommended string
	Actual      string
}

// CheckRecommendedSDKVersion inspects
// payload["metadata"]["recommended_sdk_version"] and returns
// RecommendedSDKResult{Behind: true, ...} when the recommended version is
// strictly newer than sdkVersion. Bundles without the field return
// RecommendedSDKResult{} (back-compat). Pure function; no I/O.
//
// recommended_sdk_version is the SOFT counterpart to min_sdk_version:
// min refuses to load (over-block risk); recommended only nudges the
// operator to upgrade so enforcement/audit fixes that shipped in newer
// SDKs reach them. Never changes enforcement.
func CheckRecommendedSDKVersion(payload map[string]any, sdkVersion string) RecommendedSDKResult {
	metaAny, ok := payload["metadata"]
	if !ok {
		return RecommendedSDKResult{}
	}
	meta, ok := metaAny.(map[string]any)
	if !ok {
		return RecommendedSDKResult{}
	}
	recAny, ok := meta["recommended_sdk_version"]
	if !ok {
		return RecommendedSDKResult{}
	}
	recommended, ok := recAny.(string)
	if !ok || recommended == "" {
		return RecommendedSDKResult{}
	}
	if !less(ParseVersionTuple(sdkVersion), ParseVersionTuple(recommended)) {
		return RecommendedSDKResult{}
	}
	return RecommendedSDKResult{Behind: true, Recommended: recommended, Actual: sdkVersion}
}

// bundleActivePolicyCount returns metadata.active_policy_count -- the
// backend's LIVE count of active policy attachments at bundle-build time
// (#1303 part 3) -- or (0, false) when the field is absent or malformed
// (an older backend that predates the field).
//
// This is the AUTHORITATIVE empty-vs-degraded discriminator. 0 means a
// genuinely-empty project (observe, #1247); >0 means policies ARE
// attached, so an empty translated rule set is a degraded / stripped /
// stale bundle and must fail closed. A false `ok` makes the caller fall
// back to the older `policies: []` shape heuristic.
//
// Mirrors the Python _bundle_active_policy_count: never treats a
// non-integer as a genuine 0. bool, string, negative, and non-whole
// floats are all rejected. JSON decoding lands integers as float64, so a
// whole-number float64 (e.g. 3.0 for `"active_policy_count": 3`) is
// accepted; native int / int64 / json.Number are accepted too for
// payloads built directly as Go maps.
func bundleActivePolicyCount(payload map[string]any) (int, bool) {
	meta, ok := payload["metadata"].(map[string]any)
	if !ok {
		return 0, false
	}
	raw, ok := meta["active_policy_count"]
	if !ok {
		return 0, false
	}
	switch v := raw.(type) {
	case bool:
		// bool must never be read as 0/1 (matches Python's int-subclass reject).
		return 0, false
	case int:
		if v < 0 {
			return 0, false
		}
		return v, true
	case int64:
		if v < 0 {
			return 0, false
		}
		return int(v), true
	case float64:
		// Reject non-integer floats (e.g. 1.5) and negatives. JSON whole
		// numbers arrive as float64, so an integral value is a real count.
		if v < 0 || v != float64(int64(v)) {
			return 0, false
		}
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil || n < 0 {
			return 0, false
		}
		return int(n), true
	default:
		// string, nil, or any other type -> treated as absent.
		return 0, false
	}
}

// extractDefault reads a top-level string knob from the payload and
// returns it when it is one of validSet, else the canonical fallback.
// Mirrors the Python translator's `payload.get(...) not in VALID_... ->
// canonical` coercion so unknown / absent / non-string values never flip
// an org's posture through a typo.
func extractDefault(payload map[string]any, key string, validSet map[string]bool, fallback string) string {
	if v, ok := payload[key].(string); ok && validSet[v] {
		return v
	}
	return fallback
}

// TranslateToLocalPolicy converts a decrypted bundle payload to the
// local-mode policy map accepted by LoadPolicy. Sorts policies by
// `priority` ascending so every SDK produces identical decisions from
// identical input.
//
// #1247 + #1303 parity (founder-approved): brings the Go translator to
// match the post-fix Python semantics. The previous Go behaviour
// hard-coded a deny-all synthetic rule on ANY empty rule set and dropped
// the default_on_* knobs. Now:
//
//   - A GENUINELY-empty project (active_policy_count == 0 AND an explicit
//     `policies: []`, or -- on older backends with no count -- just an
//     explicit `policies: []`) honours default_on_empty. The canonical
//     fallback is "observe": allow + a loud OBSERVE_MODE_NO_POLICY signal
//     so a fresh hosted project is monitored, not bricked (#1247). An
//     operator can override default_on_empty to deny / warn / allow.
//   - A DEGRADED / partial / stale bundle (zero translatable rules but NOT
//     a genuine empty project: policies attached that produced no rules, a
//     missing / non-array `policies` key, or active_policy_count > 0 with
//     an empty list) FAILS CLOSED via default_on_missing (canonical deny),
//     stamped with the synthetic BUNDLE_MISSING rule. This is the
//     empty-vs-degraded boundary that prevents the rm-rf fail-open.
//
// The four knobs (default_action / default_on_missing / default_on_empty
// / default_on_tamper) are propagated into the returned map's `settings`
// block (and mirrored at the top level) so LoadPolicy / PolicyEvaluator
// honour them downstream, exactly like the Python + Node SDKs.
func TranslateToLocalPolicy(payload map[string]any) map[string]any {
	// Resolve the four enforcement-default knobs up front so both the
	// degraded and the genuinely-empty branch can consult them. Unknown /
	// absent values coerce to the canonical fallbacks (deny / deny /
	// observe / warn).
	defaultAction := extractDefault(payload, "default_action", validDefaultActions, defaultBundleAction)
	defaultOnMissing := extractDefault(payload, "default_on_missing", validDefaultOnMissing, defaultBundleOnMissing)
	defaultOnEmpty := extractDefault(payload, "default_on_empty", validDefaultOnEmpty, defaultBundleOnEmpty)
	defaultOnTamper := extractDefault(payload, "default_on_tamper", validDefaultOnTamper, defaultBundleOnTamper)

	// Keep the RAW `policies` value to distinguish a genuinely-empty
	// project (the backend ships an explicit empty list `policies: []`)
	// from a DEGRADED bundle (policies attached but zero translatable
	// rules, or a missing / non-array `policies` key). The former is
	// observe (#1247); the latter must fail CLOSED.
	rawPolicies, policiesIsArray := payload["policies"].([]any)
	raw := rawPolicies
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
	// #1303 part 3: active_policy_count is the AUTHORITATIVE
	// empty-vs-degraded discriminator. >0 means policies ARE attached, so
	// an empty translated rule set is a degraded / stripped bundle -> fail
	// closed. For the GENUINELY-empty direction the count is necessary but
	// not sufficient: a genuine empty project requires count == 0 AND the
	// backend's explicit `policies: []`. A count == 0 paired with a missing
	// or non-array `policies` key is a truncated / malformed / degraded
	// bundle, NOT a genuine empty project -- trusting the count alone there
	// would observe -> allow-all a degraded bundle (the rm-rf fail-open
	// class, #1303), so it must fail closed. Count ABSENT (older backend)
	// -> fall back to the explicit `policies: []` shape check.
	activeCount, countPresent := bundleActivePolicyCount(payload)
	explicitEmptyPolicies := policiesIsArray && len(rawPolicies) == 0
	var genuinelyEmpty bool
	if countPresent {
		genuinelyEmpty = activeCount == 0 && explicitEmptyPolicies
	} else {
		genuinelyEmpty = explicitEmptyPolicies
	}

	if len(flat) == 0 && !genuinelyEmpty {
		// #1303 FAIL-CLOSED (the empty-vs-degraded boundary). Zero
		// translatable rules, but this is NOT a genuinely-empty project:
		// the payload carried attached policies that produced no rules, OR
		// a missing / non-array `policies` key, OR active_policy_count > 0
		// with an empty list (a stripped bundle). Treating that as observe
		// would ALLOW EVERY tool call for a customer who HAS a policy -- the
		// reproduced rm-rf fail-open. Fail CLOSED via default_on_missing
		// (canonical deny), stamped with the BUNDLE_MISSING reason_code +
		// synthetic id so it is not confused with a genuine empty project.
		flat = append(flat, map[string]any{
			"id":     "synthetic:BUNDLE_MISSING",
			"effect": defaultOnMissing,
			"action": "*",
			"reason": "Your project has attached policies but the resolved bundle " +
				"produced zero enforceable rules (a degraded, partial, or stale " +
				"bundle). Control Zero is failing CLOSED (deny) rather than " +
				"allowing every tool call. Regenerate the policy bundle in the " +
				"Control Zero dashboard; contact support if this persists.",
			"reason_code": "BUNDLE_MISSING",
		})
	}

	if len(flat) == 0 {
		// Genuinely-empty project (resolved successfully, zero rules):
		// posture is driven by default_on_empty (#1247 item 3), NOT
		// default_action. Canonical "observe" allows the call through
		// (effect=allow) but loudly flags it as monitoring-only via
		// reason_code=OBSERVE_MODE_NO_POLICY so the operator knows the
		// engine is wired up and watching, not enforcing. An operator can
		// override default_on_empty to deny / warn / allow.
		if defaultOnEmpty == "observe" {
			flat = append(flat, map[string]any{
				"id":     "synthetic:OBSERVE_MODE_NO_POLICY",
				"effect": "allow",
				"action": "*",
				"reason": "OBSERVE MODE: no policies are active on this project, so " +
					"Control Zero is monitoring and auditing tool calls but NOT " +
					"enforcing -- every call is allowed and logged. Attach a policy " +
					"(or set the empty-project default to deny) in the Control Zero " +
					"dashboard to start enforcing.",
				"reason_code": "OBSERVE_MODE_NO_POLICY",
			})
		} else {
			// Explicit non-observe empty posture (deny / warn / allow).
			// Keeps the historical NO_ACTIVE_POLICIES reason_code so
			// dashboards still bucket it as "nothing attached"; the effect
			// honours the operator's declared default_on_empty.
			flat = append(flat, map[string]any{
				"id":     "synthetic:NO_ACTIVE_POLICIES",
				"effect": defaultOnEmpty,
				"action": "*",
				"reason": "No policies are active on this project. If the dashboard " +
					"shows attached policies, regenerate the policy bundle.",
				"reason_code": "NO_ACTIVE_POLICIES",
			})
		}
	}

	rules := make([]any, len(flat))
	for i, r := range flat {
		rules[i] = r
	}

	// Propagate the four knobs so LoadPolicy / PolicyEvaluator honour them
	// downstream. Emit both a `settings` block (the canonical home, read by
	// parseSettings) AND the top-level scalars (the bundle wire shape, which
	// validateAndTranslate also accepts and which takes precedence). This
	// matches the Python translator's `settings` output and keeps the
	// translated shape compatible with every LoadPolicy code path.
	settings := map[string]any{
		"default_action":     defaultAction,
		"default_on_missing": defaultOnMissing,
		"default_on_empty":   defaultOnEmpty,
		"default_on_tamper":  defaultOnTamper,
	}
	return map[string]any{
		"version":            "1",
		"rules":              rules,
		"settings":           settings,
		"default_action":     defaultAction,
		"default_on_missing": defaultOnMissing,
		"default_on_empty":   defaultOnEmpty,
		"default_on_tamper":  defaultOnTamper,
	}
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
		}
	}
	// An UNRECOGNIZED or empty effect on a validly-signed rule must fail
	// CLOSED -> deny, mirroring the Python (_translate_rule: `else "deny"`)
	// and Node (`effect = 'deny'`) SDKs. Coercing to "allow" (the old
	// behavior) turned an unknown rule into allow-*-for-its-pattern -- the
	// exact #1303 cross-surface fail-open, and the one surface that still had
	// it. A deny over-denies that single pattern at worst (the safe
	// direction); all three SDKs must agree byte-for-byte on the decision.
	if !isEffectWord(effect) {
		effect = "deny"
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
	// T79: pass through `id` and `reason_code` so synthetic rules
	// (NO_ACTIVE_POLICIES, BUNDLE_MISSING) reach the evaluator with
	// their machine labels intact. Without this, the empty-bundle
	// synthetic rule the translator just emitted gets stripped by
	// the round-trip through policy_loader.
	if id, ok := rule["id"].(string); ok && id != "" {
		out["id"] = id
	}
	if rc, ok := rule["reason_code"].(string); ok && rc != "" {
		out["reason_code"] = rc
	}
	// gh#175 P1.1 outside-voice review: pass `clients` / `projects`
	// selectors through to the local rule shape. Without this, the
	// backend ships selector-scoped rules in the signed bundle but
	// the Go loader strips them and the engine treats every such
	// rule as unscoped. Same bug-class as the 2026-04-17 actions-
	// stripping incident #173 / #221.
	if clients, ok := rule["clients"].([]any); ok && len(clients) > 0 {
		strs := make([]string, 0, len(clients))
		for _, c := range clients {
			if s, ok := c.(string); ok {
				strs = append(strs, s)
			}
		}
		if len(strs) > 0 {
			out["clients"] = strs
		}
	}
	if projects, ok := rule["projects"].([]any); ok && len(projects) > 0 {
		strs := make([]string, 0, len(projects))
		for _, p := range projects {
			if s, ok := p.(string); ok {
				strs = append(strs, s)
			}
		}
		if len(strs) > 0 {
			out["projects"] = strs
		}
	}
	// Same pattern (gh#538): the HITL `escalate_on_deny` tag was
	// also being stripped at the bundle layer. Forward it when present.
	if escalate, ok := rule["escalate_on_deny"].(bool); ok {
		out["escalate_on_deny"] = escalate
	}
	return out
}

// Errors surface-level convenience (matches Python/Node API shape).
var (
	ErrBadMagic = errors.New("bundle: bad magic")
	_           = ErrBadMagic
)
