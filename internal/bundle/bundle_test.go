// Tests for the .czpolicy bundle parser.
//
// Deterministic: the bundle is constructed inline with the exact same
// wire format as the backend's buildBundle() in Go. If these tests and
// the Python + Node tests pass, we have cross-language parity.
package bundle

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/klauspost/compress/zstd"
)

type buildOpts struct {
	schemaVersion  uint16
	createdAt      uint64
	policyCount    uint16
	corruptMagic   bool
	corruptReserve bool
	corruptSigLen  bool
	extraTrailing  []byte
}

func buildTestBundle(t *testing.T, payload, encKey []byte, priv ed25519.PrivateKey, opts buildOpts) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		t.Fatal(err)
	}
	compressed := enc.EncodeAll(payload, nil)
	enc.Close()

	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ct := gcm.Seal(nonce, nonce, compressed, nil)
	// ct == nonce || ciphertext || tag

	magic := []byte("CZ01")
	if opts.corruptMagic {
		magic = []byte("XX01")
	}
	sv := opts.schemaVersion
	if sv == 0 {
		sv = 1
	}
	ts := opts.createdAt
	if ts == 0 {
		ts = 1700000000
	}
	pc := opts.policyCount
	if pc == 0 {
		pc = 1
	}
	sigLenVal := uint32(64)
	if opts.corruptSigLen {
		sigLenVal = 65
	}
	sigOffset := uint32(32 + len(ct))

	header := make([]byte, 32)
	copy(header[0:4], magic)
	binary.LittleEndian.PutUint16(header[4:6], sv)
	binary.LittleEndian.PutUint64(header[6:14], ts)
	binary.LittleEndian.PutUint16(header[14:16], pc)
	binary.LittleEndian.PutUint32(header[16:20], sigOffset)
	binary.LittleEndian.PutUint32(header[20:24], sigLenVal)
	if opts.corruptReserve {
		for i := 24; i < 32; i++ {
			header[i] = 0xff
		}
	}

	toSign := append(append([]byte{}, header...), ct...)
	sig := ed25519.Sign(priv, toSign)
	bundle := append(toSign, sig...)
	if len(opts.extraTrailing) > 0 {
		bundle = append(bundle, opts.extraTrailing...)
	}
	return bundle
}

func validPayload() []byte {
	m := map[string]any{
		"schema_version": "1.0",
		"bundle_id":      "v1",
		"project_id":     "p",
		"policies": []any{
			map[string]any{
				"id":       "p1",
				"priority": 10,
				"rules": []any{
					map[string]any{"effect": "deny", "tool": "send_email"},
					map[string]any{"effect": "allow", "tool": "*"},
				},
			},
		},
	}
	b, _ := json.Marshal(m)
	return b
}

func genKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := make([]byte, 32)
	if _, err := rand.Read(enc); err != nil {
		t.Fatal(err)
	}
	return pub, priv, enc
}

func TestParse_Valid(t *testing.T) {
	pub, priv, enc := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{})
	p, err := Parse(bundle, enc, pub, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Header.SchemaVersion != 1 {
		t.Errorf("want schema v1, got %d", p.Header.SchemaVersion)
	}
	if p.Payload["project_id"] != "p" {
		t.Errorf("wrong payload: %v", p.Payload)
	}
}

func TestParse_TamperedSignature(t *testing.T) {
	pub, priv, enc := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{})
	bundle[len(bundle)-5] ^= 0xff
	_, err := Parse(bundle, enc, pub, nil)
	var se *SignatureError
	if !errors.As(err, &se) {
		t.Fatalf("expected SignatureError, got %v", err)
	}
}

func TestParse_TamperedCiphertext(t *testing.T) {
	pub, priv, enc := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{})
	bundle[40] ^= 0x01
	_, err := Parse(bundle, enc, pub, nil)
	var se *SignatureError
	if !errors.As(err, &se) {
		t.Fatalf("expected SignatureError, got %v", err)
	}
}

func TestParse_WrongPubkey(t *testing.T) {
	_, priv, enc := genKeys(t)
	other, _, _ := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{})
	_, err := Parse(bundle, enc, other, nil)
	var se *SignatureError
	if !errors.As(err, &se) {
		t.Fatalf("expected SignatureError, got %v", err)
	}
}

func TestParse_WrongEncKey(t *testing.T) {
	pub, priv, enc := genKeys(t)
	wrong := make([]byte, 32)
	rand.Read(wrong)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{})
	_, err := Parse(bundle, wrong, pub, nil)
	var se *SignatureError
	if !errors.As(err, &se) {
		t.Fatalf("expected SignatureError (from AEAD failure), got %v", err)
	}
}

func TestParse_BadMagic(t *testing.T) {
	pub, priv, enc := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{corruptMagic: true})
	_, err := Parse(bundle, enc, pub, nil)
	var fe *FormatError
	if !errors.As(err, &fe) {
		t.Fatalf("expected FormatError, got %v", err)
	}
}

func TestParse_NonzeroReserved(t *testing.T) {
	pub, priv, enc := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{corruptReserve: true})
	_, err := Parse(bundle, enc, pub, nil)
	var fe *FormatError
	if !errors.As(err, &fe) {
		t.Fatalf("expected FormatError, got %v", err)
	}
}

func TestParse_WrongSigLen(t *testing.T) {
	pub, priv, enc := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{corruptSigLen: true})
	_, err := Parse(bundle, enc, pub, nil)
	var fe *FormatError
	if !errors.As(err, &fe) {
		t.Fatalf("expected FormatError, got %v", err)
	}
}

func TestParse_TrailingBytes(t *testing.T) {
	pub, priv, enc := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{extraTrailing: []byte{0xaa}})
	_, err := Parse(bundle, enc, pub, nil)
	var fe *FormatError
	if !errors.As(err, &fe) {
		t.Fatalf("expected FormatError, got %v", err)
	}
}

func TestParse_OverSizeCap(t *testing.T) {
	pub, priv, enc := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{})
	_, err := Parse(bundle, enc, pub, &ParseOptions{MaxBundleBytes: 32})
	var fe *FormatError
	if !errors.As(err, &fe) {
		t.Fatalf("expected FormatError for size cap, got %v", err)
	}
}

func TestParse_WrongSizePubkey(t *testing.T) {
	_, priv, enc := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{})
	_, err := Parse(bundle, enc, make([]byte, 8), nil)
	var se *SignatureError
	if !errors.As(err, &se) {
		t.Fatalf("expected SignatureError, got %v", err)
	}
}

func TestParse_WrongSizeEncKey(t *testing.T) {
	pub, priv, enc := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{})
	_, err := Parse(bundle, make([]byte, 8), pub, nil)
	var se *SignatureError
	if !errors.As(err, &se) {
		t.Fatalf("expected SignatureError, got %v", err)
	}
}

func TestTranslateToLocalPolicy_SortsByPriority(t *testing.T) {
	payload := map[string]any{
		"policies": []any{
			map[string]any{"id": "p2", "priority": 20.0, "rules": []any{map[string]any{"effect": "allow", "tool": "*"}}},
			map[string]any{"id": "p1", "priority": 10.0, "rules": []any{map[string]any{"effect": "deny", "tool": "send_email"}}},
		},
	}
	out := TranslateToLocalPolicy(payload)
	if out["version"] != "1" {
		t.Errorf("want version=1, got %v", out["version"])
	}
	rules := out["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	first := rules[0].(map[string]any)
	if first["action"] != "send_email" || first["effect"] != "deny" {
		t.Errorf("sort order wrong: %v", first)
	}
}

func TestTranslateToLocalPolicy_EmptyBecomesDenyAll(t *testing.T) {
	out := TranslateToLocalPolicy(map[string]any{"policies": []any{}})
	rules := out["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	r := rules[0].(map[string]any)
	if r["effect"] != "deny" || r["action"] != "*" {
		t.Errorf("expected deny-all, got %v", r)
	}
}

// Sanity: construct a bundle and verify the header bytes match the
// backend's buildBundle() byte layout.
func TestHeaderLayout(t *testing.T) {
	_, priv, enc := genKeys(t)
	bundle := buildTestBundle(t, validPayload(), enc, priv, buildOpts{})
	if !bytes.Equal(bundle[0:4], []byte("CZ01")) {
		t.Error("bad magic position")
	}
	if bundle[4] != 1 || bundle[5] != 0 {
		t.Errorf("schema version LE encoding wrong: %x %x", bundle[4], bundle[5])
	}
}
