// Package controlzero
//
// RFC 8785 canonical JSON + ArgsHash for cross-SDK audit parity.
//
// Phase 1A of cua rig v2 (issue #450). Same contract as the Python
// SDK's controlzero/canonical.py and the Node SDK's
// src/canonical.ts. Given the same input map, all three SDKs MUST
// produce the same SHA-256 hex over the RFC 8785 canonical bytes.
//
// Implementation: uses github.com/gowebpki/jcs (the pkg.go.dev
// reference implementation of RFC 8785). The Python SDK uses
// trailofbits/rfc8785; the Node SDK uses the cyberphone-derived
// `canonicalize` npm package. Cross-language parity is verified by
// the shared fixture at tests/parity/jcs_args_hash_vectors.json
// (vendored copy at sdks/go/controlzero/tests/parity/...).
//
// Reference: https://www.rfc-editor.org/rfc/rfc8785

package controlzero

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/gowebpki/jcs"
)

// argsHashWarnOnce ensures the diagnostic warning about ArgsHash
// returning an empty string fires at most once per process. PR #463
// reviewers (Claude + Gemini + Codex) flagged the previous silent
// swallow as undebuggable in production: an "empty args_hash" column
// in the analytical audit store could mean either "legacy SDK row"
// or "current SDK hit an encoding error" with no way to tell them
// apart. We warn on the FIRST failure so operators see the trail;
// further failures stay silent so a misbehaving input does not flood
// stderr from a guard() hot path.
var argsHashWarnOnce sync.Once

// CanonicalJSON returns the RFC 8785 (JCS) canonical bytes for v.
//
// Returns an error if v cannot be marshalled to JSON or if the JCS
// transform rejects the result (e.g. integers above 2^53-1 are
// outside the safe integer domain).
func CanonicalJSON(v interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("controlzero: json.Marshal for JCS input: %w", err)
	}
	return canonicalJSONBytes(raw)
}

// canonicalJSONBytes wraps jcs.Transform with the same error-wrap
// envelope CanonicalJSON exposes. Split out so the jcs.Transform
// failure path can be exercised by tests that feed pre-marshalled
// invalid JSON bytes (json.Marshal will not produce invalid output
// for any Go value, so the public CanonicalJSON's transform-error
// branch is otherwise structurally unreachable in normal use).
func canonicalJSONBytes(raw []byte) ([]byte, error) {
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("controlzero: jcs.Transform: %w", err)
	}
	return canonical, nil
}

// ArgsHash returns "sha256:<hex>" for the canonical bytes of args.
//
// Stable across SDKs. The rig's Tier C parity test asserts
// byte-identical hashes for the same input across Python, Node, and
// Go SDKs.
//
// nil maps and empty maps hash identically (both serialise to "{}").
//
// On any canonicalisation error returns the empty string, matching
// the Python / Node SDK best-effort contract. The FIRST such error
// per process is logged to stderr at WARNING so operators can tell
// an SDK encoding bug apart from a legacy-row empty value. Callers
// that need to handle the error path explicitly (no swallow, no
// global side effect) should call CanonicalJSON directly.
func ArgsHash(args map[string]interface{}) string {
	input := args
	if input == nil {
		input = map[string]interface{}{}
	}
	canonical, err := CanonicalJSON(input)
	if err != nil {
		argsHashWarnOnce.Do(func() {
			fmt.Fprintf(os.Stderr,
				"controlzero: ArgsHash encoding error (%v); "+
					"audit rows from this process will land with an empty "+
					"args_hash. This warning fires once per process.\n",
				err)
		})
		return ""
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}
