// Phase 1A (#450) / PR #463 H8: negative-vector tests at the
// safe-integer boundary.
//
// Mirror of test_unsafe_int_boundary.py and unsafeIntBoundary.test.ts.
// Codex flagged the parity fixture as covering only IN-range integers.
//
// Cross-SDK reality at the unsafe-int boundary (>2^53):
//
//   - Python rfc8785 (trailofbits)  -> raises IntegerDomainError
//   - Node canonicalize npm         -> silently truncates via Number()
//   - Go gowebpki/jcs v1.0.1        -> silently truncates via json
//                                      number-to-float coercion
//
// ArgsHash for each SDK wraps any throw with a best-effort empty
// string so callers never crash. The contract this trio enforces is
// "never crash, and document the actual behavior so the divergence
// is visible". The cross-SDK audit join is best-effort on unsafe
// inputs (the args_hash column may differ between SDKs for the same
// truncating input); callers that need strict parity should keep
// integer values within the IEEE-754 safe range.

package controlzero

import (
	"strings"
	"testing"
)

func TestCanonicalJSON_OnUnsafeInt_NoCrash(t *testing.T) {
	// 2^53 + 1 -- one past the I-JSON safe integer ceiling.
	// Document the actual gowebpki/jcs v1.0.1 behavior: silent
	// truncation rather than a transform error. Either outcome is
	// acceptable as long as we do not crash; the empty-hash wrapper
	// covers any future library bump that switches to a hard error.
	out, err := CanonicalJSON(map[string]interface{}{"id": uint64(9007199254740993)})
	if err != nil {
		// Acceptable future-proof path: library starts rejecting.
		t.Logf("unsafe-int rejection (acceptable): %v", err)
		return
	}
	if len(out) == 0 {
		t.Fatal("CanonicalJSON returned no error and empty output -- invalid state")
	}
}

func TestArgsHash_OnUnsafeInt_NoCrash(t *testing.T) {
	// Per the cross-SDK contract: either an empty hash (best-effort
	// skip on a transform error) or a well-formed sha256 prefix
	// (precision-lost hash). What is NOT acceptable is a crash or
	// silent garbage. Matches the Node tests/unsafeIntBoundary.test.ts
	// shape.
	h := ArgsHash(map[string]interface{}{"id": uint64(9007199254740993)})
	if h == "" {
		// Empty is fine: ArgsHash chose the skip path.
		return
	}
	if !strings.HasPrefix(h, "sha256:") || len(h) != len("sha256:")+64 {
		t.Fatalf(
			"unsafe-int hash must be either empty or a well-formed "+
				"sha256:<64hex> string, got %q",
			h,
		)
	}
}

func TestArgsHash_SafeIntBoundary_StillHashes(t *testing.T) {
	// 2^53 - 1 -- the in-range boundary value.
	h := ArgsHash(map[string]interface{}{"id": int64(9007199254740991)})
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatalf("safe-int max should still hash, got %q", h)
	}
}
