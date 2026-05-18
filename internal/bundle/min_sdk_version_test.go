// Tests for the min_sdk_version bundle gate (gh#602).
//
// Mirrors the Python `test_min_sdk_version_gate.py` cases and the
// Node `minSdkVersionGate.test.ts` cases so any cross-SDK contract
// drift surfaces in CI as a parametrised-name mismatch rather than
// at customer runtime.

package bundle

import "testing"

// TestCheckMinSDKVersion_FloorHigher_Refuses asserts a bundle whose
// declared floor exceeds the SDK version is refused with the typed
// MinSDKResult{Refuse: true, ...} so hosted_policy.go can wrap it
// into the public BundleRequiresNewerSDKError.
func TestCheckMinSDKVersion_FloorHigher_Refuses(t *testing.T) {
	payload := map[string]any{
		"policies": []any{},
		"metadata": map[string]any{"min_sdk_version": "9999.0.0"},
	}
	got := CheckMinSDKVersion(payload, "1.0.0")
	if !got.Refuse {
		t.Fatalf("expected Refuse=true; got %+v", got)
	}
	if got.Required != "9999.0.0" {
		t.Errorf("Required: got %q, want 9999.0.0", got.Required)
	}
	if got.Actual != "1.0.0" {
		t.Errorf("Actual: got %q, want 1.0.0", got.Actual)
	}
}

// TestCheckMinSDKVersion_NoMetadata_Accepts asserts pre-#602 bundles
// (no metadata block) keep loading. This is THE back-compat invariant.
func TestCheckMinSDKVersion_NoMetadata_Accepts(t *testing.T) {
	payload := map[string]any{"policies": []any{}}
	if got := CheckMinSDKVersion(payload, "1.0.0"); got.Refuse {
		t.Fatalf("no metadata must NOT refuse; got %+v", got)
	}
}

// TestCheckMinSDKVersion_NoField_Accepts asserts a bundle whose
// metadata is present but does not carry min_sdk_version (the default
// shape for any rule without selectors) loads unchanged.
func TestCheckMinSDKVersion_NoField_Accepts(t *testing.T) {
	payload := map[string]any{
		"metadata": map[string]any{"tags": map[string]any{}},
	}
	if got := CheckMinSDKVersion(payload, "1.0.0"); got.Refuse {
		t.Fatalf("missing min_sdk_version must NOT refuse; got %+v", got)
	}
}

// TestCheckMinSDKVersion_FloorEqual_Accepts asserts the boundary
// case where the bundle floor exactly matches the SDK version
// accepts. The gate is `current >= required`, NOT strictly greater.
func TestCheckMinSDKVersion_FloorEqual_Accepts(t *testing.T) {
	payload := map[string]any{
		"metadata": map[string]any{"min_sdk_version": "1.5.8"},
	}
	if got := CheckMinSDKVersion(payload, "1.5.8"); got.Refuse {
		t.Fatalf("equal-floor must NOT refuse; got %+v", got)
	}
}

// TestCheckMinSDKVersion_FloorLower_Accepts asserts a bundle floor
// below the SDK version accepts. This is the common case for any
// newer SDK loading any bundle from a fleet floor anchor.
func TestCheckMinSDKVersion_FloorLower_Accepts(t *testing.T) {
	payload := map[string]any{
		"metadata": map[string]any{"min_sdk_version": "0.0.1"},
	}
	if got := CheckMinSDKVersion(payload, "1.5.8"); got.Refuse {
		t.Fatalf("low-floor must NOT refuse; got %+v", got)
	}
}

// TestCheckMinSDKVersion_MalformedMetadata_Accepts asserts the gate
// is defensive: any non-string min_sdk_version (None/int/list) does
// not crash; we treat the value as 'unknown' = 'accept'.
func TestCheckMinSDKVersion_MalformedMetadata_Accepts(t *testing.T) {
	cases := []map[string]any{
		{"metadata": "not-a-dict"},
		{"metadata": map[string]any{"min_sdk_version": 123}},
		{"metadata": map[string]any{"min_sdk_version": nil}},
		{"metadata": map[string]any{"min_sdk_version": ""}},
		{"metadata": map[string]any{"min_sdk_version": []string{"1.0.0"}}},
	}
	for i, c := range cases {
		if got := CheckMinSDKVersion(c, "1.0.0"); got.Refuse {
			t.Errorf("case %d: malformed metadata must NOT refuse; got %+v", i, got)
		}
	}
}

// --- Version parser invariants ---------------------------------------------

// TestParseVersionTuple_StripsVPrefix asserts the Go SDK tag form
// `v1.7.6` parses identically to `1.7.6`. Without this, the Go SDK
// would always refuse its own bundles whenever it compared against
// itself (Version is "v1.7.6").
func TestParseVersionTuple_StripsVPrefix(t *testing.T) {
	a := ParseVersionTuple("v1.7.6")
	b := ParseVersionTuple("1.7.6")
	if less(a, b) || less(b, a) {
		t.Errorf("v1.7.6 must compare equal to 1.7.6; got %+v vs %+v", a, b)
	}
}

// TestParseVersionTuple_PrereleaseBelowRelease asserts a PEP 440
// alpha sorts below the matching release. Cross-SDK contract: the
// Python parser does the same thing.
func TestParseVersionTuple_PrereleaseBelowRelease(t *testing.T) {
	pre := ParseVersionTuple("1.5.5a1")
	rel := ParseVersionTuple("1.5.5")
	if !less(pre, rel) {
		t.Errorf("1.5.5a1 must sort below 1.5.5; got %+v vs %+v", pre, rel)
	}
}

// TestParseVersionTuple_EmptyIsZero asserts the empty string parses
// to the zero tuple without crashing. The caller treats this as
// 'permissive' (do not block).
func TestParseVersionTuple_EmptyIsZero(t *testing.T) {
	got := ParseVersionTuple("")
	if got.major != 0 || got.minor != 0 || got.patch != 0 {
		t.Errorf("empty must parse to zero; got %+v", got)
	}
}

// TestParseVersionTuple_PadsShortVersions asserts 1.5 compares
// against 1.5.8 cleanly (no crash, sensible ordering).
func TestParseVersionTuple_PadsShortVersions(t *testing.T) {
	short := ParseVersionTuple("1.5")
	full := ParseVersionTuple("1.5.8")
	if !less(short, full) {
		t.Errorf("1.5 must sort below 1.5.8; got %+v vs %+v", short, full)
	}
}

// --- Conformance vectors (parity scope) ------------------------------------
//
// Mirrors the Python + Node parametrised cases. IDs match so a
// future cross-SDK runner can join on case id.

type minSDKVec struct {
	id          string
	metadata    map[string]any // nil means no metadata block at all
	expectRefuse bool
}

func TestCheckMinSDKVersion_ConformanceVectors(t *testing.T) {
	vectors := []minSDKVec{
		{
			id:          "min-sdk-blocks-on-future-floor",
			metadata:    map[string]any{"min_sdk_version": "9999.0.0"},
			expectRefuse: true,
		},
		{
			id:          "min-sdk-back-compat",
			metadata:    nil,
			expectRefuse: false,
		},
		{
			id:          "min-sdk-low-floor-accepts",
			metadata:    map[string]any{"min_sdk_version": "0.0.1"},
			expectRefuse: false,
		},
	}
	for _, v := range vectors {
		t.Run(v.id, func(t *testing.T) {
			payload := map[string]any{"policies": []any{}}
			if v.metadata != nil {
				payload["metadata"] = v.metadata
			}
			got := CheckMinSDKVersion(payload, "1.5.8")
			if got.Refuse != v.expectRefuse {
				t.Errorf("vec %q: Refuse got=%v want=%v (full=%+v)", v.id, got.Refuse, v.expectRefuse, got)
			}
		})
	}
}
