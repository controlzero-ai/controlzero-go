// Tests for the recommended_sdk_version bundle nudge.
//
// recommended_sdk_version is the SOFT counterpart to the gh#602 HARD
// min_sdk_version floor: where min refuses to load, recommended only
// reports Behind=true so the caller prints one non-fatal upgrade nudge.
// The back-compat invariant (no field -> no-op) mirrors min_sdk_version.

package bundle

import "testing"

// TestCheckRecommendedSDKVersion_Newer_Behind asserts a bundle that
// recommends a strictly newer SDK reports Behind=true with the values
// the caller threads into the stderr nudge line.
func TestCheckRecommendedSDKVersion_Newer_Behind(t *testing.T) {
	payload := map[string]any{
		"policies": []any{},
		"metadata": map[string]any{"recommended_sdk_version": "2.0.0"},
	}
	got := CheckRecommendedSDKVersion(payload, "1.0.0")
	if !got.Behind {
		t.Fatalf("expected Behind=true; got %+v", got)
	}
	if got.Recommended != "2.0.0" {
		t.Errorf("Recommended: got %q, want 2.0.0", got.Recommended)
	}
	if got.Actual != "1.0.0" {
		t.Errorf("Actual: got %q, want 1.0.0", got.Actual)
	}
}

// TestCheckRecommendedSDKVersion_NoField_Silent asserts a bundle without
// recommended_sdk_version is a no-op. THE back-compat invariant: every
// pre-existing bundle must keep loading with no nudge.
func TestCheckRecommendedSDKVersion_NoField_Silent(t *testing.T) {
	payload := map[string]any{
		"metadata": map[string]any{"tags": map[string]any{}},
	}
	if got := CheckRecommendedSDKVersion(payload, "1.0.0"); got.Behind {
		t.Fatalf("missing recommended_sdk_version must NOT nudge; got %+v", got)
	}
}

// TestCheckRecommendedSDKVersion_NoMetadata_Silent asserts a bundle with
// no metadata block at all is a no-op.
func TestCheckRecommendedSDKVersion_NoMetadata_Silent(t *testing.T) {
	payload := map[string]any{"policies": []any{}}
	if got := CheckRecommendedSDKVersion(payload, "1.0.0"); got.Behind {
		t.Fatalf("no metadata must NOT nudge; got %+v", got)
	}
}

// TestCheckRecommendedSDKVersion_Equal_Silent asserts the boundary case:
// when the SDK is exactly at the recommended version, no nudge. The check
// is strictly-greater (current < recommended), not >=.
func TestCheckRecommendedSDKVersion_Equal_Silent(t *testing.T) {
	payload := map[string]any{
		"metadata": map[string]any{"recommended_sdk_version": "1.8.0"},
	}
	if got := CheckRecommendedSDKVersion(payload, "1.8.0"); got.Behind {
		t.Fatalf("equal version must NOT nudge; got %+v", got)
	}
}

// TestCheckRecommendedSDKVersion_Ahead_Silent asserts an SDK newer than
// the recommendation does not nudge (e.g. a dev build ahead of the fleet
// anchor).
func TestCheckRecommendedSDKVersion_Ahead_Silent(t *testing.T) {
	payload := map[string]any{
		"metadata": map[string]any{"recommended_sdk_version": "1.5.0"},
	}
	if got := CheckRecommendedSDKVersion(payload, "v1.8.0"); got.Behind {
		t.Fatalf("ahead-of-recommendation must NOT nudge; got %+v", got)
	}
}

// TestCheckRecommendedSDKVersion_Malformed_Silent asserts the check is
// defensive: any non-string / empty value is treated as absent (no nudge,
// no crash).
func TestCheckRecommendedSDKVersion_Malformed_Silent(t *testing.T) {
	cases := []map[string]any{
		{"metadata": "not-a-dict"},
		{"metadata": map[string]any{"recommended_sdk_version": 123}},
		{"metadata": map[string]any{"recommended_sdk_version": nil}},
		{"metadata": map[string]any{"recommended_sdk_version": ""}},
		{"metadata": map[string]any{"recommended_sdk_version": []string{"2.0.0"}}},
	}
	for i, c := range cases {
		if got := CheckRecommendedSDKVersion(c, "1.0.0"); got.Behind {
			t.Errorf("case %d: malformed metadata must NOT nudge; got %+v", i, got)
		}
	}
}
