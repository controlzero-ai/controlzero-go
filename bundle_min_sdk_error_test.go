// Tests for the public BundleRequiresNewerSDKError type (gh#602).
//
// The internal/bundle.CheckMinSDKVersion test suite covers the gate
// arithmetic; this file pins the public error contract that
// hosted_policy.go presents to customers: message text, E#### code,
// and copy-pasteable upgrade command.

package controlzero

import (
	"strings"
	"testing"
)

// TestBundleRequiresNewerSDKError_Error_IncludesEverything asserts
// the public Error() string includes both versions AND the upgrade
// command. Per #602 hard limit: customers must self-serve the fix
// without filing support.
func TestBundleRequiresNewerSDKError_Error_IncludesEverything(t *testing.T) {
	err := &BundleRequiresNewerSDKError{
		Required:       "1.5.8",
		Actual:         "v1.0.0",
		UpgradeCommand: "go get github.com/control-zero/controlzero@latest",
	}
	msg := err.Error()
	if !strings.Contains(msg, "1.5.8") {
		t.Errorf("message must name the required version; got %q", msg)
	}
	if !strings.Contains(msg, "v1.0.0") {
		t.Errorf("message must name the actual SDK version; got %q", msg)
	}
	if !strings.Contains(msg, "go get") {
		t.Errorf("message must include an upgrade command; got %q", msg)
	}
}

// TestBundleRequiresNewerSDKError_ECode asserts the stable E#### code
// is E1712. Mirrors the Python E_CODE attribute and the Node e_code
// field so customers see the same docs URL across all 3 SDKs.
func TestBundleRequiresNewerSDKError_ECode(t *testing.T) {
	err := &BundleRequiresNewerSDKError{Required: "1.0", Actual: "0.1"}
	if got := err.ECode(); got != "E1712" {
		t.Errorf("ECode: got %q, want E1712", got)
	}
	if ECodeBundleRequiresNewerSDK != "E1712" {
		t.Errorf("package constant: got %q, want E1712", ECodeBundleRequiresNewerSDK)
	}
}

// TestBundleRequiresNewerSDKError_ConformsToError asserts the type
// satisfies the error interface so callers can `errors.As(err,
// &target)` it through any wrapped chain.
func TestBundleRequiresNewerSDKError_ConformsToError(t *testing.T) {
	var _ error = &BundleRequiresNewerSDKError{}
}
