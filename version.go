// Package controlzero exports the canonical Version of the SDK so
// runtime callers (audit_remote.go, conformance fixtures, debug
// bundle) can read it without parsing go.mod or guessing.
//
// #495 / v1 (2026-05-14): introduced alongside the
// controlzero_sdk_version audit-log column. The wire-format helper
// builds the normalized "go@<version>" string the backend ingest
// accepts.
//
// CI drift guard: scripts/ci/check-go-sdk-version-drift.sh asserts
// Version matches the latest git tag matching `sdks/go/controlzero/v*`.
// A tag bump without updating this constant fails the check. The
// reverse (constant ahead of tag) is fine -- the next tag will
// catch up.
package controlzero

// Version is the package version of the controlzero Go SDK. Bump
// this in lockstep with the git tag in sdks/go/controlzero. The drift
// CI guard enforces equality on every PR that touches the package.
const Version = "v1.7.6"

// sdkVersionWire is the "<lang>@<version>" wire-format value the
// audit POST carries. 64-char cap mirrors the backend ingest gate
// (MaxControlzeroSDKVersionLen) so over-length values never
// round-trip. Computed once at package init so audit_remote.go can
// read it without re-allocating per row.
var sdkVersionWire = func() string {
	w := "go@" + Version
	if len(w) > 64 {
		return ""
	}
	return w
}()
