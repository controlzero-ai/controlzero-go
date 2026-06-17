// Tests for `controlzero update` (self-update command).
//
// Hermetic: the module-proxy lookup is stubbed via latestVersionFunc (or
// pointed at an httptest server via proxyLatestURL); the actual `go install`
// is stubbed via the injectable installer in runUpdateWith. No test touches
// the real network or runs the real toolchain. Mirrors the Python
// tests/test_update_cmd.py cases.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withStubLatest swaps latestVersionFunc for the duration of a test and
// restores it after.
func withStubLatest(t *testing.T, v string) {
	t.Helper()
	prev := latestVersionFunc
	latestVersionFunc = func() string { return v }
	t.Cleanup(func() { latestVersionFunc = prev })
}

// noInstall is an installer that fails loudly if called -- used to prove
// --check never shells out.
func noInstall(_, _ io.Writer) error {
	return errors.New("must not install under --check")
}

func TestParseVersion_NumericNotLexical(t *testing.T) {
	// 1.9.10 must sort ABOVE 1.9.9 (lexical "10" < "9" would be wrong).
	if compareVersions("1.9.10", "1.9.9") <= 0 {
		t.Errorf("1.9.10 must be > 1.9.9 (numeric)")
	}
	if compareVersions("1.10.0", "1.9.99") <= 0 {
		t.Errorf("1.10.0 must be > 1.9.99 (numeric)")
	}
	if compareVersions("v1.9.9", "1.9.9") != 0 {
		t.Errorf("v1.9.9 must equal 1.9.9 (v-prefix stripped)")
	}
	if compareVersions("1.9.9-rc1", "1.9.9") != 0 {
		t.Errorf("1.9.9-rc1 must equal 1.9.9 (prerelease dropped)")
	}
	if compareVersions("1.8", "1.8.0") != 0 {
		t.Errorf("1.8 must equal 1.8.0 (zero-padded)")
	}
	if got := parseVersion("garbage"); len(got) != 1 || got[0] != 0 {
		t.Errorf("garbage must parse to [0]; got %v", got)
	}
}

func TestParseVersion_Table(t *testing.T) {
	cases := []struct {
		a, b string
		want int // sign of compareVersions(a,b)
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"2.0.0", "1.99.99", 1},
		{"1.9.10", "1.9.9", 1},
		{"1.10.0", "1.9.9", 1},
		{"v1.8.0", "1.8.0", 0},
		{"1.8.0", "v1.8.0", 0},
		{"1.8.0-rc1", "1.8.0", 0},
		{"1.8.0+build5", "1.8.0", 0},
		{"1.8", "1.8.0", 0},
		{"1.8.1", "1.8", 1},
		{"", "0.0.0", 0},
		{"garbage", "0.0.0", 0},
	}
	for _, c := range cases {
		got := compareVersions(c.a, c.b)
		// normalize to sign
		if got > 0 {
			got = 1
		} else if got < 0 {
			got = -1
		}
		if got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestRunUpdate_UpToDate(t *testing.T) {
	withStubLatest(t, Version) // proxy reports our exact version
	var out, errw bytes.Buffer
	code := runUpdateWith(&out, &errw, strings.NewReader(""), false, false, noInstall)
	if code != 0 {
		t.Fatalf("up-to-date exit: got %d want 0", code)
	}
	if !strings.Contains(out.String(), "up to date") {
		t.Errorf("expected 'up to date' in output; got %q", out.String())
	}
}

func TestRunUpdate_CheckReportsAvailableWithoutInstalling(t *testing.T) {
	withStubLatest(t, "9999.0.0")
	var out, errw bytes.Buffer
	// noInstall would error if --check ever shelled out.
	code := runUpdateWith(&out, &errw, strings.NewReader(""), true /*check*/, false, noInstall)
	if code != exitUpdateAvailable {
		t.Fatalf("--check exit: got %d want %d", code, exitUpdateAvailable)
	}
	if !strings.Contains(out.String(), Version+" -> 9999.0.0") {
		t.Errorf("expected 'current -> latest' in output; got %q", out.String())
	}
}

func TestRunUpdate_CheckUpToDateExitsZero(t *testing.T) {
	withStubLatest(t, "0.0.1") // far below current
	var out, errw bytes.Buffer
	code := runUpdateWith(&out, &errw, strings.NewReader(""), true, false, noInstall)
	if code != 0 {
		t.Fatalf("--check up-to-date exit: got %d want 0", code)
	}
}

func TestRunUpdate_NetworkFailureDegrades(t *testing.T) {
	withStubLatest(t, "") // proxy unreachable
	var out, errw bytes.Buffer
	code := runUpdateWith(&out, &errw, strings.NewReader(""), true, false, noInstall)
	if code != exitUnknown {
		t.Fatalf("network-failure exit: got %d want %d", code, exitUnknown)
	}
	if !strings.Contains(errw.String(), "could not reach the module proxy") {
		t.Errorf("expected degrade message on stderr; got %q", errw.String())
	}
	if !strings.Contains(errw.String(), "go install "+installPath+"@latest") {
		t.Errorf("expected manual install command on stderr; got %q", errw.String())
	}
}

func TestRunUpdate_YesRunsInstaller(t *testing.T) {
	withStubLatest(t, "9999.0.0")
	var out, errw bytes.Buffer
	called := false
	installer := func(_, _ io.Writer) error { called = true; return nil }
	code := runUpdateWith(&out, &errw, strings.NewReader(""), false, true /*yes*/, installer)
	if code != 0 {
		t.Fatalf("--yes success exit: got %d want 0", code)
	}
	if !called {
		t.Errorf("installer was not invoked under --yes")
	}
	if !strings.Contains(out.String(), "Running: go install "+installPath+"@latest") {
		t.Errorf("expected echoed install command; got %q", out.String())
	}
	if !strings.Contains(out.String(), "Upgraded controlzero to 9999.0.0") {
		t.Errorf("expected success line; got %q", out.String())
	}
}

func TestRunUpdate_InstallFailureExitCode(t *testing.T) {
	withStubLatest(t, "9999.0.0")
	var out, errw bytes.Buffer
	installer := func(_, _ io.Writer) error { return errors.New("boom") }
	code := runUpdateWith(&out, &errw, strings.NewReader(""), false, true, installer)
	if code != exitUpgradeFailed {
		t.Fatalf("install-failure exit: got %d want %d", code, exitUpgradeFailed)
	}
	if !strings.Contains(strings.ToLower(errw.String()), "failed") {
		t.Errorf("expected failure message on stderr; got %q", errw.String())
	}
	if !strings.Contains(errw.String(), "go install "+installPath+"@latest") {
		t.Errorf("expected manual fallback command; got %q", errw.String())
	}
}

func TestRunUpdate_PromptDeclineSkips(t *testing.T) {
	withStubLatest(t, "9999.0.0")
	var out, errw bytes.Buffer
	called := false
	installer := func(_, _ io.Writer) error { called = true; return nil }
	// "n\n" declines the prompt.
	code := runUpdateWith(&out, &errw, strings.NewReader("n\n"), false, false, installer)
	if code != 0 {
		t.Fatalf("declined-prompt exit: got %d want 0", code)
	}
	if called {
		t.Errorf("installer must NOT run when prompt declined")
	}
	if !strings.Contains(out.String(), "Skipped") {
		t.Errorf("expected 'Skipped' message; got %q", out.String())
	}
}

func TestRunUpdate_PromptEmptyDefaultsYes(t *testing.T) {
	withStubLatest(t, "9999.0.0")
	var out, errw bytes.Buffer
	called := false
	installer := func(_, _ io.Writer) error { called = true; return nil }
	// Empty line -> default yes (mirrors click.confirm default=True).
	code := runUpdateWith(&out, &errw, strings.NewReader("\n"), false, false, installer)
	if code != 0 {
		t.Fatalf("default-yes exit: got %d want 0", code)
	}
	if !called {
		t.Errorf("empty-line prompt must default to yes and install")
	}
}

// TestLatestProxyVersion_ParsesProxyJSON exercises the real
// latestProxyVersion against a local httptest server (no real network),
// proving the proxy @latest JSON shape {"Version":"v1.2.3"} is parsed.
func TestLatestProxyVersion_ParsesProxyJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Version":"v1.9.10","Time":"2026-06-17T00:00:00Z"}`)
	}))
	defer srv.Close()

	prev := proxyLatestURL
	proxyLatestURL = srv.URL
	defer func() { proxyLatestURL = prev }()

	if got := latestProxyVersion(); got != "v1.9.10" {
		t.Errorf("latestProxyVersion: got %q want v1.9.10", got)
	}
}

// TestLatestProxyVersion_404FallsBack proves a 404 (e.g. private module path
// not yet synced to the proxy) degrades to "" so the caller prints the
// manual install command instead of crashing.
func TestLatestProxyVersion_404FallsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	prev := proxyLatestURL
	proxyLatestURL = srv.URL
	defer func() { proxyLatestURL = prev }()

	if got := latestProxyVersion(); got != "" {
		t.Errorf("404 must degrade to empty; got %q", got)
	}
}

// TestLatestProxyVersion_BadJSONFallsBack proves malformed JSON degrades to
// "" rather than panicking.
func TestLatestProxyVersion_BadJSONFallsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `not json`)
	}))
	defer srv.Close()

	prev := proxyLatestURL
	proxyLatestURL = srv.URL
	defer func() { proxyLatestURL = prev }()

	if got := latestProxyVersion(); got != "" {
		t.Errorf("bad JSON must degrade to empty; got %q", got)
	}
}

// TestUpdateCmd_Registered asserts the subcommand is wired into the root via
// the same registration path as init/validate/test/tail.
func TestUpdateCmd_Registered(t *testing.T) {
	cmd := updateCmd()
	if cmd.Use != "update" {
		t.Errorf("update command Use: got %q want update", cmd.Use)
	}
	if f := cmd.Flags().Lookup("check"); f == nil {
		t.Errorf("--check flag not registered")
	}
	if f := cmd.Flags().Lookup("yes"); f == nil {
		t.Errorf("--yes flag not registered")
	}
}
