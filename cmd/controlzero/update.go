package main

// `controlzero update` -- self-update the Go SDK CLI to the latest release.
//
// Why this exists: enforcement and audit fixes (e.g. the no-policy->observe
// posture and self-explaining deny, #1247/#1303) ship in the SDK, so a
// customer on an old version keeps hitting fixed bugs until they upgrade.
// `controlzero update` is the one-command path the upgrade nudge points at,
// so closing that loop is a `go install` away instead of a support ticket.
//
// This mirrors the Python `controlzero update` (cli/update_cmd.py) in
// behavior: read the running Version, ask the source-of-truth registry for
// the latest release, `--check` reports only (with a distinct exit code when
// behind), otherwise show current->latest, prompt, and run the upgrader.
//
// Source of latest: the Go SDK installs via
//
//	go install controlzero.ai/sdk/go/cmd/controlzero@latest
//
// so the latest version is whatever the Go module proxy resolves `@latest`
// to. We query the proxy's @latest endpoint:
//
//	https://proxy.golang.org/controlzero.ai/sdk/go/@latest  ->  {"Version":"v1.7.6",...}
//
// stdlib net/http only, 6s timeout, degrades gracefully on any network
// failure (this command must never panic on a flaky network). If the proxy
// 404s for the module path (e.g. a private path not yet synced), we fall
// back to printing the manual `go install ...@latest` command.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// modulePath is the public Go module path the CLI is installed from. It
// matches the `module` line in go.mod (controlzero.ai/sdk/go) and the path
// the public-sync workflow (sync-go-sdk-public.yml) publishes under, and the
// `go install controlzero.ai/sdk/go/cmd/controlzero@latest` line in the
// README / docs.
const modulePath = "controlzero.ai/sdk/go"

// installPath is the full `cmd` package path `go install` targets.
const installPath = modulePath + "/cmd/controlzero"

// proxyLatestURL is the Go module proxy @latest endpoint for modulePath. It
// returns JSON `{"Version":"v1.2.3",...}`. Held in a package-level var so
// tests can point it at an httptest server (hermetic, no real network).
var proxyLatestURL = "https://proxy.golang.org/" + modulePath + "/@latest"

// proxyTimeout caps the latest-version lookup. Mirrors the Python 6s.
const proxyTimeout = 6 * time.Second

// Exit codes (stable for the nudge / scripts; mirror the Python EXIT_*):
//
//	0  up to date, or upgrade performed
//	10 an update is available (only with --check; without --check we upgrade)
//	11 could not determine the latest version (network/proxy error)
//	12 upgrade attempt failed
const (
	exitUpdateAvailable = 10
	exitUnknown         = 11
	exitUpgradeFailed   = 12
)

// latestVersionFunc resolves the latest published version, or "" on any
// failure. A package-level var so tests inject a stub without hitting the
// network (mirrors the Python monkeypatch of _latest_pypi_version).
var latestVersionFunc = latestProxyVersion

// latestProxyVersion returns the latest CLI version the Go module proxy
// resolves `@latest` to, or "" on any failure (network down, non-200, bad
// JSON). Never panics -- this gates an upgrade prompt, not security.
func latestProxyVersion() string {
	client := &http.Client{Timeout: proxyTimeout}
	req, err := http.NewRequest(http.MethodGet, proxyLatestURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 404 / 410 etc. -- module path not resolvable at the proxy. Caller
		// degrades to the manual install command.
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return ""
	}
	var meta struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return ""
	}
	return meta.Version
}

// parseVersion parses "1.9.10" -> [1, 9, 10] for NUMERIC (not lexical)
// ordering, so 1.9.10 sorts above 1.9.9. A leading "v"/"V" is stripped (Go
// tags carry it) and a trailing pre-release / build segment ("-rc1",
// "+local") is dropped so a release sorts at or above its own pre-releases.
// Leading digits of each dotted segment are taken; unparseable parts become
// 0. Never panics. Mirrors the Python _parse_version semantics.
func parseVersion(v string) []int {
	core := strings.TrimLeft(strings.TrimSpace(v), "vV")
	// Drop build metadata then pre-release suffix.
	if i := strings.IndexByte(core, '+'); i >= 0 {
		core = core[:i]
	}
	if i := strings.IndexByte(core, '-'); i >= 0 {
		core = core[:i]
	}
	if core == "" {
		return []int{0}
	}
	parts := strings.Split(core, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for j := 0; j < len(p); j++ {
			ch := p[j]
			if ch < '0' || ch > '9' {
				break
			}
			n = n*10 + int(ch-'0')
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return []int{0}
	}
	return out
}

// compareVersions returns -1, 0, or +1 for a<b, a==b, a>b using numeric
// tuple ordering. Shorter tuples are zero-padded ("1.9" == "1.9.0").
func compareVersions(a, b string) int {
	av, bv := parseVersion(a), parseVersion(b)
	n := len(av)
	if len(bv) > n {
		n = len(bv)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(av) {
			ai = av[i]
		}
		if i < len(bv) {
			bi = bv[i]
		}
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}
	return 0
}

// manualInstallCommand is the copy-pasteable upgrade command shown whenever
// the proxy is unreachable or the upgrade attempt fails.
func manualInstallCommand() string {
	return "go install " + installPath + "@latest"
}

// updateCmd builds the `controlzero update` cobra subcommand. The testable
// core lives in runUpdate; RunE wires it to os.Exit with the returned code so
// the documented exit codes (10/11/12) reach scripts and the nudge.
func updateCmd() *cobra.Command {
	var checkOnly, assumeYes bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the controlzero CLI to the latest release",
		Long: `Update the controlzero CLI to the latest release.

Enforcement and audit fixes ship in the SDK, so staying current is how you
get them. Run 'controlzero update' (or 'controlzero update --check' in
scripts; it exits 10 when an update is available).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			code := runUpdate(cmd.OutOrStdout(), cmd.ErrOrStderr(),
				cmd.InOrStdin(), checkOnly, assumeYes)
			os.Exit(code)
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false,
		"Only check whether a newer version exists; do not install. Exits 10 if an update is available.")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false,
		"Upgrade without the confirmation prompt.")
	return cmd
}

// runUpdate is the testable core of `controlzero update`. It returns the
// process exit code (mirrors the Python EXIT_*). It never calls os.Exit so
// tests can assert the code directly. installer defaults to runGoInstall and
// is a parameter only so tests can stub the actual install.
func runUpdate(stdout, stderr io.Writer, stdin io.Reader, checkOnly, assumeYes bool) int {
	return runUpdateWith(stdout, stderr, stdin, checkOnly, assumeYes, runGoInstall)
}

// runUpdateWith is runUpdate with an injectable installer for tests.
func runUpdateWith(
	stdout, stderr io.Writer, stdin io.Reader,
	checkOnly, assumeYes bool,
	installer func(io.Writer, io.Writer) error,
) int {
	current := Version
	latest := latestVersionFunc()

	if latest == "" {
		fmt.Fprintf(stderr,
			"controlzero %s (could not reach the module proxy to check for updates). "+
				"Upgrade manually with: %s\n",
			current, manualInstallCommand())
		return exitUnknown
	}

	if compareVersions(current, latest) >= 0 {
		fmt.Fprintf(stdout, "controlzero %s is up to date (latest: %s).\n", current, latest)
		return 0
	}

	fmt.Fprintf(stdout, "Update available: controlzero %s -> %s\n", current, latest)

	if checkOnly {
		fmt.Fprintln(stdout, "Run `controlzero update` to install it.")
		return exitUpdateAvailable
	}

	if !assumeYes {
		if !confirm(stdout, stdin, fmt.Sprintf("Upgrade controlzero to %s now?", latest)) {
			fmt.Fprintln(stdout, "Skipped. Upgrade later with: controlzero update")
			return 0
		}
	}

	fmt.Fprintf(stdout, "Running: %s\n", manualInstallCommand())
	if err := installer(stdout, stderr); err != nil {
		fmt.Fprintf(stderr,
			"Upgrade command failed (%v). Try manually:\n  %s\n",
			err, manualInstallCommand())
		return exitUpgradeFailed
	}

	fmt.Fprintf(stdout,
		"Upgraded controlzero to %s. Restart your agent/hook to use it.\n", latest)
	return 0
}

// runGoInstall runs `go install controlzero.ai/sdk/go/cmd/controlzero@latest`
// in the current environment, streaming output. Returns an error on a missing
// toolchain or a non-zero exit so the caller prints the manual fallback.
func runGoInstall(stdout, stderr io.Writer) error {
	c := exec.Command("go", "install", installPath+"@latest")
	c.Stdout = stdout
	c.Stderr = stderr
	c.Stdin = nil
	return c.Run()
}

// confirm reads a y/N answer from stdin (default yes on an empty line, like
// the Python click.confirm default=True). Any read error -> treated as "no"
// so a non-interactive context never silently installs.
func confirm(stdout io.Writer, stdin io.Reader, prompt string) bool {
	fmt.Fprintf(stdout, "%s [Y/n] ", prompt)
	r := bufio.NewReader(stdin)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "" || ans == "y" || ans == "yes"
}
