// Phase 1B (#451): PolicyDecision exposes PolicyEngineVersion.
//
// Mirrors the Python and Node tests. Same canonical constant across
// all three SDKs so cross-SDK audit consumers can join rows by
// engine bytes and detect stale-SDK installs.

package controlzero

import (
	"strings"
	"testing"
)

func TestPolicyEngineVersion_ConstantFormat(t *testing.T) {
	if PolicyEngineVersion == "" {
		t.Fatal("PolicyEngineVersion must be a non-empty string")
	}
	if !strings.Contains(PolicyEngineVersion, ".") {
		t.Fatalf("expected semver-style version, got %q", PolicyEngineVersion)
	}
}

func TestPolicyEngineVersion_FieldExposed(t *testing.T) {
	// Field exists on the struct; zero-value is empty string.
	d := PolicyDecision{}
	_ = d.PolicyEngineVersion // compiles -> field present

	// Caller-populated version round-trips.
	d.PolicyEngineVersion = PolicyEngineVersion
	if d.PolicyEngineVersion != PolicyEngineVersion {
		t.Fatalf("expected %q, got %q", PolicyEngineVersion, d.PolicyEngineVersion)
	}
}

// TestGuardReturnCarriesEngineVersion is the post-review regression test
// (PR #463 review, blocker B1). It asserts that EVERY decision returned by
// Client.Guard carries the canonical engine version, not just the audit
// row that the wire-format fallback stamps. A previous version of the
// Go SDK had this field zero-valued at all six PolicyDecision
// construction sites and only the audit fallback covered it; Python and
// Node returned "0.1.0" while Go returned "" to the caller.
func TestGuardReturnCarriesEngineVersion(t *testing.T) {
	t.Run("rule_deny", func(t *testing.T) {
		c, err := New(WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"deny": "Bash:rm", "reason": "test"},
			},
		}))
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		d, _ := c.Guard("Bash", GuardOptions{
			Method: "rm",
			Args:   map[string]any{"command": "rm -rf /tmp/x"},
		})
		if d.PolicyEngineVersion != PolicyEngineVersion {
			t.Fatalf("rule-deny decision missing engine version: got %q, want %q",
				d.PolicyEngineVersion, PolicyEngineVersion)
		}
	})

	t.Run("noop_passthrough", func(t *testing.T) {
		c, err := New()
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		d, _ := c.Guard("AnyTool", GuardOptions{
			Method: "do",
			Args:   map[string]any{"x": 1},
		})
		if d.PolicyEngineVersion != PolicyEngineVersion {
			t.Fatalf("noop decision missing engine version: got %q, want %q",
				d.PolicyEngineVersion, PolicyEngineVersion)
		}
	})

	t.Run("no_rule_match", func(t *testing.T) {
		c, err := New(WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"deny": "Bash:rm", "reason": "test"},
			},
		}))
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		// Tool that doesn't match any rule -- exercises the synthetic
		// no-rule-match path in enforcer.go.
		d, _ := c.Guard("OtherTool", GuardOptions{
			Method: "do",
			Args:   map[string]any{},
		})
		if d.PolicyEngineVersion != PolicyEngineVersion {
			t.Fatalf("no-rule-match decision missing engine version: got %q, want %q",
				d.PolicyEngineVersion, PolicyEngineVersion)
		}
	})
}
