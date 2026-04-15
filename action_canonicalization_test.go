package controlzero

import "testing"

// Cross-SDK action canonicalization parity (issue #69).
//
// Mirrors the fixture at tests/cross-sdk/policy-action-format.json. The
// same cases run in the Python SDK (test_action_canonicalization.py)
// and Node SDK (actionCanonicalization.test.ts). Drift between any of
// the three breaks this test in the SDK that drifted.

func TestActionCanonicalization_Parity(t *testing.T) {
	// Keep this list in sync with the same fixture in the Python + Node tests.
	cases := []struct {
		in       string
		expected string
	}{
		{"*", "*"},
		{"delete_*", "delete_*:*"},
		{"github", "github:*"},
		{"github:*", "github:*"},
		{"github:list_*", "github:list_*"},
		{"*:read", "*:read"},
		{"llm:openai.generate", "llm:openai.generate"},
		{"tool_with_dot.name", "tool_with_dot.name:*"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := canonicalizeAction(c.in)
			if got != c.expected {
				t.Fatalf("canonicalizeAction(%q) = %q, want %q", c.in, got, c.expected)
			}
		})
	}
}
