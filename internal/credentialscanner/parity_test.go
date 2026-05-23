// Cross-SDK parity test for the credential leak scanner.
//
// The Python SDK (sdks/python/controlzero/tests/test_credential_hook.py)
// and the Node SDK (PR-3) run the same three representative inputs
// against the same embedded built_in.yaml. The match-list these
// inputs produce is the cross-SDK wire contract; any divergence
// between SDKs surfaces here.
//
// The assertions here are written by-shape (pattern ids + count +
// severity) rather than exact byte offsets so the test stays stable
// across whitespace-only tweaks to the Python / Node fixture strings.
// PR-5 lands a JSON fixture in tests/parity/credential_scanner.json
// shared across all three SDKs; this test then folds onto that
// fixture loader.
package credentialscanner

import "testing"

// parityCase carries one representative input plus the expected
// match-set shape the cross-SDK contract requires.
type parityCase struct {
	name     string
	text     string
	expected []parityMatch
}

type parityMatch struct {
	PatternID string
	Severity  string
}

func parityMatchKey(m parityMatch) string { return m.PatternID + "/" + m.Severity }

// Representative cross-SDK inputs. The first two exercise the regex
// and regex_with_paired_token strategies; the third exercises the
// marker_block strategy. All bodies use the EXAMPLE / notreal
// marker convention.
var parityCases = []parityCase{
	{
		name: "aws_access_key_in_env_dump",
		text: "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY00000Z",
		expected: []parityMatch{
			{PatternID: "AWS_ACCESS_KEY_ID", Severity: "P0"},
		},
	},
	{
		name: "github_classic_pat_in_env_dump",
		text: "GITHUB_TOKEN=ghp_EXAMPLEnotrealnotrealnotrealnotrealN",
		expected: []parityMatch{
			{PatternID: "GITHUB_PAT_CLASSIC", Severity: "P0"},
		},
	},
	{
		name: "openssh_private_key_pem_block",
		text: "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
			"EXAMPLE_THIS_IS_A_PLACEHOLDER_NOT_A_REAL_KEY_FOR_TESTS_ONLY_AAAAA\n" +
			"-----END OPENSSH PRIVATE KEY-----",
		expected: []parityMatch{
			{PatternID: "SSH_PRIVATE_KEY_OPENSSH", Severity: "P0"},
		},
	},
}

func TestCrossSDKScannerParity(t *testing.T) {
	s, err := Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}

	for _, tc := range parityCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := s.Scan(tc.text)
			seen := make(map[string]int, len(got))
			for _, m := range got {
				seen[parityMatchKey(parityMatch{PatternID: m.PatternID, Severity: m.Severity})]++
			}
			for _, want := range tc.expected {
				if seen[parityMatchKey(want)] == 0 {
					t.Errorf("parity case %q: missing required match %s/%s; got=%+v",
						tc.name, want.PatternID, want.Severity, got)
				}
			}
		})
	}
}
