// In-package test for gh#175 outside-voice P1 fix: when the SDK is
// in hosted mode, the caller-supplied Context.ProjectID MUST be
// overwritten by the bundle's hostedProjectID -- including when
// hostedProjectID is itself empty. Without this gap fix, an unscoped
// hosted bundle would let a caller spoof a project_id via Context.
package controlzero

import "testing"

func TestBuildEvalContext_HostedAlwaysOverridesProjectID(t *testing.T) {
	cases := []struct {
		name            string
		isHosted        bool
		hostedProjectID string
		callerProjectID string
		wantProjectID   string
	}{
		{
			name:            "hosted_with_project_id_wins_over_caller",
			isHosted:        true,
			hostedProjectID: "proj-prod",
			callerProjectID: "proj-spoof",
			wantProjectID:   "proj-prod",
		},
		{
			name:            "hosted_with_EMPTY_project_id_still_blanks_caller",
			isHosted:        true,
			hostedProjectID: "",
			callerProjectID: "proj-spoof",
			wantProjectID:   "", // spoof must be blanked
		},
		{
			name:            "local_mode_caller_value_survives",
			isHosted:        false,
			hostedProjectID: "",
			callerProjectID: "proj-local-dev",
			wantProjectID:   "proj-local-dev",
		},
		{
			name:            "local_mode_no_caller_value_defaults_empty",
			isHosted:        false,
			hostedProjectID: "",
			callerProjectID: "",
			wantProjectID:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{
				hostedProjectID: tc.hostedProjectID,
				isHosted:        tc.isHosted,
			}
			got := c.buildEvalContext(&EvalContext{ProjectID: tc.callerProjectID})
			if got.ProjectID != tc.wantProjectID {
				t.Errorf("buildEvalContext().ProjectID = %q, want %q", got.ProjectID, tc.wantProjectID)
			}
		})
	}
}
