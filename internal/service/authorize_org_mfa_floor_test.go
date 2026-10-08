package service

import (
	"errors"
	"testing"

	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// F7 P12 (SEC-MFA-REVIEW-2026-10-08, owner ruling bb): authorize honoured a
// client's acr_values but not the organization's MFA policy, so a session
// without MFA kept getting codes after the organization required MFA. With
// no acr_values at all, the organization floor decides: step-up when the
// user can do it, the honest unmet error when not, a code when the session
// did MFA.
func TestAuthorize_RequiredMFAPolicyIsAFloor(t *testing.T) {
	cases := []struct {
		name, policy, sessionACR string
		enrolled                 bool
		want                     error // nil: a code is minted
	}{
		{"required, password session, TOTP enrolled", "required", auth.ACRPassword, true, ErrAuthorizeStepUpRequired},
		{"required, password session, not enrolled", "required", auth.ACRPassword, false, ErrAuthorizeUnmetAuthenticationRequirements},
		{"required, MFA session", "required", auth.ACRMFA, true, nil},
		{"optional, password session", "optional", auth.ACRPassword, true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, principal := acrHarness(t, tc.sessionACR, tc.enrolled)
			svc.WithOrganizationLookup(newFakeOrgRepo(&domain.Organization{ID: principal.OrganizationID, Active: true, MFAPolicy: tc.policy}))
			_, err := authorizeWithACR(t, svc, principal, "")
			if tc.want == nil {
				if err != nil || len(repo.byID) != 1 {
					t.Fatalf("err = %v, codes %d; want one code", err, len(repo.byID))
				}
				return
			}
			if !errors.Is(err, tc.want) || len(repo.byID) != 0 {
				t.Fatalf("err = %v, codes %d; want %v and no code", err, len(repo.byID), tc.want)
			}
		})
	}
}
