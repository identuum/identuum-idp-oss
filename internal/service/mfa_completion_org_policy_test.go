package service

import (
	"context"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// F5 and F6 (SEC-MFA-REVIEW-2026-10-08): the pending-MFA sign-in completion
// returned the user without the organization join, so the session it made
// had no session cap (F5), and an organization switched to idp_only between
// the password and the code still got an org_user session (F6). Completion
// returns the organization-bearing user and applies the local-credential rule.
func TestMFAVerifyLogin_UsesTheOrganizationPolicy(t *testing.T) {
	verify := func(t *testing.T, role domain.UserRole, authPolicy string, cap int) (*MFAEnrollmentCompleteResult, error) {
		t.Helper()
		svc, _, userRepo, user := newEnrollSvc(t)
		stored := userRepo.byID[user.ID]
		secret, _ := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
		stored.Role, stored.MFAEnabled, stored.MFASecret = role, true, &secret
		stored.OrgAuthPolicy, stored.OrgMaxSessionsPerUser = &authPolicy, &cap
		row, err := svc.CreatePending(context.Background(), stored, domain.MFAPendingKindVerify, false)
		if err != nil {
			t.Fatal(err)
		}
		code, _ := computeHOTP(secret, uint64(svc.now().Unix())/defaultTOTPPeriod, defaultTOTPDigits)
		return svc.VerifyAndConsume(context.Background(), row.ID, code)
	}
	t.Run("the organization session cap reaches the session", func(t *testing.T) {
		res, err := verify(t, domain.RoleOrgUser, domain.AuthPolicyMixed, 2)
		if err != nil {
			t.Fatal(err)
		}
		if res.User.OrgMaxSessionsPerUser == nil || *res.User.OrgMaxSessionsPerUser != 2 {
			t.Fatalf("completion returned session cap %v; want 2", res.User.OrgMaxSessionsPerUser)
		}
	})
	t.Run("idp_only refuses an org_user", func(t *testing.T) {
		if res, err := verify(t, domain.RoleOrgUser, domain.AuthPolicyIDPOnly, 2); err == nil || res != nil {
			t.Fatalf("an org_user completed local MFA under idp_only (error %v)", err)
		}
	})
	t.Run("idp_only keeps an org_admin's local sign-in", func(t *testing.T) {
		if _, err := verify(t, domain.RoleOrgAdmin, domain.AuthPolicyIDPOnly, 2); err != nil {
			t.Fatalf("an org_admin was refused: %v", err)
		}
	})
}
