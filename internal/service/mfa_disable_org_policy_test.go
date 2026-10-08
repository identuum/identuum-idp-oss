package service

import (
	"context"
	"errors"
	"testing"
)

// F4 (SEC-MFA-REVIEW-2026-10-08): self-disable read the user without the
// organization join, so an org_user of an organization that requires MFA
// could disable it with a valid TOTP or recovery code. The organization's
// policy decides: 403 and nothing cleared.
func TestMFAEnrollment_DisableSelfWithProof_HonoursTheOrganizationPolicy(t *testing.T) {
	required := "required"
	t.Run("current TOTP", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		seed := regenerateSeedForTest(t)
		seedEnrolledOrgUser(userRepo, user, seed, []string{"REC-A"})
		userRepo.byID[user.ID].MFAPolicy = &required
		_, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Code: regenerateTOTPForTest(t, svc, seed)})
		if !errors.Is(err, ErrMFADisableForbiddenByPolicy) || !userRepo.byID[user.ID].MFAEnabled {
			t.Fatalf("got %v, MFA enabled %v; want ErrMFADisableForbiddenByPolicy and MFA kept", err, userRepo.byID[user.ID].MFAEnabled)
		}
	})
	t.Run("recovery code", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		seedEnrolledOrgUser(userRepo, user, "JBSWY3DPEHPK3PXP", []string{"REC-A", "REC-B"})
		userRepo.byID[user.ID].MFAPolicy = &required
		_, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Code: "REC-B"})
		stored := userRepo.byID[user.ID]
		if !errors.Is(err, ErrMFADisableForbiddenByPolicy) || !stored.MFAEnabled || len(stored.MFARecoveryCodes) != 2 {
			t.Fatalf("got %v, MFA enabled %v, %d recovery codes; want refusal and nothing cleared", err, stored.MFAEnabled, len(stored.MFARecoveryCodes))
		}
	})
}
