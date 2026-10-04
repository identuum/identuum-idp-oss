package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// D-026: turning on "skip consent" for an app needs the org_admin's current
// TOTP code. ProveTOTP is that proof as a service call: ONLY a current TOTP
// code counts (a recovery code never does, as for regenerate), every wrong
// proof is one cause-neutral refusal, and the replay guard burns the step.
func TestMFAEnrollment_ProveTOTP(t *testing.T) {
	ctx := context.Background()

	t.Run("a current TOTP code proves, once", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		seed := regenerateSeedForTest(t)
		seedEnrolledOrgUser(userRepo, user, seed, []string{"REC-A"})
		code := regenerateTOTPForTest(t, svc, seed)
		if err := svc.ProveTOTP(ctx, user.ID, code); err != nil {
			t.Fatalf("a current code: %v", err)
		}
		if err := svc.ProveTOTP(ctx, user.ID, code); !errors.Is(err, ErrMFAProofInvalid) {
			t.Errorf("the same code again: err=%v, want ErrMFAProofInvalid (the step is single-use)", err)
		}
	})

	t.Run("absent, blank, wrong and recovery-code proofs are one refusal", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		seedEnrolledOrgUser(userRepo, user, regenerateSeedForTest(t), []string{"REC-A"})
		for _, code := range []string{"", "   ", "abcdef", "12345", "REC-A"} {
			if err := svc.ProveTOTP(ctx, user.ID, code); !errors.Is(err, ErrMFAProofInvalid) {
				t.Errorf("code %q: err=%v, want ErrMFAProofInvalid", code, err)
			}
		}
		if got := userRepo.byID[user.ID].MFARecoveryCodes; len(got) != 1 {
			t.Errorf("stored recovery codes = %d after refusals, want 1 (nothing burned)", len(got))
		}
	})

	t.Run("a user without MFA is told to enroll", func(t *testing.T) {
		svc, _, _, user := newEnrollSvc(t)
		if err := svc.ProveTOTP(ctx, user.ID, "123456"); !errors.Is(err, ErrMFANotEnrolled) {
			t.Errorf("err=%v, want ErrMFANotEnrolled", err)
		}
	})

	t.Run("an unknown user is refused", func(t *testing.T) {
		svc, _, _, _ := newEnrollSvc(t)
		if err := svc.ProveTOTP(ctx, uuid.New(), "123456"); !errors.Is(err, ErrMFAEnrollmentInvalid) {
			t.Errorf("err=%v, want ErrMFAEnrollmentInvalid", err)
		}
	})
}
