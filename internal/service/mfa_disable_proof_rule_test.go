package service

import (
	"context"
	"errors"
	"testing"
)

// THE-LAST-PASSWORD-DISARM (2026-09-10). DisableSelfWithProof accepted
// the account PASSWORD as a proof for disarming the user's own second
// factor — the first factor authorising the removal of the second, so
// a hijacked session that knew the password could disarm the account.
// identuum-idp-ce removed that proof under the owner's ruling B; this
// repository now does the same: a user disarms with a current TOTP code
// or a recovery code, nothing else. A supplied password neither proves
// nor helps, the password verifier is never consulted, and the refusal
// is the one the route already gives for a bad proof — nothing in the
// answer says a password was once accepted.

// TestMFAEnrollment_DisableSelfWithProof_PasswordAloneIsNoProof is the
// ruling itself: the CORRECT current password, alone, is refused with
// ErrMFADisableInvalidCode, the verifier is not called, and the
// enrolment is exactly as it was.
func TestMFAEnrollment_DisableSelfWithProof_PasswordAloneIsNoProof(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	secret := "JBSWY3DPEHPK3PXP"
	seedEnrolledOrgUser(userRepo, user, secret, []string{"REC-A", "REC-B"})
	method, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Password: "correct-current-password"})
	if !errors.Is(err, ErrMFADisableInvalidCode) {
		t.Fatalf("password-only disable = (%q, %v); want ErrMFADisableInvalidCode — the password is not a disarm proof", method, err)
	}
	if userRepo.verifyPasswordCalls != 0 {
		t.Errorf("password verifier calls = %d; want 0 (the password is never consulted)", userRepo.verifyPasswordCalls)
	}
	stored := userRepo.byID[user.ID]
	if !stored.MFAEnabled || stored.MFASecret == nil || *stored.MFASecret != secret || len(stored.MFARecoveryCodes) != 2 {
		t.Errorf("password-only refusal mutated state: %+v", stored)
	}
}

// TestMFAEnrollment_DisableSelfWithProof_CodeProofsStillDisarm: the two
// proofs the ruling leaves — a current TOTP code and a recovery code —
// still disarm, and a code beside a (wrong or right) password is judged
// on the code alone.
func TestMFAEnrollment_DisableSelfWithProof_CodeProofsStillDisarm(t *testing.T) {
	t.Run("current TOTP", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		seed := regenerateSeedForTest(t)
		seedEnrolledOrgUser(userRepo, user, seed, []string{"REC-A"})
		method, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Code: regenerateTOTPForTest(t, svc, seed), Password: "correct-current-password"})
		if err != nil || method != MFADisableReauthTOTP {
			t.Fatalf("TOTP disable = (%q, %v); want totp, nil", method, err)
		}
		if userRepo.verifyPasswordCalls != 0 {
			t.Errorf("password verifier calls = %d; want 0", userRepo.verifyPasswordCalls)
		}
		if userRepo.byID[user.ID].MFAEnabled {
			t.Errorf("MFAEnabled still true after a TOTP disable")
		}
	})
	t.Run("recovery code", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		seedEnrolledOrgUser(userRepo, user, "JBSWY3DPEHPK3PXP", []string{"REC-A", "REC-B"})
		method, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Code: "REC-B", Password: "wrong-current-password"})
		if err != nil || method != MFADisableReauthRecoveryCode {
			t.Fatalf("recovery-code disable = (%q, %v); want recovery_code, nil", method, err)
		}
		if userRepo.verifyPasswordCalls != 0 {
			t.Errorf("password verifier calls = %d; want 0", userRepo.verifyPasswordCalls)
		}
		stored := userRepo.byID[user.ID]
		if stored.MFAEnabled || len(stored.MFARecoveryCodes) != 0 {
			t.Errorf("recovery-code disable did not clear the enrolment: %+v", stored)
		}
	})
}
