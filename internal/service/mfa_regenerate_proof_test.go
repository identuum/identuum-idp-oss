package service

import (
	"context"
	"errors"
	"testing"
)

// THE-OSS-HALF-OF-THE-RULING (2026-09-10). RegenerateRecoveryCodes took
// the user id alone and minted fresh recovery codes, while
// DisableSelfWithProof accepts a recovery code as a valid proof — so a
// session that could regenerate held a fresh set of disable proofs a
// moment later. Owner ruling (b): A TOTP CODE ONLY; a recovery code must
// not buy more recovery codes. These pins hold the service to it and hold
// the disable exactly where it was: its TOTP leg and the regenerate's
// share ONE helper (totpProofOK), and its recovery-code leg is untouched.
// The HTTP-level RED-first pin for the same ruling is
// internal/e2e/mfa_recovery_regenerate_http_test.go.

// regenerateSeedForTest mints a real base32 TOTP seed for a fixture row
// (the identity cipher stores it unchanged).
func regenerateSeedForTest(t *testing.T) string {
	t.Helper()
	seed, err := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	return seed
}

// regenerateTOTPForTest computes the code the service expects at its
// pinned clock (newEnrollSvc pins svc.now to one instant).
func regenerateTOTPForTest(t *testing.T, svc *MFAEnrollmentService, seed string) string {
	t.Helper()
	code, err := computeHOTP(seed, uint64(svc.now().Unix())/defaultTOTPPeriod, defaultTOTPDigits)
	if err != nil {
		t.Fatalf("compute TOTP: %v", err)
	}
	return code
}

func TestMFAEnrollment_RegenerateRecoveryCodes_RecoveryCodeIsRefused(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	seed := regenerateSeedForTest(t)
	seedEnrolledOrgUser(userRepo, user, seed, []string{"REC-A", "REC-B", "REC-C"})
	before := append([]string(nil), userRepo.byID[user.ID].MFARecoveryCodes...)

	_, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID, "REC-B")
	if !errors.Is(err, ErrMFARegenerateInvalidCode) {
		t.Fatalf("regenerate with a VALID recovery code = %v; want ErrMFARegenerateInvalidCode", err)
	}
	// Not burned, not replaced.
	after := userRepo.byID[user.ID].MFARecoveryCodes
	if len(after) != len(before) {
		t.Fatalf("stored codes = %d after a refused regenerate; want %d", len(after), len(before))
	}
	for i := range before {
		if after[i] != before[i] {
			t.Fatalf("stored code %d changed under a refused regenerate", i)
		}
	}
	// The route the ruling leaves open: the same recovery code still
	// disarms through the disable.
	method, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Code: "REC-B"})
	if err != nil || method != MFADisableReauthRecoveryCode {
		t.Fatalf("disable with the same recovery code = %q, %v; want recovery_code, nil", method, err)
	}
}

func TestMFAEnrollment_RegenerateRecoveryCodes_AbsentEmptyWrongAreOneRefusal(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	seed := regenerateSeedForTest(t)
	seedEnrolledOrgUser(userRepo, user, seed, []string{"REC-A"})
	for _, code := range []string{"", "   ", "abcdef", "12345", "REC-A"} {
		_, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID, code)
		if !errors.Is(err, ErrMFARegenerateInvalidCode) {
			t.Errorf("code %q: err = %v; want ErrMFARegenerateInvalidCode (one cause-neutral refusal)", code, err)
		}
	}
	if got := userRepo.byID[user.ID].MFARecoveryCodes; len(got) != 1 {
		t.Errorf("stored codes = %d after refusals; want 1 (nothing burned or replaced)", len(got))
	}
}

func TestMFAEnrollment_RegenerateRecoveryCodes_TOTPCodeAccepted(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	seed := regenerateSeedForTest(t)
	seedEnrolledOrgUser(userRepo, user, seed, []string{"REC-A"})
	codes, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID, regenerateTOTPForTest(t, svc, seed))
	if err != nil {
		t.Fatalf("regenerate with a current TOTP code: %v", err)
	}
	if len(codes) != defaultMFAEnrollmentRecoveryCodeCount {
		t.Fatalf("count = %d; want %d", len(codes), defaultMFAEnrollmentRecoveryCodeCount)
	}
	stored := userRepo.byID[user.ID]
	if len(stored.MFARecoveryCodes) != len(codes) {
		t.Fatalf("persisted codes = %d; want %d", len(stored.MFARecoveryCodes), len(codes))
	}
	if _, ok := consumeRecoveryCode(stored.MFARecoveryCodes, "REC-A"); ok {
		t.Error("the seeded recovery code survived the regenerate")
	}
	if !stored.MFAEnabled || stored.MFASecret == nil || *stored.MFASecret != seed {
		t.Error("the enrolment moved under a regenerate")
	}
}

// TestMFAEnrollment_RegenerateRecoveryCodes_UndecryptableSeedRefuses: a
// seed the cipher cannot open leaves the shared TOTP leg false — the
// regenerate refuses (there is no recovery-code leg to fall through to).
func TestMFAEnrollment_RegenerateRecoveryCodes_UndecryptableSeedRefuses(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	svc.cipher = nil // decryptSeed → ErrMFASecretUnavailable
	seed := regenerateSeedForTest(t)
	seedEnrolledOrgUser(userRepo, user, seed, []string{"REC-A"})
	_, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID, regenerateTOTPForTest(t, svc, seed))
	if !errors.Is(err, ErrMFARegenerateInvalidCode) {
		t.Fatalf("regenerate with an undecryptable seed = %v; want ErrMFARegenerateInvalidCode", err)
	}
}

// TestMFAEnrollment_DisableSelfWithProof_TOTPLegIsTheSharedHelper: the
// disable's TOTP leg still verifies through the one helper — a current
// code disarms with reauth totp, and an undecryptable seed falls through
// to the recovery-code leg exactly as before the extraction.
func TestMFAEnrollment_DisableSelfWithProof_TOTPLegIsTheSharedHelper(t *testing.T) {
	t.Run("current TOTP disarms", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		seed := regenerateSeedForTest(t)
		seedEnrolledOrgUser(userRepo, user, seed, []string{"REC-A"})
		method, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Code: regenerateTOTPForTest(t, svc, seed)})
		if err != nil || method != MFADisableReauthTOTP {
			t.Fatalf("disable with a current TOTP = %q, %v; want totp, nil", method, err)
		}
	})
	t.Run("undecryptable seed falls through to the recovery leg", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		svc.cipher = nil
		seed := regenerateSeedForTest(t)
		seedEnrolledOrgUser(userRepo, user, seed, []string{"REC-A"})
		if _, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Code: regenerateTOTPForTest(t, svc, seed)}); !errors.Is(err, ErrMFADisableInvalidCode) {
			t.Fatalf("disable with a TOTP but no cipher = %v; want ErrMFADisableInvalidCode (the recovery leg refused it)", err)
		}
		method, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Code: "REC-A"})
		if err != nil || method != MFADisableReauthRecoveryCode {
			t.Fatalf("disable with a recovery code and no cipher = %q, %v; want recovery_code, nil", method, err)
		}
	})
}
