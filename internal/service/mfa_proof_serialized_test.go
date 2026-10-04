package service

import (
	"context"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// The per-user wrong-code bounds are read, the code checked, and a miss
// recorded as three steps. Unless one user's attempts take turns, parallel
// guesses all read the count before any is recorded and each gets through: the
// bound of 5 becomes 5 per request in flight. Each proof path therefore holds
// the user's turn across the three steps; another user is never kept waiting.

// returnsWhileHeld reports whether call returns while hold is held, and that it
// returns once hold is released.
func returnsWhileHeld(t *testing.T, release func(), call func()) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		call()
		close(done)
	}()
	select {
	case <-done:
		release()
		return true
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the call did not return after the user's turn was released")
	}
	return false
}

func TestMFAVerifierVerify_OneUsersAttemptsTakeTurns(t *testing.T) {
	ctx := context.Background()
	budget := NewTOTPFailureBudget(3, 15*time.Minute, nil)
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Replay: testReplayGuard(t), Failures: budget})
	secret := freshTOTPSecret(t)
	user := userWithMFA(secret)
	user.ID = domainUserID(t)
	other := userWithMFA(secret)
	other.ID = domainUserID(t)

	if returnsWhileHeld(t, budget.Hold(user.ID), func() { _ = svc.Verify(ctx, user, "000000") }) {
		t.Error("a verify ran while another attempt of the same user held its turn")
	}
	if !returnsWhileHeld(t, budget.Hold(user.ID), func() { _ = svc.Verify(ctx, other, "000000") }) {
		t.Error("another user's verify waited on this user's turn")
	}
}

func TestMFAEnrollment_ProofOneUsersAttemptsTakeTurns(t *testing.T) {
	ctx := context.Background()
	budget := NewTOTPFailureBudget(3, 15*time.Minute, nil)
	svc, _, userRepo, user := newEnrollSvc(t)
	svc.proofFailures = budget
	seedEnrolledOrgUser(userRepo, user, regenerateSeedForTest(t), []string{"REC-A"})

	if returnsWhileHeld(t, budget.Hold(user.ID), func() { _ = svc.ProveTOTP(ctx, user.ID, "000000") }) {
		t.Error("a TOTP proof ran while another attempt of the same user held its turn")
	}
}

func TestMFAEnrollment_VerifyAndConsume_OneUsersAttemptsTakeTurns(t *testing.T) {
	ctx := context.Background()
	svc, _, userRepo, user := newEnrollSvc(t)
	secret, _ := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	userRepo.byID[user.ID].MFAEnabled = true
	userRepo.byID[user.ID].MFASecret = &secret
	row, err := svc.CreatePending(ctx, userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)
	if err != nil {
		t.Fatal(err)
	}
	if returnsWhileHeld(t, svc.verifyTurns.lock(user.ID.String()), func() { _, _ = svc.VerifyAndConsume(ctx, row.ID, "000000") }) {
		t.Error("a pending sign-in's verify ran while another attempt of the same user held its turn")
	}
}
