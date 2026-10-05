package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// FUNC-M3 (audits/oss-functionality-2026-10-05.md): while the per-user
// wrong-code bound was spent, a CORRECT code was answered 401 invalid_code, so
// the person retyped good codes into a wall with no hint to wait. The bound
// stays exactly as strong and still refuses every code without looking at it
// (no oracle); the answer is now the sign-in wait, 429 login_throttled with
// Retry-After, until the oldest counted miss leaves the window.

func TestVerifyAndConsume_ASpentBoundSaysToWait(t *testing.T) {
	ctx := context.Background()
	svc, pendingRepo, userRepo, user := newEnrollSvc(t)
	frozen := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return frozen }
	svc.maxVerifyAttempts = 5
	svc.maxUserFailures = 5
	secret, _ := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	userRepo.byID[user.ID].MFAEnabled = true
	userRepo.byID[user.ID].MFASecret = &secret
	u := userRepo.byID[user.ID]

	first, _ := svc.CreatePending(ctx, u, domain.MFAPendingKindVerify, false)
	pendingRepo.rows[first.ID].CreatedAt = frozen // the stub stamps the wall clock
	for i := 0; i < 5; i++ {
		_, _ = svc.VerifyAndConsume(ctx, first.ID, wrongCodeForWindow(t, secret, frozen))
	}
	svc.now = func() time.Time { return frozen.Add(time.Minute) }
	right, _ := computeHOTP(secret, uint64(frozen.Add(time.Minute).Unix())/defaultTOTPPeriod, defaultTOTPDigits)
	for name, code := range map[string]string{"right": right, "wrong": wrongCodeForWindow(t, secret, frozen.Add(time.Minute))} {
		row, _ := svc.CreatePending(ctx, u, domain.MFAPendingKindVerify, false)
		_, err := svc.VerifyAndConsume(ctx, row.ID, code)
		var throttled *LoginThrottledError
		if !errors.As(err, &throttled) || !errors.Is(err, ErrLoginThrottled) {
			t.Fatalf("%s code at the spent bound: err = %v; want a LoginThrottledError (429)", name, err)
		}
		if throttled.RetryAfter != 14*time.Minute {
			t.Errorf("%s code: RetryAfter = %v; want 14m (the first handle's misses leave the window)", name, throttled.RetryAfter)
		}
		if pendingRepo.rows[row.ID].ConsumedAt != nil || pendingRepo.rows[row.ID].FailedAttempts != 0 {
			t.Errorf("%s code: a refusal at the spent bound consumed or counted the handle", name)
		}
	}
}

func TestMFAVerifierVerify_ASpentBudgetSaysToWait(t *testing.T) {
	ctx := context.Background()
	frozen := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	budget := NewTOTPFailureBudget(3, 15*time.Minute, func() time.Time { return frozen })
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Replay: testReplayGuard(t), Failures: budget})
	svc.now = func() time.Time { return frozen }
	secret := freshTOTPSecret(t)
	user := userWithMFA(secret)
	user.ID = domainUserID(t)
	right, _ := codeAt(t, secret, frozen)
	for i := 0; i < 3; i++ {
		_ = svc.Verify(ctx, user, wrongCodeUnlike(right))
	}
	budget.now = func() time.Time { return frozen.Add(2 * time.Minute) }
	svc.now = func() time.Time { return frozen.Add(2 * time.Minute) }
	right, _ = codeAt(t, secret, frozen.Add(2*time.Minute))
	err := svc.Verify(ctx, user, right)
	var throttled *LoginThrottledError
	if !errors.As(err, &throttled) {
		t.Fatalf("the right code past the budget: err = %v; want a LoginThrottledError (429)", err)
	}
	if throttled.RetryAfter != 13*time.Minute {
		t.Errorf("RetryAfter = %v; want 13m", throttled.RetryAfter)
	}
}
