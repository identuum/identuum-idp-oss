package service

import (
	"context"
	"errors"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// The wrong-code bound is per USER, not only per pending sign-in. Each
// password step mints a fresh handle with a fresh per-handle counter, so a
// person who knows the password could otherwise keep guessing by signing in
// again. A user's recent wrong codes across all of their handles are summed:
// at the bound, even the correct code on a new handle is refused, unlooked at,
// with the sign-in wait (FUNC-M3), and a store error refuses too.
func TestMFAEnrollment_VerifyAndConsume_UserFailuresSpanHandles(t *testing.T) {
	ctx := context.Background()

	setup := func(t *testing.T) (*MFAEnrollmentService, *stubPendingRepo, *domain.User, string) {
		svc, pendingRepo, userRepo, user := newEnrollSvc(t)
		svc.maxVerifyAttempts = 3
		svc.maxUserFailures = 5
		secret, _ := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
		userRepo.byID[user.ID].MFAEnabled = true
		userRepo.byID[user.ID].MFASecret = &secret
		return svc, pendingRepo, userRepo.byID[user.ID], secret
	}
	wrongOn := func(t *testing.T, svc *MFAEnrollmentService, u *domain.User, secret string, n int) {
		t.Helper()
		row, err := svc.CreatePending(ctx, u, domain.MFAPendingKindVerify, false)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			if _, err := svc.VerifyAndConsume(ctx, row.ID, wrongCodeForWindow(t, secret, svc.now())); !errors.Is(err, ErrMFAEnrollmentInvalid) {
				t.Fatalf("a wrong code: err=%v, want ErrMFAEnrollmentInvalid", err)
			}
		}
	}
	correctFor := func(secret string, svc *MFAEnrollmentService) string {
		code, _ := computeHOTP(secret, uint64(svc.now().Unix())/defaultTOTPPeriod, defaultTOTPDigits)
		return code
	}

	t.Run("at the bound a fresh handle with the correct code is refused", func(t *testing.T) {
		svc, pendingRepo, user, secret := setup(t)
		wrongOn(t, svc, user, secret, 3) // first handle dies at 3
		wrongOn(t, svc, user, secret, 2) // second handle: 2 more, 5 in all
		row, _ := svc.CreatePending(ctx, user, domain.MFAPendingKindVerify, false)
		if _, err := svc.VerifyAndConsume(ctx, row.ID, correctFor(secret, svc)); !errors.Is(err, ErrLoginThrottled) {
			t.Errorf("correct code at the per-user bound: err=%v, want ErrLoginThrottled (the wait, FUNC-M3)", err)
		}
		if pendingRepo.rows[row.ID].ConsumedAt != nil {
			t.Error("a refused verification must not consume the handle")
		}
	})

	t.Run("below the bound the correct code on a fresh handle succeeds", func(t *testing.T) {
		svc, _, user, secret := setup(t)
		wrongOn(t, svc, user, secret, 2)
		row, _ := svc.CreatePending(ctx, user, domain.MFAPendingKindVerify, false)
		if _, err := svc.VerifyAndConsume(ctx, row.ID, correctFor(secret, svc)); err != nil {
			t.Errorf("below the per-user bound the correct code must succeed: %v", err)
		}
	})

	t.Run("a failing counter store refuses", func(t *testing.T) {
		svc, pendingRepo, user, secret := setup(t)
		row, _ := svc.CreatePending(ctx, user, domain.MFAPendingKindVerify, false)
		pendingRepo.countErr = errors.New("count store down")
		_, err := svc.VerifyAndConsume(ctx, row.ID, correctFor(secret, svc))
		if err == nil || errors.Is(err, ErrMFAEnrollmentInvalid) {
			t.Errorf("a counter-store error: err=%v, want a non-sentinel error (500)", err)
		}
	})
}
