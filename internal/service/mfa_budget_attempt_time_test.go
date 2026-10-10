package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// F4 (OSS-PRE-RELEASE-REVIEW-2026-10-10, OSS-REVIEW-FIXES-1): the shared
// wrong-code allowance (P-103: five wrong codes in fifteen minutes, every
// second-factor code check of the user) must age a sign-in miss by WHEN IT
// WAS MADE, not by when its handle was created. The pending row keeps one
// counter and no attempt times; until this slice the count summed handles
// CREATED inside the window, so five wrong codes made four minutes into a
// handle's life left the allowance eleven minutes later. The rule now counts
// a handle's misses while the latest moment they can have been made — the
// handle's expiry, or its consumption when that came first — is inside the
// window: never early, and at most the handle's five-minute life late.

// signInMissesOn records n wrong codes against one pending handle at the
// rig's current clock and returns the handle.
func (r *sharedBudgetRig) signInMissesOn(t *testing.T, ctx context.Context, row *domain.MFAPendingLoginSession, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := r.enroll.VerifyAndConsume(ctx, row.ID, r.wrong(t)); !errors.Is(err, ErrMFAEnrollmentInvalid) {
			t.Fatalf("sign-in miss %d on the handle: %v; want ErrMFAEnrollmentInvalid", i+1, err)
		}
	}
}

// blocked asks every family with the right code; an accepted code burns its
// step, so the clock moves one period between the asks.
func (r *sharedBudgetRig) blocked(t *testing.T, ctx context.Context) bool {
	t.Helper()
	step := time.Duration(defaultTOTPPeriod) * time.Second
	signIn := r.signIn(t, ctx, r.right(t))
	*r.clock = r.clock.Add(step)
	stepUp := r.verifier.Verify(ctx, r.user, r.right(t))
	*r.clock = r.clock.Add(step)
	proof := r.enroll.ProveTOTP(ctx, r.user.ID, r.right(t))
	switch {
	case throttled(signIn) && stepUp != nil && proof != nil:
		return true
	case signIn == nil && stepUp == nil && proof == nil:
		return false
	}
	t.Fatalf("the routes disagree: sign-in %v, step-up %v, proof %v", signIn, stepUp, proof)
	return false
}

// The brief's rig: a handle created at t0, five wrong codes at t0+4m (the
// fifth invalidates the handle), still blocked at t0+15m+1s, released once the
// misses are fifteen minutes old; exactly five counted.
func TestSharedBudget_SignInMissesAgeByTheirAttemptTimeNotTheHandleCreation(t *testing.T) {
	ctx := context.Background()
	r := newSharedBudgetRig(t)
	t0 := *r.clock
	row, err := r.enroll.CreatePending(ctx, r.user, domain.MFAPendingKindVerify, false)
	if err != nil {
		t.Fatal(err)
	}
	*r.clock = t0.Add(4 * time.Minute)
	r.signInMissesOn(t, ctx, row, 5)
	if n, _, _ := r.pending.CountRecentFailedVerifyAttempts(ctx, r.user.ID, t0.Add(-time.Hour)); n != 5 {
		t.Fatalf("misses counted = %d; want exactly 5 (one count per attempt)", n)
	}
	if len(r.store.rows[r.user.ID]) != 0 {
		t.Fatalf("proof-route misses = %d; want 0 (a sign-in miss is counted once, on the pending row)", len(r.store.rows[r.user.ID]))
	}

	*r.clock = t0.Add(15*time.Minute + time.Second)
	if !r.blocked(t, ctx) {
		t.Fatal("at t0+15m+1s the five wrong codes made at t0+4m are eleven minutes old, yet the allowance was released")
	}
	*r.clock = t0.Add(19*time.Minute + time.Second)
	if r.blocked(t, ctx) {
		t.Fatal("at t0+19m+1s the misses are over fifteen minutes old, yet the allowance is still spent")
	}
}

// Handles that are never invalidated carry no attempt time at all: their
// misses stay counted until the handle's expiry (the latest moment they can
// have been made) is fifteen minutes old — late by at most the handle's life,
// never early.
func TestSharedBudget_MissesOnLiveHandlesAreNeverReleasedEarly(t *testing.T) {
	ctx := context.Background()
	r := newSharedBudgetRig(t)
	t0 := *r.clock
	a, err := r.enroll.CreatePending(ctx, r.user, domain.MFAPendingKindVerify, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.enroll.CreatePending(ctx, r.user, domain.MFAPendingKindVerify, false)
	if err != nil {
		t.Fatal(err)
	}
	*r.clock = t0.Add(4 * time.Minute)
	r.signInMissesOn(t, ctx, a, 2)
	r.signInMissesOn(t, ctx, b, 3)
	if n, _, _ := r.pending.CountRecentFailedVerifyAttempts(ctx, r.user.ID, t0.Add(-time.Hour)); n != 5 {
		t.Fatalf("misses counted = %d; want exactly 5", n)
	}
	*r.clock = t0.Add(15*time.Minute + time.Second)
	if !r.blocked(t, ctx) {
		t.Fatal("at t0+15m+1s five wrong codes made at t0+4m were released early")
	}
	// The handles expired at t0+5m; their misses age out fifteen minutes later.
	*r.clock = t0.Add(20*time.Minute + time.Second)
	if r.blocked(t, ctx) {
		t.Fatal("at t0+20m+1s every miss is over fifteen minutes old by any reading, yet the allowance is still spent")
	}
}
