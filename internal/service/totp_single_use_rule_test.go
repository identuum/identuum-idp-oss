package service

// totp_single_use_rule_test.go — RULE: TOTP-SINGLE-USE-1
// (THE-CODE-THAT-WORKS-TWICE, 2026-09-13).
//
// A TOTP code that has been accepted is not accepted again. Every subtest
// is a way the guard could fail its purpose: a replay admitted on any TOTP
// leg (login verifier, step-up verifier, enrolment complete, pending-login
// verify, recovery-code regenerate, self-disable), a replay refusal that
// looks different from a wrong-code refusal (an oracle), a fresh code
// refused (the guard too wide), a store outage read as a pass (the guard
// open), or a row expiring while its code is still inside its window (the
// guard resurrecting a code). Everything here is hermetic: an in-memory
// store, a pinned clock, no appliance.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// codeAt mints the code for the step containing at, and the step itself.
func codeAt(t *testing.T, secret string, at time.Time) (string, int64) {
	t.Helper()
	counter := uint64(at.Unix()) / uint64(defaultTOTPPeriod)
	code, err := computeHOTP(secret, counter, defaultTOTPDigits)
	if err != nil {
		t.Fatalf("compute code: %v", err)
	}
	return code, int64(counter)
}

// wrongCodeUnlike returns a six-digit code that is not the given one.
func wrongCodeUnlike(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

// RULE: TOTP-SINGLE-USE-1
func TestRuleTOTPSingleUse1_AnAcceptedCodeIsNeverAcceptedAgain(t *testing.T) {
	frozen := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

	t.Run("verifier (login, step-up): the second presentation is REFUSED with the wrong-code sentinel and the wrong-code message", func(t *testing.T) {
		store := newMemTOTPSteps()
		svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Replay: testReplayGuardOver(store)})
		svc.now = func() time.Time { return frozen }
		secret := freshTOTPSecret(t)
		u := userWithMFA(secret)
		u.ID = domainUserID(t)
		code, _ := codeAt(t, secret, frozen)
		if err := svc.Verify(context.Background(), u, code); err != nil {
			t.Fatalf("PREMISE: the first presentation must be accepted: %v", err)
		}
		replay := svc.Verify(context.Background(), u, code)
		if !errors.Is(replay, ErrMFAInvalid) {
			t.Fatalf("the second presentation of an accepted code was not refused as a wrong code: %v", replay)
		}
		wrong := svc.Verify(context.Background(), u, wrongCodeUnlike(code))
		if !errors.Is(wrong, ErrMFAInvalid) || wrong.Error() != replay.Error() {
			t.Fatalf("a replay must be indistinguishable from a wrong code: replay=%q wrong=%q", replay, wrong)
		}
		// The replay was DECIDED BY THE STORE (asked for the first use and
		// again for the replay); the wrong code never reached it.
		if store.claims != 2 {
			t.Fatalf("the store was asked %d times; want 2 — once for the first use, once for the replay, never for a wrong code", store.claims)
		}
	})

	t.Run("verifier: a fresh code still succeeds — the next step, and the previous step never used", func(t *testing.T) {
		svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Replay: testReplayGuard(t)})
		svc.now = func() time.Time { return frozen }
		secret := freshTOTPSecret(t)
		u := userWithMFA(secret)
		u.ID = domainUserID(t)
		current, _ := codeAt(t, secret, frozen)
		if err := svc.Verify(context.Background(), u, current); err != nil {
			t.Fatalf("first use of the current step: %v", err)
		}
		next, _ := codeAt(t, secret, frozen.Add(defaultTOTPPeriod*time.Second))
		if err := svc.Verify(context.Background(), u, next); err != nil {
			t.Fatalf("a fresh code for the next step was refused: %v", err)
		}
		previous, _ := codeAt(t, secret, frozen.Add(-defaultTOTPPeriod*time.Second))
		if err := svc.Verify(context.Background(), u, previous); err != nil {
			t.Fatalf("a never-used code for the previous step, still inside the window, was refused: %v", err)
		}
		if err := svc.Verify(context.Background(), u, previous); !errors.Is(err, ErrMFAInvalid) {
			t.Fatalf("the previous-step code was accepted twice: %v", err)
		}
	})

	t.Run("verifier: a store that cannot be consulted REFUSES, never admits", func(t *testing.T) {
		store := newMemTOTPSteps()
		store.err = errors.New("store down")
		svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Replay: testReplayGuardOver(store)})
		svc.now = func() time.Time { return frozen }
		secret := freshTOTPSecret(t)
		u := userWithMFA(secret)
		u.ID = domainUserID(t)
		code, _ := codeAt(t, secret, frozen)
		err := svc.Verify(context.Background(), u, code)
		if err == nil {
			t.Fatal("a genuine code was ADMITTED while the single-use store was unavailable — the guard must fail closed")
		}
		if !errors.Is(err, ErrMFAReplayStateUnavailable) {
			t.Fatalf("the refusal must say the state was unavailable (for the log, never the wire): %v", err)
		}
		if strings.Contains(err.Error(), code) || strings.Contains(err.Error(), secret) {
			t.Fatalf("the error leaked the code or the secret: %q", err)
		}
		// A nil guard is the same refusal.
		var none *TOTPReplayGuard
		if first, nerr := none.FirstUse(context.Background(), u.ID, 1); first || !errors.Is(nerr, ErrMFAReplayStateUnavailable) {
			t.Fatalf("a nil guard must answer (false, unavailable), got (%v, %v)", first, nerr)
		}
	})

	t.Run("enrolment service: regenerate, self-disable, pending-login verify and enrolment complete each refuse the second presentation as a wrong code", func(t *testing.T) {
		// Regenerate: the same code twice; the second is the wrong-code sentinel.
		svc, _, userRepo, user := newEnrollSvc(t)
		seed := regenerateSeedForTest(t)
		user.MFAEnabled = true
		user.MFASecret = &seed
		userRepo.byID[user.ID] = user
		code := regenerateTOTPForTest(t, svc, seed)
		if _, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID, code); err != nil {
			t.Fatalf("PREMISE: first regenerate must succeed: %v", err)
		}
		replay := func() error { _, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID, code); return err }()
		wrong := func() error {
			_, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID, wrongCodeUnlike(code))
			return err
		}()
		if !errors.Is(replay, ErrMFARegenerateInvalidCode) || replay.Error() != wrong.Error() {
			t.Fatalf("regenerate: replay=%v wrong=%v — must be one indistinguishable refusal", replay, wrong)
		}

		// Self-disable: a fresh service and user (org_user, so policy allows the disable).
		svc2, _, userRepo2, user2 := newEnrollSvc(t)
		seed2 := regenerateSeedForTest(t)
		user2.Role = domain.RoleOrgUser
		user2.MFAEnabled = true
		user2.MFASecret = &seed2
		userRepo2.byID[user2.ID] = user2
		code2 := regenerateTOTPForTest(t, svc2, seed2)
		// Spend the step on a regenerate, then try to disable with the same code.
		if _, err := svc2.RegenerateRecoveryCodes(context.Background(), user2.ID, code2); err != nil {
			t.Fatalf("PREMISE: regenerate must succeed: %v", err)
		}
		_, replayDisable := svc2.DisableSelfWithProof(context.Background(), user2.ID, MFADisableSelfInput{Code: code2})
		_, wrongDisable := svc2.DisableSelfWithProof(context.Background(), user2.ID, MFADisableSelfInput{Code: wrongCodeUnlike(code2)})
		if !errors.Is(replayDisable, ErrMFADisableInvalidCode) || replayDisable.Error() != wrongDisable.Error() {
			t.Fatalf("disable: replay=%v wrong=%v — must be one indistinguishable refusal", replayDisable, wrongDisable)
		}
		if userRepo2.byID[user2.ID].MFAEnabled != true {
			t.Fatal("a replayed code disabled MFA")
		}

		// Pending-login verify: the same code on two verify handles.
		svc3, _, userRepo3, user3 := newEnrollSvc(t)
		seed3 := regenerateSeedForTest(t)
		user3.MFAEnabled = true
		user3.MFASecret = &seed3
		userRepo3.byID[user3.ID] = user3
		code3 := regenerateTOTPForTest(t, svc3, seed3)
		row1, err := svc3.CreatePending(context.Background(), user3, domain.MFAPendingKindVerify, false)
		if err != nil {
			t.Fatalf("CreatePending: %v", err)
		}
		if _, err := svc3.VerifyAndConsume(context.Background(), row1.ID, code3); err != nil {
			t.Fatalf("PREMISE: first login verify must succeed: %v", err)
		}
		row2, _ := svc3.CreatePending(context.Background(), user3, domain.MFAPendingKindVerify, false)
		_, replayVerify := svc3.VerifyAndConsume(context.Background(), row2.ID, code3)
		row3, _ := svc3.CreatePending(context.Background(), user3, domain.MFAPendingKindVerify, false)
		_, wrongVerify := svc3.VerifyAndConsume(context.Background(), row3.ID, wrongCodeUnlike(code3))
		if !errors.Is(replayVerify, ErrMFAEnrollmentInvalid) || replayVerify.Error() != wrongVerify.Error() {
			t.Fatalf("login verify: replay=%v wrong=%v — must be one indistinguishable refusal", replayVerify, wrongVerify)
		}

		// Enrolment complete: the code that completed the enrolment cannot then log the user in.
		svc4, _, userRepo4, user4 := newEnrollSvc(t)
		enroll, err := svc4.CreatePending(context.Background(), user4, domain.MFAPendingKindEnroll, false)
		if err != nil {
			t.Fatalf("CreatePending(enroll): %v", err)
		}
		init, err := svc4.Initiate(context.Background(), enroll.ID)
		if err != nil {
			t.Fatalf("Initiate: %v", err)
		}
		code4 := regenerateTOTPForTest(t, svc4, init.Secret)
		if _, err := svc4.Complete(context.Background(), enroll.ID, code4); err != nil {
			t.Fatalf("PREMISE: enrolment must complete with a fresh code: %v", err)
		}
		enrolled := userRepo4.byID[user4.ID]
		verify, _ := svc4.CreatePending(context.Background(), enrolled, domain.MFAPendingKindVerify, false)
		if _, err := svc4.VerifyAndConsume(context.Background(), verify.ID, code4); !errors.Is(err, ErrMFAEnrollmentInvalid) {
			t.Fatalf("the enrolment code logged the user in a second time: %v", err)
		}
	})

	t.Run("enrolment service: a store that cannot be consulted REFUSES every TOTP leg", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		store := newMemTOTPSteps()
		svc.replay = testReplayGuardOver(store)
		seed := regenerateSeedForTest(t)
		user.MFAEnabled = true
		user.MFASecret = &seed
		userRepo.byID[user.ID] = user
		code := regenerateTOTPForTest(t, svc, seed)
		store.err = errors.New("store down")
		if _, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID, code); !errors.Is(err, ErrMFARegenerateInvalidCode) {
			t.Fatalf("regenerate admitted a code while the store was unavailable: %v", err)
		}
		row, _ := svc.CreatePending(context.Background(), user, domain.MFAPendingKindVerify, false)
		if _, err := svc.VerifyAndConsume(context.Background(), row.ID, code); err == nil {
			t.Fatal("login verify admitted a code while the store was unavailable")
		}
		store.err = nil
		if _, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID, code); err != nil {
			t.Fatalf("PREMISE: the same code is a first use once the store answers again: %v", err)
		}
	})

	t.Run("bounded: a claimed step outlives its own validity window and is swept only after it", func(t *testing.T) {
		store := newMemTOTPSteps()
		g := testReplayGuardOver(store)
		user := domainUserID(t)
		step := frozen.Unix() / defaultTOTPPeriod
		if first, err := g.FirstUse(context.Background(), user, step); err != nil || !first {
			t.Fatalf("first use = (%v, %v)", first, err)
		}
		// The step is accepted by a ±1 verifier until the end of step+1;
		// the row must survive a sweep at that instant and be gone one
		// period later.
		lastAccepting := time.Unix((step+int64(defaultTOTPWindow)+1)*defaultTOTPPeriod, 0).UTC()
		if n, _ := store.DeleteExpiredBefore(context.Background(), lastAccepting); n != 0 || store.rows() != 1 {
			t.Fatalf("a sweep inside the step's validity window removed the row (deleted %d)", n)
		}
		if first, _ := g.FirstUse(context.Background(), user, step); first {
			t.Fatal("the step was resurrected while its code was still valid")
		}
		if n, _ := store.DeleteExpiredBefore(context.Background(), lastAccepting.Add(defaultTOTPPeriod*time.Second+time.Second)); n != 1 || store.rows() != 0 {
			t.Fatalf("the row was not swept once the step could no longer be accepted (deleted %d, rows %d)", n, store.rows())
		}
	})
}

// domainUserID returns a fresh user id for a verifier test's user.
func domainUserID(t *testing.T) uuid.UUID {
	t.Helper()
	return uuid.New()
}
