package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A six-digit code over a ±1-step window is guessable at wire speed if nothing
// counts the misses. The routes that prove an authenticated caller holds the
// second factor — step-up, self-service MFA disable, recovery-code regenerate,
// and turning "skip consent" on — share one per-user budget of wrong codes:
// past it, even the right code is refused until the window moves on.

func TestTOTPFailureBudget(t *testing.T) {
	clock := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	b := NewTOTPFailureBudget(3, 15*time.Minute, func() time.Time { return clock })
	alice, bob := uuid.New(), uuid.New()

	if b.Exhausted(alice) {
		t.Fatal("a fresh budget is not exhausted")
	}
	b.Record(alice)
	b.Record(alice)
	if b.Exhausted(alice) {
		t.Error("two misses of three are not yet the bound")
	}
	b.Record(alice)
	if !b.Exhausted(alice) {
		t.Error("three misses reach the bound")
	}
	if b.Exhausted(bob) {
		t.Error("one user's misses must not count against another")
	}
	clock = clock.Add(15*time.Minute + time.Second)
	if b.Exhausted(alice) {
		t.Error("the misses age out of the window")
	}

	var nilBudget *TOTPFailureBudget
	if nilBudget.Exhausted(alice) {
		t.Error("no budget wired means no bound, as before")
	}
	nilBudget.Record(alice) // must not panic
}

func TestMFAVerifierVerify_PastTheBudgetEvenTheRightCodeIsRefused(t *testing.T) {
	ctx := context.Background()
	frozen := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	budget := NewTOTPFailureBudget(3, 15*time.Minute, func() time.Time { return frozen })
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Replay: testReplayGuard(t), Failures: budget})
	svc.now = func() time.Time { return frozen }

	secret := freshTOTPSecret(t)
	user := userWithMFA(secret)
	user.ID = domainUserID(t)
	right, _ := codeAt(t, secret, frozen)
	wrong := wrongCodeUnlike(right)

	for i := 0; i < 3; i++ {
		if err := svc.Verify(ctx, user, wrong); !errors.Is(err, ErrMFAInvalid) {
			t.Fatalf("wrong code %d: err=%v, want ErrMFAInvalid", i, err)
		}
	}
	if err := svc.Verify(ctx, user, right); !errors.Is(err, ErrMFAInvalid) {
		t.Errorf("the right code past the budget: err=%v, want ErrMFAInvalid (the same cause-neutral refusal)", err)
	}

	// Another user is not refused for this one's misses.
	other := userWithMFA(secret)
	other.ID = domainUserID(t)
	if err := svc.Verify(ctx, other, right); err != nil {
		t.Errorf("another user with the right code: %v", err)
	}
}

func TestMFAEnrollment_ProofRoutesShareTheBudget(t *testing.T) {
	ctx := context.Background()
	budget := NewTOTPFailureBudget(3, 15*time.Minute, nil)

	svc, _, userRepo, user := newEnrollSvc(t)
	svc.proofFailures = budget
	seed := regenerateSeedForTest(t)
	seedEnrolledOrgUser(userRepo, user, seed, []string{"REC-A"})
	right := regenerateTOTPForTest(t, svc, seed)

	for i := 0; i < 3; i++ {
		if err := svc.ProveTOTP(ctx, user.ID, "000000"); !errors.Is(err, ErrMFAProofInvalid) {
			t.Fatalf("wrong proof %d: err=%v", i, err)
		}
	}
	if err := svc.ProveTOTP(ctx, user.ID, right); !errors.Is(err, ErrMFAProofInvalid) {
		t.Errorf("ProveTOTP with the right code past the budget: err=%v, want ErrMFAProofInvalid", err)
	}
	if _, err := svc.RegenerateRecoveryCodes(ctx, user.ID, right); !errors.Is(err, ErrMFARegenerateInvalidCode) {
		t.Errorf("regenerate with the right code past the SHARED budget: err=%v, want ErrMFARegenerateInvalidCode", err)
	}
	if _, err := svc.DisableSelfWithProof(ctx, user.ID, MFADisableSelfInput{Code: right}); !errors.Is(err, ErrMFADisableInvalidCode) {
		t.Errorf("disable with the right code past the SHARED budget: err=%v, want ErrMFADisableInvalidCode", err)
	}
}
