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
	ctx := context.Background()

	if b.Exhausted(ctx, alice) {
		t.Fatal("a fresh budget is not exhausted")
	}
	b.Record(ctx, alice)
	b.Record(ctx, alice)
	if b.Exhausted(ctx, alice) {
		t.Error("two misses of three are not yet the bound")
	}
	b.Record(ctx, alice)
	if !b.Exhausted(ctx, alice) {
		t.Error("three misses reach the bound")
	}
	if b.Exhausted(ctx, bob) {
		t.Error("one user's misses must not count against another")
	}
	clock = clock.Add(15*time.Minute + time.Second)
	if b.Exhausted(ctx, alice) {
		t.Error("the misses age out of the window")
	}

	var nilBudget *TOTPFailureBudget
	if nilBudget.Exhausted(ctx, alice) {
		t.Error("no budget wired means no bound, as before")
	}
	nilBudget.Record(ctx, alice) // must not panic
}

// The misses are kept in the database when a store is wired, so a restart does
// not reset them and every replica counts the same ones. A store that cannot
// answer refuses (the same cause-neutral answer), and the sweep drops the
// misses that have left the window.

type memProofFailures struct {
	rows map[uuid.UUID][]time.Time
	err  error
}

func (m *memProofFailures) RecordProofFailure(_ context.Context, user uuid.UUID, at time.Time) error {
	if m.err != nil {
		return m.err
	}
	m.rows[user] = append(m.rows[user], at)
	return nil
}

func (m *memProofFailures) CountProofFailuresSince(_ context.Context, user uuid.UUID, since time.Time) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	n := 0
	for _, at := range m.rows[user] {
		if !at.Before(since) {
			n++
		}
	}
	return n, nil
}

func (m *memProofFailures) DeleteProofFailuresBefore(_ context.Context, cutoff time.Time) (int64, error) {
	var gone int64
	for user, ats := range m.rows {
		kept := ats[:0]
		for _, at := range ats {
			if at.Before(cutoff) {
				gone++
				continue
			}
			kept = append(kept, at)
		}
		m.rows[user] = kept
	}
	return gone, nil
}

func TestTOTPFailureBudget_TheStoreKeepsTheMissesAcrossARestart(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	store := &memProofFailures{rows: map[uuid.UUID][]time.Time{}}
	alice := uuid.New()

	before := NewTOTPFailureBudget(3, 15*time.Minute, func() time.Time { return clock }).WithStore(store)
	for i := 0; i < 3; i++ {
		before.Record(ctx, alice)
	}
	after := NewTOTPFailureBudget(3, 15*time.Minute, func() time.Time { return clock }).WithStore(store)
	if !after.Exhausted(ctx, alice) {
		t.Fatal("a new process (the same store) forgot the misses")
	}

	clock = clock.Add(16 * time.Minute)
	if after.Exhausted(ctx, alice) {
		t.Error("the misses age out of the window")
	}
	if gone, err := after.DeleteExpired(ctx); err != nil || gone != 3 {
		t.Errorf("sweep = %d, %v; want the 3 misses past the window dropped", gone, err)
	}
}

func TestTOTPFailureBudget_AStoreThatCannotAnswerRefuses(t *testing.T) {
	b := NewTOTPFailureBudget(3, 15*time.Minute, nil).WithStore(&memProofFailures{rows: map[uuid.UUID][]time.Time{}, err: errors.New("store down")})
	if !b.Exhausted(context.Background(), uuid.New()) {
		t.Error("a store that cannot be read must refuse the proof, not lift the bound")
	}
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
