package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-MFA-BUDGET-1 (P-103, "one shared allowance"): every second-factor code
// check of a user spends one allowance of 5 wrong codes in 15 minutes: the
// pending sign-in step (VerifyAndConsume) and the proof routes (step-up
// through the verifier, ProveTOTP, regenerate, disable) alike. Until this
// slice they were two budgets, 5 + 5.

type sharedBudgetRig struct {
	enroll   *MFAEnrollmentService
	verifier *MFAVerifierService
	budget   *TOTPFailureBudget
	store    *memProofFailures
	pending  *stubPendingRepo
	user     *domain.User
	seed     string
	clock    *time.Time
}

func newSharedBudgetRig(t *testing.T) *sharedBudgetRig {
	t.Helper()
	svc, pending, userRepo, user := newEnrollSvc(t)
	seed := regenerateSeedForTest(t)
	seedEnrolledOrgUser(userRepo, user, seed, []string{"REC-A"})
	clock := svc.now()
	now := func() time.Time { return clock }
	r := &sharedBudgetRig{enroll: svc, pending: pending, user: user, seed: seed, clock: &clock,
		store: &memProofFailures{rows: map[uuid.UUID][]time.Time{}}}
	r.budget = NewTOTPFailureBudget(DefaultTOTPFailureBudgetMax, DefaultTOTPFailureBudgetWindow, now).WithStore(r.store).WithSignInFailures(pending)
	svc.now, svc.proofFailures = now, r.budget
	r.verifier = NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Replay: testReplayGuard(t), Failures: r.budget})
	r.verifier.now = now
	return r
}

func (r *sharedBudgetRig) right(t *testing.T) string {
	t.Helper()
	code, _ := codeAt(t, r.seed, *r.clock)
	return code
}

func (r *sharedBudgetRig) wrong(t *testing.T) string {
	t.Helper()
	return wrongCodeForWindow(t, r.seed, *r.clock)
}

// signIn runs one pending sign-in code check on a fresh handle.
func (r *sharedBudgetRig) signIn(t *testing.T, ctx context.Context, code string) error {
	t.Helper()
	row, err := r.enroll.CreatePending(ctx, r.user, domain.MFAPendingKindVerify, false)
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}
	_, err = r.enroll.VerifyAndConsume(ctx, row.ID, code)
	return err
}

func throttled(err error) bool {
	var th *LoginThrottledError
	return errors.As(err, &th) && th.RetryAfter > 0
}

// Proof 1: five proof-route misses, then the right sign-in code gets the
// sign-in wait.
func TestSharedBudget_ProofMissesRefuseTheSignInCode(t *testing.T) {
	ctx := context.Background()
	r := newSharedBudgetRig(t)
	for i := 0; i < 5; i++ {
		if err := r.enroll.ProveTOTP(ctx, r.user.ID, r.wrong(t)); !errors.Is(err, ErrMFAProofInvalid) {
			t.Fatalf("proof miss %d: %v", i+1, err)
		}
	}
	if err := r.signIn(t, ctx, r.right(t)); !throttled(err) {
		t.Fatalf("the right sign-in code after 5 proof misses: %v; want the sign-in wait", err)
	}
}

// Proof 2: five sign-in misses, then the right step-up code is refused.
func TestSharedBudget_SignInMissesRefuseTheStepUpCode(t *testing.T) {
	ctx := context.Background()
	r := newSharedBudgetRig(t)
	for i := 0; i < 5; i++ {
		if err := r.signIn(t, ctx, r.wrong(t)); !errors.Is(err, ErrMFAEnrollmentInvalid) {
			t.Fatalf("sign-in miss %d: %v", i+1, err)
		}
	}
	if err := r.verifier.Verify(ctx, r.user, r.right(t)); err == nil {
		t.Fatal("the right step-up code after 5 sign-in misses was accepted")
	}
}

// Proof 3: three proof misses and two sign-in misses reach the bound on both
// families; proof 5: after the window the right codes work again.
func TestSharedBudget_MixedMissesReachTheBoundAndAgeOut(t *testing.T) {
	ctx := context.Background()
	r := newSharedBudgetRig(t)
	for i := 0; i < 3; i++ {
		if err := r.verifier.Verify(ctx, r.user, r.wrong(t)); !errors.Is(err, ErrMFAInvalid) {
			t.Fatalf("step-up miss %d: %v", i+1, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := r.signIn(t, ctx, r.wrong(t)); !errors.Is(err, ErrMFAEnrollmentInvalid) {
			t.Fatalf("sign-in miss %d: %v", i+1, err)
		}
	}
	if err := r.signIn(t, ctx, r.right(t)); !throttled(err) {
		t.Errorf("sign-in at 3 + 2: %v; want the sign-in wait", err)
	}
	if err := r.verifier.Verify(ctx, r.user, r.right(t)); err == nil {
		t.Error("step-up at 3 + 2 accepted the right code")
	}
	if err := r.enroll.ProveTOTP(ctx, r.user.ID, r.right(t)); err == nil {
		t.Error("a proof route at 3 + 2 accepted the right code")
	}

	*r.clock = r.clock.Add(DefaultTOTPFailureBudgetWindow + time.Minute)
	if err := r.signIn(t, ctx, r.right(t)); err != nil {
		t.Errorf("sign-in after the window: %v", err)
	}
	*r.clock = r.clock.Add(time.Duration(defaultTOTPPeriod) * time.Second)
	if err := r.verifier.Verify(ctx, r.user, r.right(t)); err != nil {
		t.Errorf("step-up after the window: %v", err)
	}
}

// rendezvous holds each family after its last count before its code check
// (its second count: the sign-in step counts its rows, then the proof misses;
// a proof route counts the proof misses, then the sign-in rows) until the
// other family has finished its own, or briefly. Two checks that do not share
// the user's turn therefore both finish counting before either records a miss;
// checks that share it never meet, and the first waits out the short timeout
// alone.
type rendezvous struct {
	mu    sync.Mutex
	calls map[string]int
	done  map[string]chan struct{}
}

type familyKey struct{}

func (z *rendezvous) ready(family string) chan struct{} {
	if z.done[family] == nil {
		z.done[family] = make(chan struct{})
	}
	return z.done[family]
}

func (z *rendezvous) arrive(ctx context.Context) {
	me, _ := ctx.Value(familyKey{}).(string)
	if me == "" {
		return
	}
	other := map[string]string{"signin": "proof", "proof": "signin"}[me]
	z.mu.Lock()
	z.calls[me]++
	if z.calls[me] != 2 {
		z.mu.Unlock()
		return
	}
	close(z.ready(me))
	wait := z.ready(other)
	z.mu.Unlock()
	select {
	case <-wait:
	case <-time.After(300 * time.Millisecond):
	}
}

type rendezvousPending struct {
	*stubPendingRepo
	z *rendezvous
}

func (p rendezvousPending) CountRecentFailedVerifyAttempts(ctx context.Context, user uuid.UUID, since time.Time) (int, time.Time, error) {
	n, oldest, err := p.stubPendingRepo.CountRecentFailedVerifyAttempts(ctx, user, since)
	p.z.arrive(ctx)
	return n, oldest, err
}

type rendezvousProof struct {
	*memProofFailures
	z *rendezvous
}

func (p rendezvousProof) CountProofFailuresSince(ctx context.Context, user uuid.UUID, since time.Time) (int, time.Time, error) {
	n, oldest, err := p.memProofFailures.CountProofFailuresSince(ctx, user, since)
	p.z.arrive(ctx)
	return n, oldest, err
}

// Proof 4: at 4 misses, a wrong sign-in code and a wrong step-up code in
// parallel: only one of them is checked, so the user holds exactly 5 misses.
func TestSharedBudget_ParallelGuessesAcrossFamiliesAreCountedOneByOne(t *testing.T) {
	ctx := context.Background()
	r := newSharedBudgetRig(t)
	for i := 0; i < 2; i++ {
		_ = r.verifier.Verify(ctx, r.user, r.wrong(t))
		_ = r.signIn(t, ctx, r.wrong(t))
	}
	z := &rendezvous{calls: map[string]int{}, done: map[string]chan struct{}{}}
	r.enroll.pending = rendezvousPending{stubPendingRepo: r.pending, z: z}
	r.budget.store = rendezvousProof{memProofFailures: r.store, z: z}
	r.budget.signIn = rendezvousPending{stubPendingRepo: r.pending, z: z}
	row, err := r.enroll.CreatePending(ctx, r.user, domain.MFAPendingKindVerify, false)
	if err != nil {
		t.Fatal(err)
	}
	wrong := r.wrong(t)
	var wg sync.WaitGroup
	var signInErr, proofErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, signInErr = r.enroll.VerifyAndConsume(context.WithValue(ctx, familyKey{}, "signin"), row.ID, wrong)
	}()
	go func() {
		defer wg.Done()
		proofErr = r.verifier.Verify(context.WithValue(ctx, familyKey{}, "proof"), r.user, wrong)
	}()
	wg.Wait()
	signIn, _, _ := r.pending.CountRecentFailedVerifyAttempts(ctx, r.user.ID, r.clock.Add(-time.Hour))
	proof := len(r.store.rows[r.user.ID])
	if signIn+proof != 5 {
		t.Fatalf("misses after two parallel wrong codes at 4: %d sign-in + %d proof; want exactly 5", signIn, proof)
	}
	// One check ran and missed; the other met the bound without being looked at.
	if (signInErr == nil) || (proofErr == nil) || (!throttled(signInErr) && !throttled(proofErr)) {
		t.Fatalf("sign-in: %v; step-up: %v; want both refused, one of them with the wait", signInErr, proofErr)
	}
}
