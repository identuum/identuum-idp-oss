package service

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/logger"
)

// Defaults for the per-user wrong-code budget the TOTP proof routes share: 5
// misses in 15 minutes, the password-login lockout's own numbers.
const (
	DefaultTOTPFailureBudgetMax    = 5
	DefaultTOTPFailureBudgetWindow = 15 * time.Minute
)

// ProofFailureStore keeps the budget's misses in the database
// (mfa_proof_failures), so a restart does not reset them and every replica
// counts the same ones.
type ProofFailureStore interface {
	RecordProofFailure(ctx context.Context, user uuid.UUID, at time.Time) error
	CountProofFailuresSince(ctx context.Context, user uuid.UUID, since time.Time) (int, error)
	DeleteProofFailuresBefore(ctx context.Context, cutoff time.Time) (int64, error)
}

// TOTPFailureBudget counts the wrong TOTP codes one USER presents across the
// routes that prove an authenticated caller holds the second factor: step-up,
// self-service MFA disable, recovery-code regenerate, and turning "skip
// consent" on. A six-digit code over a ±1-step window is guessable at wire
// speed if nothing counts the misses, and a per-route request limiter counts
// the right codes too. Past the bound even the right code is refused, with the
// same cause-neutral answer as a wrong one, until the misses age out of the
// sliding window.
//
// With a store (WithStore) the misses live in the database: a restart keeps
// them and replicas share them, and a store that cannot answer refuses the
// proof. Without one they live in process memory. A nil *TOTPFailureBudget is
// a no-op, so a composition that wires none is exactly as it was.
type TOTPFailureBudget struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	now    func() time.Time
	misses map[uuid.UUID][]time.Time
	turns  keyedMutex
	store  ProofFailureStore
}

// Hold gives one user's proof attempt its turn: the caller holds it across
// Exhausted, the code check and Record, so parallel wrong codes cannot all pass
// the check before any is counted. Another user never waits on it. A nil
// budget holds nothing. The turn is per process; the instance lease keeps one
// serving replica per database.
func (b *TOTPFailureBudget) Hold(user uuid.UUID) (release func()) {
	if b == nil {
		return func() {}
	}
	return b.turns.lock(user.String())
}

// NewTOTPFailureBudget returns a budget of max misses per user within window.
// A non-positive max or window takes the default; a nil clock is time.Now.
func NewTOTPFailureBudget(max int, window time.Duration, now func() time.Time) *TOTPFailureBudget {
	if max <= 0 {
		max = DefaultTOTPFailureBudgetMax
	}
	if window <= 0 {
		window = DefaultTOTPFailureBudgetWindow
	}
	if now == nil {
		now = time.Now
	}
	return &TOTPFailureBudget{max: max, window: window, now: now, misses: map[uuid.UUID][]time.Time{}}
}

// WithStore keeps the misses in store instead of process memory.
func (b *TOTPFailureBudget) WithStore(store ProofFailureStore) *TOTPFailureBudget {
	if b == nil {
		return nil
	}
	b.store = store
	return b
}

// prune drops the user's misses that have left the window; callers hold b.mu.
func (b *TOTPFailureBudget) prune(user uuid.UUID) []time.Time {
	cutoff := b.now().Add(-b.window)
	kept := b.misses[user][:0]
	for _, at := range b.misses[user] {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(b.misses, user)
		return nil
	}
	b.misses[user] = kept
	return kept
}

// Exhausted reports whether the user has used up the budget. A store that
// cannot be read reports true: the proof is refused rather than unbounded.
func (b *TOTPFailureBudget) Exhausted(ctx context.Context, user uuid.UUID) bool {
	if b == nil {
		return false
	}
	if b.store != nil {
		n, err := b.store.CountProofFailuresSince(ctx, user, b.now().Add(-b.window))
		if err != nil {
			logger.ErrorContext(ctx, "totp proof budget: store unavailable; refusing the proof", zap.Error(err))
			return true
		}
		return n >= b.max
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.prune(user)) >= b.max
}

// Record counts one wrong code for the user.
func (b *TOTPFailureBudget) Record(ctx context.Context, user uuid.UUID) {
	if b == nil {
		return
	}
	if b.store != nil {
		if err := b.store.RecordProofFailure(ctx, user, b.now()); err != nil {
			logger.ErrorContext(ctx, "totp proof budget: a wrong code was not recorded", zap.Error(err))
		}
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.prune(user)
	b.misses[user] = append(b.misses[user], b.now())
}

// DeleteExpired drops the stored misses that have left the window, for the
// cleanup sweep. Without a store there is nothing to drop.
func (b *TOTPFailureBudget) DeleteExpired(ctx context.Context) (int64, error) {
	if b == nil || b.store == nil {
		return 0, nil
	}
	return b.store.DeleteProofFailuresBefore(ctx, b.now().Add(-b.window))
}
