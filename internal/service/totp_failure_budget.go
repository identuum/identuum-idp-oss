package service

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Defaults for the per-user wrong-code budget the TOTP proof routes share: 5
// misses in 15 minutes, the password-login lockout's own numbers.
const (
	DefaultTOTPFailureBudgetMax    = 5
	DefaultTOTPFailureBudgetWindow = 15 * time.Minute
)

// TOTPFailureBudget counts the wrong TOTP codes one USER presents across the
// routes that prove an authenticated caller holds the second factor: step-up,
// self-service MFA disable, recovery-code regenerate, and turning "skip
// consent" on. A six-digit code over a ±1-step window is guessable at wire
// speed if nothing counts the misses, and a per-route request limiter counts
// the right codes too. Past the bound even the right code is refused, with the
// same cause-neutral answer as a wrong one, until the misses age out of the
// sliding window.
//
// The count lives in process memory: the instance lease keeps one replica per
// database, and a restart is not something a caller holding only a session can
// cause. A nil *TOTPFailureBudget is a no-op, so a composition that wires none
// is exactly as it was.
type TOTPFailureBudget struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	now    func() time.Time
	misses map[uuid.UUID][]time.Time
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

// Exhausted reports whether the user has used up the budget.
func (b *TOTPFailureBudget) Exhausted(user uuid.UUID) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.prune(user)) >= b.max
}

// Record counts one wrong code for the user.
func (b *TOTPFailureBudget) Record(user uuid.UUID) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.prune(user)
	b.misses[user] = append(b.misses[user], b.now())
}
