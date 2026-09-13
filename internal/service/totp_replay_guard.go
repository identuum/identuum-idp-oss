package service

// totp_replay_guard.go — the single-use decision behind every TOTP proof
// (THE-CODE-THAT-WORKS-TWICE, 2026-09-13).
//
// RFC 6238 verifies a code by matching it inside a skew window, and nothing
// in that match remembers that the code was already accepted: the same
// captured code stayed acceptable for as long as its window lasted — a
// one-time password by name only. This guard is what MFAVerifierService and
// MFAEnrollmentService consult AFTER a code matches: the matched step is
// claimed for the user in the totp_used_steps store, exactly once. A second
// claim of the same (user, step) is a replay and the callers refuse it with
// the SAME sentinel a wrong code gets, so a replay never tells anyone that
// a code was once valid.
//
// FAIL CLOSED. A guard that cannot run is never a pass: a nil guard or a
// store error makes FirstUse answer (false, error), and every caller turns
// that into a refusal — the verifier surfaces ErrMFAReplayStateUnavailable
// (the wire treats it as the same opaque failure as any MFA error), the
// enrollment service's boolean legs answer false. Nothing here can be
// configured off.
//
// BOUNDED. One row per accepted (user, step); a row expires once its step
// can no longer be accepted — the step's own validity window plus one period
// of margin — and the revocation cleanup ticker sweeps it. Expiry can never
// resurrect a code still inside its window, because the row outlives the
// window by construction.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// ErrMFAReplayStateUnavailable is returned by the verifier when the
// single-use store cannot be consulted (nil guard, store error). The code
// is REFUSED; the wire layer maps it like every other MFA failure — an
// opaque refusal, never a distinct signal.
var ErrMFAReplayStateUnavailable = errors.New("service: mfa replay state unavailable")

// TOTPReplayGuardOptions carries the step geometry the guard needs to size
// a row's lifetime. Zero values fall back to the RFC 6238 §5.2 defaults the
// verifier uses (period 30 s, window ±1).
type TOTPReplayGuardOptions struct {
	Period uint64 // step interval in seconds. Default 30.
	Window int    // accepted ± steps. Default 1.
}

// TOTPReplayGuard claims matched TOTP steps once per user.
type TOTPReplayGuard struct {
	repo   repository.TOTPUsedStepRepository
	period uint64
	window int
	now    func() time.Time
}

// NewTOTPReplayGuard wires the guard (P-018: a nil store is a recorded
// startup fault, never a panic — and the guard then fails closed).
func NewTOTPReplayGuard(report *lifecycle.StartupReport, repo repository.TOTPUsedStepRepository, opts TOTPReplayGuardOptions) *TOTPReplayGuard {
	if repo == nil {
		report.Fatal("NewTOTPReplayGuard", "service: NewTOTPReplayGuard requires a non-nil TOTPUsedStepRepository")
	}
	period := opts.Period
	if period == 0 {
		period = defaultTOTPPeriod
	}
	window := opts.Window
	if window <= 0 {
		window = defaultTOTPWindow
	}
	return &TOTPReplayGuard{repo: repo, period: period, window: window, now: time.Now}
}

// FirstUse claims (userID, step). It answers (true, nil) exactly once per
// pair; (false, nil) for a replay; (false, err) when the store cannot be
// consulted — including a nil guard — which every caller treats as a
// refusal.
func (g *TOTPReplayGuard) FirstUse(ctx context.Context, userID uuid.UUID, step int64) (bool, error) {
	if g == nil || g.repo == nil {
		return false, fmt.Errorf("%w: no store", ErrMFAReplayStateUnavailable)
	}
	if userID == uuid.Nil || step < 0 {
		return false, fmt.Errorf("%w: invalid claim", ErrMFAReplayStateUnavailable)
	}
	first, err := g.repo.Claim(ctx, userID, step, g.expiresAt(step))
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrMFAReplayStateUnavailable, err)
	}
	return first, nil
}

// expiresAt is the instant after which the step can no longer be accepted
// by a verifier with this geometry — the end of the last period in which
// the step is still inside the window — plus one period of margin.
func (g *TOTPReplayGuard) expiresAt(step int64) time.Time {
	lastAccepting := (step + int64(g.window) + 1) * int64(g.period)
	return time.Unix(lastAccepting, 0).UTC().Add(time.Duration(g.period) * time.Second)
}

// DeleteExpired prunes rows past their expiry (ExpiredRowSweeper).
func (g *TOTPReplayGuard) DeleteExpired(ctx context.Context) (int64, error) {
	if g == nil || g.repo == nil {
		return 0, ErrMFAReplayStateUnavailable
	}
	return g.repo.DeleteExpiredBefore(ctx, g.now().UTC())
}
