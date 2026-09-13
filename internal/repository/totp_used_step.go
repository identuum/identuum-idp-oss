package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TOTPUsedStepRepository is the single-use store behind every TOTP proof
// (THE-CODE-THAT-WORKS-TWICE, 2026-09-13): the (user, step) a code matched
// is claimed here exactly once, so the same code cannot be accepted twice
// inside its skew window. Mirrors DPoPProofReplayRepository (migration 0038)
// in shape and contract: the store answers first-use, never a verdict about
// availability — an error is a store failure the caller must fail CLOSED on.
type TOTPUsedStepRepository interface {
	// Claim records (userID, step). firstUse is true when THIS call created
	// the row and false when it already existed (a replay). Any error is a
	// store failure — the caller refuses the code, never admits it.
	Claim(ctx context.Context, userID uuid.UUID, step int64, expiresAt time.Time) (firstUse bool, err error)

	// DeleteExpiredBefore prunes rows whose expires_at < cutoff.
	DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
