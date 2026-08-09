package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// BrowserSessionTokenRepository persists browser cookie indirection
// rows. The wire cookie value is NEVER stored — only its SHA-256
// hex digest lands in token_hash.
type BrowserSessionTokenRepository interface {
	// Insert persists a fresh row.
	Insert(ctx context.Context, t *domain.BrowserSessionToken) error

	// GetByTokenHash returns the row whose token_hash matches AND
	// which is currently active (revoked_at IS NULL AND expires_at
	// > now). Returns (nil, nil) on no-match — DO NOT distinguish
	// "not found" from "revoked".
	GetByTokenHash(ctx context.Context, tokenHash string, now time.Time) (*domain.BrowserSessionToken, error)

	// RevokeByTokenHash flips revoked_at on the matching row.
	// Idempotent — a no-op when the row is absent or already
	// revoked.
	RevokeByTokenHash(ctx context.Context, tokenHash string, at time.Time) error

	// RevokeBySessionID flips revoked_at on every row bound to
	// sessionID. Used on session-wide revocation paths.
	RevokeBySessionID(ctx context.Context, sessionID uuid.UUID, at time.Time) error

	// DeleteExpiredBefore prunes rows where expires_at < cutoff.
	DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
