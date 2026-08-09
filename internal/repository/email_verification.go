package repository

import (
	"context"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// EmailVerificationRepository defines storage for single-use email
// verification tokens. The interface mirrors the password-reset surface
// (Create / GetByTokenHash / MarkAsUsed / DeleteExpired) so the two
// account-lifecycle token flows read the same way.
type EmailVerificationRepository interface {
	// Create persists a new verification row. TokenHash is the PK;
	// re-inserting a hash a second time MUST return an error (the
	// SHA-256 collision space is large enough that a real collision
	// indicates either a programming bug or an attacker probing the
	// uniqueness invariant).
	Create(ctx context.Context, ev *domain.EmailVerification) error

	// GetByTokenHash looks up a row by its hash. Returns (nil, nil)
	// when no row exists — the service layer collapses this onto the
	// opaque "invalid token" response so the wire cannot disambiguate.
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.EmailVerification, error)

	// MarkAsUsed atomically sets used_at = NOW() on the row identified
	// by tokenHash. Idempotent — calling it on a row that was already
	// marked is not an error.
	MarkAsUsed(ctx context.Context, tokenHash string) error

	// DeleteExpired removes rows whose expires_at is in the past.
	// Maintenance only — the service layer's IsValid check is the
	// authoritative gate, so an unswept stale row cannot be replayed.
	// Returns the affected-row count; only rows past their expiry are
	// deleted, on the DB clock. A live row is never removed.
	DeleteExpired(ctx context.Context) (int64, error)
}
