package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// PasswordResetRepository defines the interface for password reset token storage
type PasswordResetRepository interface {
	// Create stores a new password reset token
	Create(ctx context.Context, reset *domain.PasswordReset) error

	// GetByTokenHash retrieves a password reset request by token hash
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.PasswordReset, error)

	// MarkAsUsed marks a token as used to prevent replay attacks
	MarkAsUsed(ctx context.Context, tokenHash string) error

	// ClaimPasswordReset atomically claims the token (single-use) AND writes
	// the new password hash in ONE transaction (P0-9): a concurrent loser gets
	// ok=false, and a failed password write rolls the claim back so a valid
	// link survives. The caller MUST fully validate the password policy first;
	// newPasswordHash MUST be a pre-computed argon2id hash.
	ClaimPasswordReset(ctx context.Context, tokenHash, newPasswordHash string) (uuid.UUID, bool, error)

	// DeleteExpired cleans up expired tokens (maintenance sweep) and
	// returns the affected-row count. Only rows past their expiry are
	// deleted, on the DB clock; a live token is never removed.
	DeleteExpired(ctx context.Context) (int64, error)
}
