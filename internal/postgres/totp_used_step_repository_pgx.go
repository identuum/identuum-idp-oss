package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxTOTPUsedStepRepository is the pgx implementation of
// repository.TOTPUsedStepRepository over totp_used_steps (migration 0040).
type PgxTOTPUsedStepRepository struct {
	db DBTX
}

var _ repository.TOTPUsedStepRepository = (*PgxTOTPUsedStepRepository)(nil)

// NewPgxTOTPUsedStepRepository constructs the repository.
func NewPgxTOTPUsedStepRepository(db DBTX) *PgxTOTPUsedStepRepository {
	return &PgxTOTPUsedStepRepository{db: db}
}

// Claim implements the repository contract: an INSERT … ON CONFLICT DO
// NOTHING whose affected-row count is the single-use verdict. Two
// concurrent presentations of the same code race on the primary key and
// exactly one of them creates the row.
func (r *PgxTOTPUsedStepRepository) Claim(ctx context.Context, userID uuid.UUID, step int64, expiresAt time.Time) (bool, error) {
	if userID == uuid.Nil {
		return false, errors.New("postgres: TOTPUsedStep.Claim requires a non-nil user id")
	}
	if step < 0 {
		return false, errors.New("postgres: TOTPUsedStep.Claim requires a non-negative step")
	}
	if expiresAt.IsZero() {
		return false, errors.New("postgres: TOTPUsedStep.Claim requires non-zero expires_at")
	}
	const q = `
		INSERT INTO totp_used_steps (user_id, step, expires_at, created_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (user_id, step) DO NOTHING`
	tag, err := r.db.Exec(ctx, q, userID, step, expiresAt)
	if err != nil {
		return false, fmt.Errorf("postgres: insert totp_used_steps: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteExpiredBefore implements the repository contract.
func (r *PgxTOTPUsedStepRepository) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := r.db.Exec(ctx, `DELETE FROM totp_used_steps WHERE expires_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired totp_used_steps: %w", err)
	}
	return tag.RowsAffected(), nil
}
