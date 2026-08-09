package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxEmailVerificationRepository is the pgx-backed implementation of
// repository.EmailVerificationRepository.
type PgxEmailVerificationRepository struct {
	db DBTX
}

// NewPgxEmailVerificationRepository constructs a pgx-backed repo.
func NewPgxEmailVerificationRepository(db DBTX) *PgxEmailVerificationRepository {
	return &PgxEmailVerificationRepository{db: db}
}

var _ repository.EmailVerificationRepository = (*PgxEmailVerificationRepository)(nil)

// Create stores a new verification token row.
func (r *PgxEmailVerificationRepository) Create(ctx context.Context, ev *domain.EmailVerification) error {
	const query = `
		INSERT INTO email_verifications (token_hash, user_id, expires_at, used_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.Exec(ctx, query, ev.TokenHash, ev.UserID, ev.ExpiresAt, ev.UsedAt, ev.CreatedAt)
	if err != nil {
		return fmt.Errorf("email_verifications: insert: %w", err)
	}
	return nil
}

// GetByTokenHash retrieves the row matching the supplied hash. Returns
// (nil, nil) when no row exists.
func (r *PgxEmailVerificationRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.EmailVerification, error) {
	const query = `
		SELECT token_hash, user_id, expires_at, used_at, created_at
		FROM email_verifications
		WHERE token_hash = $1
	`
	row := r.db.QueryRow(ctx, query, tokenHash)
	ev := &domain.EmailVerification{}
	err := row.Scan(&ev.TokenHash, &ev.UserID, &ev.ExpiresAt, &ev.UsedAt, &ev.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("email_verifications: get: %w", err)
	}
	return ev, nil
}

// MarkAsUsed atomically flips used_at on the row identified by tokenHash, and
// reports whether THIS caller is the one that flipped it.
//
// P3-1/P3-2 CLASS, third instance. The word "atomically" was true of the column
// write and false of the guarantee the caller depends on:
// EmailVerificationService.VerifyEmail reads the row, checks row.IsValid (which
// tests used_at), and then calls this — with the comment "Burn-before-write:
// mark the row used BEFORE the email_verified flag is flipped so a parallel
// attempt cannot win the race". With `WHERE token_hash = $1` and the command tag
// discarded, BOTH racers read a valid row, BOTH flipped it, and BOTH proceeded.
// The burn was not a mutex; it was a second write of the same value.
//
// `AND used_at IS NULL` makes the database the arbiter, and a zero-row result
// returns ErrEmailVerificationAlreadyUsed so the loser takes the caller's
// existing invalid-token path.
func (r *PgxEmailVerificationRepository) MarkAsUsed(ctx context.Context, tokenHash string) error {
	const query = `UPDATE email_verifications SET used_at = $2 WHERE token_hash = $1 AND used_at IS NULL`
	tag, err := r.db.Exec(ctx, query, tokenHash, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("email_verifications: mark used: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrEmailVerificationAlreadyUsed
	}
	return nil
}

// DeleteExpired sweeps rows past their TTL.
func (r *PgxEmailVerificationRepository) DeleteExpired(ctx context.Context) (int64, error) {
	// DB clock (NOW()) so no clock skew drops a still-live token; only
	// rows past their expiry are removed (mirrors oidc_states).
	const query = `DELETE FROM email_verifications WHERE expires_at < NOW()`
	tag, err := r.db.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("email_verifications: delete expired: %w", err)
	}
	return tag.RowsAffected(), nil
}
