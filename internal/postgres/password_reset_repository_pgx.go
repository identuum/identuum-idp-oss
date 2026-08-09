package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
)

// PgxPasswordResetRepository implements repository.PasswordResetRepository with pgx
type PgxPasswordResetRepository struct {
	db DBTX
}

// NewPgxPasswordResetRepository creates a new instance
func NewPgxPasswordResetRepository(db DBTX) *PgxPasswordResetRepository {
	return &PgxPasswordResetRepository{db: db}
}

var _ repository.PasswordResetRepository = (*PgxPasswordResetRepository)(nil)

// Create stores a new password reset token
func (r *PgxPasswordResetRepository) Create(ctx context.Context, reset *domain.PasswordReset) error {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("password_reset_repo", "create", "all"))
	defer timer.ObserveDuration()

	query := `
		INSERT INTO password_resets (user_id, token_hash, expires_at, used_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := r.db.Exec(ctx, query,
		reset.UserID,
		reset.TokenHash,
		reset.ExpiresAt,
		reset.UsedAt,
		reset.CreatedAt,
	)
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("password_reset_repo", "create", "error").Observe(timer.ObserveDuration().Seconds())
		return fmt.Errorf("failed to create password reset: %w", err)
	}
	metrics.DBQueryDuration.WithLabelValues("password_reset_repo", "create", "success").Observe(timer.ObserveDuration().Seconds())
	return nil
}

// GetByTokenHash retrieves a password reset request by token hash
func (r *PgxPasswordResetRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.PasswordReset, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("password_reset_repo", "get_by_hash", "all"))
	defer timer.ObserveDuration()

	query := `
		SELECT user_id, token_hash, expires_at, used_at, created_at
		FROM password_resets
		WHERE token_hash = $1
	`
	row := r.db.QueryRow(ctx, query, tokenHash)

	reset := &domain.PasswordReset{}

	err := row.Scan(
		&reset.UserID,
		&reset.TokenHash,
		&reset.ExpiresAt,
		&reset.UsedAt,
		&reset.CreatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // Not found
	}
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("password_reset_repo", "get_by_hash", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, fmt.Errorf("failed to get password reset by hash: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("password_reset_repo", "get_by_hash", "success").Observe(timer.ObserveDuration().Seconds())
	return reset, nil
}

// MarkAsUsed marks a token as used
func (r *PgxPasswordResetRepository) MarkAsUsed(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE password_resets
		SET used_at = CURRENT_TIMESTAMP
		WHERE token_hash = $1
	`
	_, err := r.db.Exec(ctx, query, tokenHash)
	if err != nil {
		return fmt.Errorf("failed to mark password reset as used: %w", err)
	}
	return nil
}

// ClaimPasswordReset atomically claims a password-reset token and writes the new
// password hash in ONE transaction (P0-9). It (1) marks the token used ONLY
// while it is still unused AND unexpired — the `used_at IS NULL` guard is the
// atomic single-use claim, so a concurrent reset matches zero rows and is
// rejected — then (2) writes the new password_hash for the token's user in the
// SAME transaction. A failed password write rolls the claim back, so a valid
// reset link is NEVER burned by a failed attempt. The caller MUST have fully
// validated the password policy BEFORE calling this. newPasswordHash MUST be a
// pre-computed argon2id hash. Returns (userID, true, nil) on success and
// (uuid.Nil, false, nil) when the token was not claimable (already used /
// expired / unknown).
func (r *PgxPasswordResetRepository) ClaimPasswordReset(ctx context.Context, tokenHash, newPasswordHash string) (uuid.UUID, bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("failed to begin password-reset transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		UPDATE password_resets
		SET used_at = NOW()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
		RETURNING user_id`, tokenHash).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, false, nil // already used / expired / unknown — reject
		}
		return uuid.Nil, false, fmt.Errorf("claim password reset token: %w", err)
	}

	ct, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, userID, newPasswordHash)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("password reset write: %w", err)
	}
	if ct.RowsAffected() != 1 {
		// User vanished/soft-deleted between validation and write: roll back
		// the claim so the (still-valid) link is not burned.
		return uuid.Nil, false, fmt.Errorf("password reset write: user not found or deleted")
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, false, fmt.Errorf("commit password reset transaction: %w", err)
	}
	return userID, true, nil
}

// DeleteExpired cleans up expired tokens
func (r *PgxPasswordResetRepository) DeleteExpired(ctx context.Context) (int64, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("password_reset_repo", "delete_expired", "all"))
	defer timer.ObserveDuration()

	// Delete ONLY rows past their expiry, keyed on the DB clock (NOW())
	// so no host/DB clock skew can drop a still-live token. Mirrors the
	// oidc_states sweeper shape. Single-use consume within the validity
	// window is untouched — a live (unexpired) row is never removed.
	query := `
		DELETE FROM password_resets
		WHERE expires_at < NOW()
	`
	tag, err := r.db.Exec(ctx, query)
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("password_reset_repo", "delete_expired", "error").Observe(timer.ObserveDuration().Seconds())
		return 0, fmt.Errorf("failed to delete expired password resets: %w", err)
	}
	metrics.DBQueryDuration.WithLabelValues("password_reset_repo", "delete_expired", "success").Observe(timer.ObserveDuration().Seconds())
	return tag.RowsAffected(), nil
}
