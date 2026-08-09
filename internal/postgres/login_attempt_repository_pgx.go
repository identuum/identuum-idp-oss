package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxLoginAttemptRepository implements LoginAttemptRepository.
type PgxLoginAttemptRepository struct {
	db DBTX
}

// NewPgxLoginAttemptRepository constructs the repo.
func NewPgxLoginAttemptRepository(db DBTX) *PgxLoginAttemptRepository {
	return &PgxLoginAttemptRepository{db: db}
}

var _ repository.LoginAttemptRepository = (*PgxLoginAttemptRepository)(nil)

func (r *PgxLoginAttemptRepository) Insert(ctx context.Context, a *domain.LoginAttempt) error {
	if a == nil {
		return errors.New("postgres: nil LoginAttempt")
	}
	if a.ID == uuid.Nil {
		return errors.New("postgres: LoginAttempt.ID required")
	}
	metaJSON := []byte("{}")
	if len(a.Metadata) > 0 {
		b, err := json.Marshal(a.Metadata)
		if err != nil {
			return fmt.Errorf("postgres: encode login_attempts metadata: %w", err)
		}
		metaJSON = b
	}
	const q = `
INSERT INTO login_attempts (id, email_hash, ip_hash, purpose, success, created_at, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`
	_, err := r.db.Exec(ctx, q, a.ID, a.EmailHash, a.IPHash, a.Purpose, a.Success, a.CreatedAt, metaJSON)
	return err
}

// CountAccountFailuresSince counts failures for the SAME (email, ip) pair
// (P2-10 V1 fix — AND, not OR). Served by idx_login_attempts_email_purpose_time.
func (r *PgxLoginAttemptRepository) CountAccountFailuresSince(ctx context.Context, emailHash, ipHash, purpose string, since time.Time) (int, error) {
	const q = `
SELECT COUNT(*) FROM login_attempts
WHERE success = false
  AND purpose = $1
  AND created_at >= $2
  AND email_hash = $3
  AND ip_hash = $4
`
	var n int
	if err := r.db.QueryRow(ctx, q, purpose, since, emailHash, ipHash).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// CountDistinctAccountsFromIPSince counts DISTINCT accounts sprayed from an
// IP (P2-10 V2 fix — COUNT(DISTINCT email_hash), not raw failures). Served
// by idx_login_attempts_ip_purpose_time.
func (r *PgxLoginAttemptRepository) CountDistinctAccountsFromIPSince(ctx context.Context, ipHash, purpose string, since time.Time) (int, error) {
	const q = `
SELECT COUNT(DISTINCT email_hash) FROM login_attempts
WHERE success = false
  AND purpose = $1
  AND created_at >= $2
  AND ip_hash = $3
`
	var n int
	if err := r.db.QueryRow(ctx, q, purpose, since, ipHash).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (r *PgxLoginAttemptRepository) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `DELETE FROM login_attempts WHERE created_at < $1`
	cmd, err := r.db.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
}
