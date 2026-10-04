package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// PgxMFAProofFailureRepository keeps one row per wrong second-factor code on
// the proof routes (mfa_proof_failures, migration 0048), for the per-user
// budget TOTPFailureBudget counts.
type PgxMFAProofFailureRepository struct {
	db DBTX
}

// NewPgxMFAProofFailureRepository constructs the repository.
func NewPgxMFAProofFailureRepository(db DBTX) *PgxMFAProofFailureRepository {
	return &PgxMFAProofFailureRepository{db: db}
}

// RecordProofFailure stores one wrong code for the user at at.
func (r *PgxMFAProofFailureRepository) RecordProofFailure(ctx context.Context, user uuid.UUID, at time.Time) error {
	id, err := uuidgen.NewV7()
	if err != nil {
		return err
	}
	const q = `INSERT INTO mfa_proof_failures (id, user_id, failed_at) VALUES ($1, $2, $3)`
	_, err = r.db.Exec(ctx, q, id, user, at)
	return err
}

// CountProofFailuresSince counts the user's wrong codes at or after since.
// Served by idx_mfa_proof_failures_user_time.
func (r *PgxMFAProofFailureRepository) CountProofFailuresSince(ctx context.Context, user uuid.UUID, since time.Time) (int, error) {
	const q = `SELECT COUNT(*) FROM mfa_proof_failures WHERE user_id = $1 AND failed_at >= $2`
	var n int
	if err := r.db.QueryRow(ctx, q, user, since).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// DeleteProofFailuresBefore drops the rows older than cutoff, for the sweep.
// Served by idx_mfa_proof_failures_time.
func (r *PgxMFAProofFailureRepository) DeleteProofFailuresBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `DELETE FROM mfa_proof_failures WHERE failed_at < $1`
	cmd, err := r.db.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
}
