package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxDPoPProofReplayRepository is the pgx implementation of
// repository.DPoPProofReplayRepository over dpop_proof_replays (migration 0038).
type PgxDPoPProofReplayRepository struct {
	db DBTX
}

var _ repository.DPoPProofReplayRepository = (*PgxDPoPProofReplayRepository)(nil)

// NewPgxDPoPProofReplayRepository constructs the repository.
func NewPgxDPoPProofReplayRepository(db DBTX) *PgxDPoPProofReplayRepository {
	return &PgxDPoPProofReplayRepository{db: db}
}

// Insert implements the repository contract: an INSERT … ON CONFLICT DO
// NOTHING whose affected-row count is the single-use verdict.
func (r *PgxDPoPProofReplayRepository) Insert(ctx context.Context, jkt, jtiHash string, expiresAt time.Time) (bool, error) {
	if jkt == "" {
		return false, errors.New("postgres: DPoPProofReplay.Insert requires non-empty jkt")
	}
	if jtiHash == "" {
		return false, errors.New("postgres: DPoPProofReplay.Insert requires non-empty jti_hash")
	}
	if expiresAt.IsZero() {
		return false, errors.New("postgres: DPoPProofReplay.Insert requires non-zero expires_at")
	}
	const q = `
		INSERT INTO dpop_proof_replays (jkt, jti_hash, expires_at, created_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (jkt, jti_hash) DO NOTHING`
	tag, err := r.db.Exec(ctx, q, jkt, jtiHash, expiresAt)
	if err != nil {
		return false, fmt.Errorf("postgres: insert dpop_proof_replays: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteExpiredBefore implements the repository contract.
func (r *PgxDPoPProofReplayRepository) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := r.db.Exec(ctx, `DELETE FROM dpop_proof_replays WHERE expires_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired dpop_proof_replays: %w", err)
	}
	return tag.RowsAffected(), nil
}
