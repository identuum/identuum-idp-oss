package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxClientAssertionReplayRepository implements
// repository.ClientAssertionReplayRepository against the
// oauth_client_assertion_replays table.
type PgxClientAssertionReplayRepository struct {
	db DBTX
}

// NewPgxClientAssertionReplayRepository constructs the repository.
func NewPgxClientAssertionReplayRepository(db DBTX) *PgxClientAssertionReplayRepository {
	return &PgxClientAssertionReplayRepository{db: db}
}

// Compile-time interface check.
var _ repository.ClientAssertionReplayRepository = (*PgxClientAssertionReplayRepository)(nil)

// Insert atomically registers (clientID, jtiHash) in the replay
// store. Returns (true, nil) when the row was newly inserted —
// first use, the caller may proceed. Returns (false, nil) when
// the row already existed — REPLAY. Returns (false, err) on a
// repository error; callers MUST treat that case as a replay
// rejection (fail-closed).
//
// The raw jti is NEVER passed to this method; the caller MUST
// supply the hex SHA-256 digest. Empty inputs are programmer
// errors and surface as wrapped errors.
func (r *PgxClientAssertionReplayRepository) Insert(ctx context.Context, clientID, jtiHash string, expiresAt time.Time) (bool, error) {
	if clientID == "" {
		return false, errors.New("postgres: ClientAssertionReplay.Insert requires non-empty client_id")
	}
	if jtiHash == "" {
		return false, errors.New("postgres: ClientAssertionReplay.Insert requires non-empty jti_hash")
	}
	if expiresAt.IsZero() {
		return false, errors.New("postgres: ClientAssertionReplay.Insert requires non-zero expires_at")
	}
	const q = `
		INSERT INTO oauth_client_assertion_replays (client_id, jti_hash, expires_at, created_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (client_id, jti_hash) DO NOTHING`
	tag, err := r.db.Exec(ctx, q, clientID, jtiHash, expiresAt)
	if err != nil {
		return false, fmt.Errorf("postgres: insert oauth_client_assertion_replays: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteExpiredBefore prunes rows whose expires_at is at or
// before cutoff.
func (r *PgxClientAssertionReplayRepository) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `DELETE FROM oauth_client_assertion_replays WHERE expires_at <= $1`
	tag, err := r.db.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres: prune oauth_client_assertion_replays: %w", err)
	}
	return tag.RowsAffected(), nil
}
