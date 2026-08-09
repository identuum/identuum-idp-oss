package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// PgxSetupStateRepository is the pgx-backed accessor for the singleton
// row in system_setup_state. The migration pre-seeds the row at
// status='setup_required', so callers can rely on Get() returning a row
// on every installation; ErrSetupStateNotFound exists for defensive
// coverage if a future operator clears the table by hand.
type PgxSetupStateRepository struct {
	db DBTX
}

// NewPgxSetupStateRepository constructs a pgx-backed repo.
func NewPgxSetupStateRepository(db DBTX) *PgxSetupStateRepository {
	return &PgxSetupStateRepository{db: db}
}

// Get returns the singleton setup state row. Returns ErrSetupStateNotFound
// if the row is missing (should never happen on a properly-migrated install).
func (r *PgxSetupStateRepository) Get(ctx context.Context) (*domain.SetupState, error) {
	const query = `
		SELECT id, status, setup_token_hash, setup_token_created_at, completed_at, updated_at
		FROM system_setup_state
		WHERE id = $1
	`
	var (
		s              domain.SetupState
		tokenHash      *string
		tokenCreatedAt *time.Time
		completedAt    *time.Time
	)
	err := r.db.QueryRow(ctx, query, domain.SetupStateSingletonID).Scan(
		&s.ID, &s.Status, &tokenHash, &tokenCreatedAt, &completedAt, &s.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrSetupStateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("system_setup_state: get: %w", err)
	}
	if tokenHash != nil {
		s.SetupTokenHash = *tokenHash
	}
	s.SetupTokenCreatedAt = tokenCreatedAt
	s.CompletedAt = completedAt
	return &s, nil
}

// EnsureRow inserts the singleton row at status='setup_required' if it is
// somehow absent. Idempotent: a no-op when the row already exists. The
// migration normally handles seeding, but this is the safety net for an
// environment where the table was truncated by hand.
func (r *PgxSetupStateRepository) EnsureRow(ctx context.Context) error {
	const query = `
		INSERT INTO system_setup_state (id, status)
		VALUES ($1, $2)
		ON CONFLICT (id) DO NOTHING
	`
	if _, err := r.db.Exec(ctx, query, domain.SetupStateSingletonID, domain.SetupStatusRequired); err != nil {
		return fmt.Errorf("system_setup_state: ensure row: %w", err)
	}
	return nil
}

// UpdateTokenHash sets the SHA-256 hex hash of the freshly-generated setup
// token and stamps the creation timestamp. Status is left untouched so a
// re-issue does not flip the state. The caller is the only writer that
// holds the plaintext (in $DATA_DIR/setup-token.txt + a single log line).
func (r *PgxSetupStateRepository) UpdateTokenHash(ctx context.Context, hash string, createdAt time.Time) error {
	const query = `
		UPDATE system_setup_state
		SET setup_token_hash = $2,
		    setup_token_created_at = $3,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`
	res, err := r.db.Exec(ctx, query, domain.SetupStateSingletonID, hash, createdAt)
	if err != nil {
		return fmt.Errorf("system_setup_state: update token hash: %w", err)
	}
	if res.RowsAffected() == 0 {
		return domain.ErrSetupStateNotFound
	}
	return nil
}

// MarkComplete flips status to 'setup_complete', records completion time,
// and clears the token hash. This is the LAST step of the setup-complete
// flow, after the first organization, site_admin user, and signing key
// are all confirmed present — so a mid-flow crash leaves status at
// 'setup_required' and the next call is free to resume.
func (r *PgxSetupStateRepository) MarkComplete(ctx context.Context, at time.Time) error {
	const query = `
		UPDATE system_setup_state
		SET status = $2,
		    setup_token_hash = NULL,
		    completed_at = $3,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`
	res, err := r.db.Exec(ctx, query, domain.SetupStateSingletonID, domain.SetupStatusComplete, at)
	if err != nil {
		return fmt.Errorf("system_setup_state: mark complete: %w", err)
	}
	if res.RowsAffected() == 0 {
		return domain.ErrSetupStateNotFound
	}
	return nil
}
