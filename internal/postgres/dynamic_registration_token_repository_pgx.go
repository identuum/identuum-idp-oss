package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxDynamicRegistrationTokenRepository implements
// repository.DynamicRegistrationTokenRepository against the
// dcr_initial_access_tokens table.
type PgxDynamicRegistrationTokenRepository struct {
	db DBTX
}

// NewPgxDynamicRegistrationTokenRepository constructs the repo.
func NewPgxDynamicRegistrationTokenRepository(db DBTX) *PgxDynamicRegistrationTokenRepository {
	return &PgxDynamicRegistrationTokenRepository{db: db}
}

// Compile-time interface check.
var _ repository.DynamicRegistrationTokenRepository = (*PgxDynamicRegistrationTokenRepository)(nil)

// Insert persists a new IAT.
func (r *PgxDynamicRegistrationTokenRepository) Insert(ctx context.Context, t *domain.DynamicRegistrationToken) (*domain.DynamicRegistrationToken, error) {
	if t == nil {
		return nil, errors.New("postgres: nil DynamicRegistrationToken")
	}
	if t.ID == uuid.Nil {
		return nil, errors.New("postgres: DynamicRegistrationToken.ID required")
	}
	if t.TokenHash == "" {
		return nil, errors.New("postgres: DynamicRegistrationToken.TokenHash required")
	}
	if t.ExpiresAt.IsZero() {
		return nil, errors.New("postgres: DynamicRegistrationToken.ExpiresAt required")
	}
	grants := t.AllowedGrantTypes
	if grants == nil {
		grants = []string{}
	}
	authMethods := t.AllowedTokenEndpointAuthMethods
	if authMethods == nil {
		authMethods = []string{}
	}
	const q = `
INSERT INTO dcr_initial_access_tokens (
    id, token_hash, organization_id,
    allowed_grant_types, allowed_token_endpoint_auth_methods,
    expires_at, max_uses, uses_count,
    revoked_at, created_by_user_id, description,
    created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())
RETURNING created_at, updated_at`
	if err := r.db.QueryRow(ctx, q,
		t.ID, t.TokenHash, t.OrganizationID,
		grants, authMethods,
		t.ExpiresAt, t.MaxUses, t.UsesCount,
		t.RevokedAt, t.CreatedByUserID, t.Description,
	).Scan(&t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, fmt.Errorf("postgres: insert dcr_initial_access_tokens: %w", err)
	}
	return t, nil
}

// scanIAT projects a row into a *DynamicRegistrationToken. When
// includeHash is false the TokenHash field is zeroed before
// returning so List/ConsumeByHash cannot leak the hash to
// downstream callers that did not explicitly request it.
func (r *PgxDynamicRegistrationTokenRepository) scanIAT(row pgx.Row, includeHash bool) (*domain.DynamicRegistrationToken, error) {
	var t domain.DynamicRegistrationToken
	if err := row.Scan(
		&t.ID, &t.TokenHash, &t.OrganizationID,
		&t.AllowedGrantTypes, &t.AllowedTokenEndpointAuthMethods,
		&t.ExpiresAt, &t.MaxUses, &t.UsesCount,
		&t.RevokedAt, &t.CreatedByUserID, &t.Description,
		&t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if !includeHash {
		t.TokenHash = ""
	}
	return &t, nil
}

const dcrIATSelectColumns = `
    id, token_hash, organization_id,
    allowed_grant_types, allowed_token_endpoint_auth_methods,
    expires_at, max_uses, uses_count,
    revoked_at, created_by_user_id, description,
    created_at, updated_at`

// GetByID returns the row identified by id with the TokenHash
// scrubbed (id-based lookup is admin-facing only).
func (r *PgxDynamicRegistrationTokenRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.DynamicRegistrationToken, error) {
	q := `SELECT ` + dcrIATSelectColumns + ` FROM dcr_initial_access_tokens WHERE id = $1`
	t, err := r.scanIAT(r.db.QueryRow(ctx, q, id), false)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrDynamicRegistrationTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get dcr_initial_access_tokens by id: %w", err)
	}
	return t, nil
}

// List returns IAT rows in created_at-DESC order with TokenHash
// scrubbed. The safe-projection guarantee is enforced at the
// repository boundary so callers cannot accidentally re-emit
// the hash.
func (r *PgxDynamicRegistrationTokenRepository) List(ctx context.Context) ([]*domain.DynamicRegistrationToken, error) {
	q := `SELECT ` + dcrIATSelectColumns + ` FROM dcr_initial_access_tokens ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("postgres: list dcr_initial_access_tokens: %w", err)
	}
	defer rows.Close()
	out := make([]*domain.DynamicRegistrationToken, 0)
	for rows.Next() {
		t, err := r.scanIAT(rows, false)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan dcr_initial_access_tokens: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke sets revoked_at = at on the row identified by id.
// Idempotent: re-revoking a revoked row leaves the original
// revoked_at untouched and returns nil.
func (r *PgxDynamicRegistrationTokenRepository) Revoke(ctx context.Context, id uuid.UUID, at time.Time) error {
	const q = `
UPDATE dcr_initial_access_tokens
SET    revoked_at = COALESCE(revoked_at, $2),
       updated_at = NOW()
WHERE  id = $1`
	tag, err := r.db.Exec(ctx, q, id, at)
	if err != nil {
		return fmt.Errorf("postgres: revoke dcr_initial_access_tokens: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrDynamicRegistrationTokenNotFound
	}
	return nil
}

// ConsumeByHash atomically looks up the row by token_hash,
// verifies active-at-time, increments uses_count, and returns
// the updated row. The activity predicate and the increment run
// in the same SQL statement so two concurrent DCR calls cannot
// both pass the gate on a single-use token.
//
// The returned row has TokenHash scrubbed.
func (r *PgxDynamicRegistrationTokenRepository) ConsumeByHash(ctx context.Context, tokenHash string, at time.Time) (*domain.DynamicRegistrationToken, error) {
	if tokenHash == "" {
		return nil, errors.New("postgres: ConsumeByHash requires non-empty token_hash")
	}
	// Strategy: UPDATE … WHERE … RETURNING when the row is
	// active; if no row matched the active predicate, fall
	// back to a SELECT to disambiguate "no such hash" from
	// "found but inactive" so the service layer can emit the
	// right (still opaque) error.
	const updateQ = `
UPDATE dcr_initial_access_tokens
SET    uses_count = uses_count + 1,
       updated_at = NOW()
WHERE  token_hash = $1
  AND  revoked_at IS NULL
  AND  expires_at > $2
  AND  (max_uses = 0 OR uses_count < max_uses)
RETURNING ` + dcrIATSelectColumns
	t, err := r.scanIAT(r.db.QueryRow(ctx, updateQ, tokenHash, at), false)
	if err == nil {
		return t, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("postgres: consume dcr_initial_access_tokens: %w", err)
	}
	// No row updated. Disambiguate: does the hash exist at all?
	const existsQ = `SELECT 1 FROM dcr_initial_access_tokens WHERE token_hash = $1`
	var one int
	if err := r.db.QueryRow(ctx, existsQ, tokenHash).Scan(&one); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrDynamicRegistrationTokenNotFound
		}
		return nil, fmt.Errorf("postgres: lookup dcr_initial_access_tokens: %w", err)
	}
	return nil, repository.ErrDynamicRegistrationTokenInactive
}

// DeleteExpiredBefore prunes rows whose expires_at is at or
// before cutoff.
func (r *PgxDynamicRegistrationTokenRepository) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `DELETE FROM dcr_initial_access_tokens WHERE expires_at <= $1`
	tag, err := r.db.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres: prune dcr_initial_access_tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}
