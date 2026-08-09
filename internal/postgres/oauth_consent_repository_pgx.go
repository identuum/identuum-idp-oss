package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxOAuthConsentRepository implements OAuthConsentRepository.
type PgxOAuthConsentRepository struct {
	db DBTX
}

// NewPgxOAuthConsentRepository constructs the repo.
func NewPgxOAuthConsentRepository(db DBTX) *PgxOAuthConsentRepository {
	return &PgxOAuthConsentRepository{db: db}
}

// Compile-time interface assertion.
var _ repository.OAuthConsentRepository = (*PgxOAuthConsentRepository)(nil)

// Upsert inserts a new row OR — on (user_id, client_id, audience)
// conflict — flips the existing row's `scope` + `granted_at` and
// clears `revoked_at`. Returns the persisted row.
func (r *PgxOAuthConsentRepository) Upsert(ctx context.Context, c *domain.OAuthConsent) (*domain.OAuthConsent, error) {
	if c == nil {
		return nil, errors.New("postgres: nil OAuthConsent")
	}
	if c.ID == uuid.Nil {
		return nil, errors.New("postgres: OAuthConsent.ID required")
	}
	if c.UserID == uuid.Nil {
		return nil, errors.New("postgres: OAuthConsent.UserID required")
	}
	if c.ClientID == "" {
		return nil, errors.New("postgres: OAuthConsent.ClientID required")
	}
	const q = `
INSERT INTO oauth_consents (
    id, user_id, organization_id, client_id, audience, scope,
    granted_at, revoked_at, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NOW(), NOW())
ON CONFLICT (user_id, client_id, audience) DO UPDATE SET
    scope = EXCLUDED.scope,
    granted_at = EXCLUDED.granted_at,
    revoked_at = NULL,
    updated_at = NOW()
RETURNING id, user_id, organization_id, client_id, audience, scope,
          granted_at, revoked_at, created_at, updated_at
`
	row := r.db.QueryRow(ctx, q,
		c.ID, c.UserID, c.OrganizationID, c.ClientID, c.Audience, c.Scope, c.GrantedAt,
	)
	return scanOAuthConsent(row)
}

// GetActive returns the (user, client, audience) row when active.
func (r *PgxOAuthConsentRepository) GetActive(ctx context.Context, userID uuid.UUID, clientID, audience string) (*domain.OAuthConsent, error) {
	const q = `
SELECT id, user_id, organization_id, client_id, audience, scope,
       granted_at, revoked_at, created_at, updated_at
FROM oauth_consents
WHERE user_id = $1 AND client_id = $2 AND audience = $3
      AND revoked_at IS NULL
`
	row := r.db.QueryRow(ctx, q, userID, clientID, audience)
	out, err := scanOAuthConsent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return out, err
}

// Revoke marks the row revoked.
func (r *PgxOAuthConsentRepository) Revoke(ctx context.Context, userID uuid.UUID, clientID, audience string, at time.Time) error {
	const q = `
UPDATE oauth_consents
SET revoked_at = $4, updated_at = NOW()
WHERE user_id = $1 AND client_id = $2 AND audience = $3
      AND revoked_at IS NULL
`
	_, err := r.db.Exec(ctx, q, userID, clientID, audience, at)
	return err
}

func scanOAuthConsent(row pgx.Row) (*domain.OAuthConsent, error) {
	var c domain.OAuthConsent
	if err := row.Scan(
		&c.ID, &c.UserID, &c.OrganizationID, &c.ClientID, &c.Audience, &c.Scope,
		&c.GrantedAt, &c.RevokedAt, &c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &c, nil
}
