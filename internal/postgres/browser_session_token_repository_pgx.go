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

// PgxBrowserSessionTokenRepository implements
// BrowserSessionTokenRepository.
type PgxBrowserSessionTokenRepository struct {
	db DBTX
}

func NewPgxBrowserSessionTokenRepository(db DBTX) *PgxBrowserSessionTokenRepository {
	return &PgxBrowserSessionTokenRepository{db: db}
}

var _ repository.BrowserSessionTokenRepository = (*PgxBrowserSessionTokenRepository)(nil)

func (r *PgxBrowserSessionTokenRepository) Insert(ctx context.Context, t *domain.BrowserSessionToken) error {
	if t == nil {
		return errors.New("postgres: nil BrowserSessionToken")
	}
	if t.ID == uuid.Nil {
		return errors.New("postgres: BrowserSessionToken.ID required")
	}
	if t.SessionID == uuid.Nil {
		return errors.New("postgres: BrowserSessionToken.SessionID required")
	}
	if t.TokenHash == "" {
		return errors.New("postgres: BrowserSessionToken.TokenHash required")
	}
	const q = `
INSERT INTO browser_session_tokens (
    id, session_id, user_id, organization_id, token_hash,
    user_agent, ip_address, expires_at,
    revoked_at, created_at, updated_at, last_used_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL,NOW(),NOW(),NULL)
`
	_, err := r.db.Exec(ctx, q,
		t.ID, t.SessionID, t.UserID, t.OrganizationID, t.TokenHash,
		t.UserAgent, t.IPAddress, t.ExpiresAt,
	)
	return err
}

func (r *PgxBrowserSessionTokenRepository) GetByTokenHash(ctx context.Context, tokenHash string, now time.Time) (*domain.BrowserSessionToken, error) {
	const q = `
SELECT id, session_id, user_id, organization_id, token_hash,
       user_agent, ip_address, expires_at, revoked_at,
       created_at, updated_at, last_used_at
FROM browser_session_tokens
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2
`
	row := r.db.QueryRow(ctx, q, tokenHash, now)
	out, err := scanBrowserSessionToken(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return out, err
}

func (r *PgxBrowserSessionTokenRepository) RevokeByTokenHash(ctx context.Context, tokenHash string, at time.Time) error {
	const q = `
UPDATE browser_session_tokens
SET revoked_at = $2, updated_at = NOW()
WHERE token_hash = $1 AND revoked_at IS NULL
`
	_, err := r.db.Exec(ctx, q, tokenHash, at)
	return err
}

func (r *PgxBrowserSessionTokenRepository) RevokeBySessionID(ctx context.Context, sessionID uuid.UUID, at time.Time) error {
	const q = `
UPDATE browser_session_tokens
SET revoked_at = $2, updated_at = NOW()
WHERE session_id = $1 AND revoked_at IS NULL
`
	_, err := r.db.Exec(ctx, q, sessionID, at)
	return err
}

func (r *PgxBrowserSessionTokenRepository) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `DELETE FROM browser_session_tokens WHERE expires_at < $1`
	cmd, err := r.db.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
}

func scanBrowserSessionToken(row pgx.Row) (*domain.BrowserSessionToken, error) {
	var t domain.BrowserSessionToken
	if err := row.Scan(
		&t.ID, &t.SessionID, &t.UserID, &t.OrganizationID, &t.TokenHash,
		&t.UserAgent, &t.IPAddress, &t.ExpiresAt, &t.RevokedAt,
		&t.CreatedAt, &t.UpdatedAt, &t.LastUsedAt,
	); err != nil {
		return nil, err
	}
	return &t, nil
}
