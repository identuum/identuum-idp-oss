package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxTokenRevocationRepository persists rows in
// `oauth_token_revocations` via pgx. The implementation is
// intentionally narrow: it never reads back the metadata blob, it
// never echoes any column except `jti` to log lines, and the
// idempotent INSERT path uses `ON CONFLICT (jti) DO NOTHING` so a
// duplicate revoke is a no-op at the wire layer.
type PgxTokenRevocationRepository struct {
	db DBTX
}

// NewPgxTokenRevocationRepository constructs the repository.
func NewPgxTokenRevocationRepository(db DBTX) *PgxTokenRevocationRepository {
	return &PgxTokenRevocationRepository{db: db}
}

// Compile-time interface check.
var _ repository.TokenRevocationRepository = (*PgxTokenRevocationRepository)(nil)

// Insert persists a TokenRevocation row. The INSERT is idempotent:
// a duplicate jti returns nil (no surfaced error) so the wire
// contract for RFC 7009 §2.2 can stay unconditional 200.
//
// The Metadata blob is encoded with encoding/json. The service
// layer is responsible for capping what may land there — this
// repository does not strip keys.
func (r *PgxTokenRevocationRepository) Insert(ctx context.Context, rev *domain.TokenRevocation) error {
	if rev == nil {
		return errors.New("postgres: nil TokenRevocation")
	}
	if rev.Jti == "" {
		return errors.New("postgres: TokenRevocation.Jti required")
	}
	if rev.ExpiresAt.IsZero() {
		return errors.New("postgres: TokenRevocation.ExpiresAt required")
	}
	metaJSON := []byte("{}")
	if len(rev.Metadata) > 0 {
		b, err := json.Marshal(rev.Metadata)
		if err != nil {
			return fmt.Errorf("postgres: encode TokenRevocation metadata: %w", err)
		}
		metaJSON = b
	}
	reason := rev.Reason
	if reason == "" {
		reason = "oauth_token_revoked"
	}
	const q = `
		INSERT INTO oauth_token_revocations (jti, expires_at, reason, metadata, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (jti) DO NOTHING`
	_, err := r.db.Exec(ctx, q, rev.Jti, rev.ExpiresAt, reason, metaJSON)
	if err != nil {
		return fmt.Errorf("postgres: insert oauth_token_revocations: %w", err)
	}
	return nil
}

// Exists is the constant-time check the introspection path runs
// on every verified token. Unknown jtis return (false, nil).
func (r *PgxTokenRevocationRepository) Exists(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	const q = `SELECT 1 FROM oauth_token_revocations WHERE jti = $1`
	var one int
	err := r.db.QueryRow(ctx, q, jti).Scan(&one)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("postgres: lookup oauth_token_revocations: %w", err)
	}
	return true, nil
}

// DeleteExpiredBefore prunes rows whose ExpiresAt is at or before
// the supplied cutoff. Returns the number of rows deleted.
func (r *PgxTokenRevocationRepository) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `DELETE FROM oauth_token_revocations WHERE expires_at <= $1`
	tag, err := r.db.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres: prune oauth_token_revocations: %w", err)
	}
	return tag.RowsAffected(), nil
}
