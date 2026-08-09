package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxRefreshTokenRepository implements
// repository.RefreshTokenRepository against the oauth_refresh_tokens
// table. The repository never reads or writes raw token bytes — the
// only token-derived value it touches is the SHA-256 hex digest of
// the validator side of the wire token.
type PgxRefreshTokenRepository struct {
	db DBTX
}

// NewPgxRefreshTokenRepository constructs the repository.
func NewPgxRefreshTokenRepository(db DBTX) *PgxRefreshTokenRepository {
	return &PgxRefreshTokenRepository{db: db}
}

// Compile-time interface checks. The extension assertion pins the
// access-jti cascade the production reuse response + RevokeAllForUser rely
// on via a runtime type assertion — if the extension interface drifts, the
// build breaks here instead of silently degrading production to no-cascade.
var (
	_ repository.RefreshTokenRepository                    = (*PgxRefreshTokenRepository)(nil)
	_ repository.RefreshTokenAccessJTIRevocationRepository = (*PgxRefreshTokenRepository)(nil)
)

// Insert plants the supplied row. Returns a wrapped error on
// constraint failure so callers can decide whether to retry the
// selector generation.
func (r *PgxRefreshTokenRepository) Insert(ctx context.Context, rt *domain.RefreshToken) error {
	if rt == nil {
		return errors.New("postgres: nil RefreshToken")
	}
	if rt.ID == uuid.Nil {
		return errors.New("postgres: RefreshToken.ID required")
	}
	if rt.ValidatorHash == "" {
		return errors.New("postgres: RefreshToken.ValidatorHash required")
	}
	if rt.ClientID == "" {
		return errors.New("postgres: RefreshToken.ClientID required")
	}
	if rt.Subject == "" {
		return errors.New("postgres: RefreshToken.Subject required")
	}
	if rt.ExpiresAt.IsZero() {
		return errors.New("postgres: RefreshToken.ExpiresAt required")
	}
	metaJSON := []byte("{}")
	if len(rt.Metadata) > 0 {
		b, err := json.Marshal(rt.Metadata)
		if err != nil {
			return fmt.Errorf("postgres: encode refresh token metadata: %w", err)
		}
		metaJSON = b
	}
	const q = `
		INSERT INTO oauth_refresh_tokens (
			id, validator_hash, client_id, client_kind, subject,
			scope, audience, expires_at, access_jti, metadata, family_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := r.db.Exec(ctx, q,
		rt.ID,
		rt.ValidatorHash,
		rt.ClientID,
		string(rt.ClientKind),
		rt.Subject,
		rt.Scope,
		rt.Audience,
		rt.ExpiresAt,
		nullableString(rt.AccessJTI),
		metaJSON,
		nullableUUIDString(rt.FamilyID),
	)
	if err != nil {
		return fmt.Errorf("postgres: insert oauth_refresh_tokens: %w", err)
	}
	return nil
}

// GetByID returns the row whose selector matches id, or (nil, nil)
// when the selector is unknown.
func (r *PgxRefreshTokenRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.RefreshToken, error) {
	if id == uuid.Nil {
		return nil, nil
	}
	const q = `
		SELECT id, validator_hash, client_id, client_kind, subject,
		       scope, audience, expires_at, revoked_at, replaced_by,
		       access_jti, created_at, last_used_at, metadata, family_id
		FROM   oauth_refresh_tokens
		WHERE  id = $1`
	row := r.db.QueryRow(ctx, q, id)
	out, err := scanRefreshToken(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres: get oauth_refresh_tokens: %w", err)
	}
	return out, nil
}

// MarkRevoked sets RevokedAt for the row. Idempotent — re-revoking
// a row simply moves the timestamp forward.
func (r *PgxRefreshTokenRepository) MarkRevoked(ctx context.Context, id uuid.UUID, at time.Time) error {
	if id == uuid.Nil {
		return nil
	}
	const q = `UPDATE oauth_refresh_tokens SET revoked_at = $2 WHERE id = $1`
	_, err := r.db.Exec(ctx, q, id, at)
	if err != nil {
		return fmt.Errorf("postgres: revoke oauth_refresh_tokens: %w", err)
	}
	return nil
}

// MarkRotated revokes the old row and points its replaced_by column
// at the new row. Also stamps last_used_at on the old row so the
// audit trail captures the rotation moment.
func (r *PgxRefreshTokenRepository) MarkRotated(ctx context.Context, oldID, newID uuid.UUID, at time.Time) error {
	if oldID == uuid.Nil || newID == uuid.Nil {
		return nil
	}
	// P3-1: COMPARE-AND-SET, not a blind UPDATE.
	//
	// This used to be `WHERE id = $1` with the result discarded, so two
	// concurrent rotations of the SAME refresh token both "succeeded": each
	// read the row while it was still active, each inserted a replacement, and
	// each returned a fresh token to its caller. One refresh token became two
	// live lineages, and the reuse detector never fired because the row's
	// ReplacedBy was simply overwritten by the second writer.
	//
	// `AND revoked_at IS NULL` makes the database the arbiter: exactly one
	// writer can match. The loser sees zero rows affected and gets
	// ErrRefreshAlreadyRotated, which Consume routes into the existing reuse
	// path — correctly, because a second exchange of an already-exchanged
	// token is precisely what reuse means.
	const q = `
		UPDATE oauth_refresh_tokens
		SET    revoked_at   = $2,
		       replaced_by  = $3,
		       last_used_at = $2
		WHERE  id = $1
		  AND  revoked_at IS NULL`
	tag, err := r.db.Exec(ctx, q, oldID, at, newID)
	if err != nil {
		return fmt.Errorf("postgres: rotate oauth_refresh_tokens: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrRefreshAlreadyRotated
	}
	return nil
}

// SetAccessJTI stores the jti of the access token most recently
// minted against the supplied refresh row so /api/v1/oauth/revoke
// can cascade the revocation.
func (r *PgxRefreshTokenRepository) SetAccessJTI(ctx context.Context, id uuid.UUID, accessJTI string, at time.Time) error {
	if id == uuid.Nil {
		return nil
	}
	const q = `
		UPDATE oauth_refresh_tokens
		SET    access_jti   = $2,
		       last_used_at = $3
		WHERE  id = $1`
	_, err := r.db.Exec(ctx, q, id, nullableString(accessJTI), at)
	if err != nil {
		return fmt.Errorf("postgres: set access_jti oauth_refresh_tokens: %w", err)
	}
	return nil
}

// RevokeAllBySubject sets revoked_at on every active row whose
// subject column matches. Empty subject is a no-op so callers do
// not have to guard against unauthenticated reset attempts. The
// `revoked_at IS NULL` predicate makes the call idempotent and
// stops the row count from drifting on repeated invocations.
// Returns the number of rows actually mutated.
func (r *PgxRefreshTokenRepository) RevokeAllBySubject(ctx context.Context, subject string, at time.Time) (int64, error) {
	if subject == "" {
		return 0, nil
	}
	const q = `
		UPDATE oauth_refresh_tokens
		SET    revoked_at = $2
		WHERE  subject    = $1
		  AND  revoked_at IS NULL`
	tag, err := r.db.Exec(ctx, q, subject, at)
	if err != nil {
		return 0, fmt.Errorf("postgres: revoke oauth_refresh_tokens by subject: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RevokeByFamily sets revoked_at on every ACTIVE row (not revoked, not
// expired) sharing family_id — the family-scoped automated reuse response
// (RFC 9700 §4.13.2). Empty familyID is a no-op so a legacy NULL-family
// row never matches — this comparison can never be true against a real UUID:
//
//	family_id = ''
//
// Returns the number of rows actually mutated.
func (r *PgxRefreshTokenRepository) RevokeByFamily(ctx context.Context, familyID string, at time.Time) (int64, error) {
	if familyID == "" {
		return 0, nil
	}
	const q = `
		UPDATE oauth_refresh_tokens
		SET    revoked_at = $2
		WHERE  family_id  = $1
		  AND  revoked_at IS NULL
		  AND  expires_at > $2`
	tag, err := r.db.Exec(ctx, q, familyID, at)
	if err != nil {
		return 0, fmt.Errorf("postgres: revoke oauth_refresh_tokens by family: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RevokeByFamilyReturningAccessJTIs is the access-token-aware variant of
// RevokeByFamily (RFC 9700 §4.13.2 reuse cascade). It revokes the same
// ACTIVE (not revoked, not expired) rows sharing family_id and returns the
// access_jti + expires_at projection for the rows newly revoked by this
// call, so the caller can denylist the family's live access tokens. Empty
// familyID is a no-op.
func (r *PgxRefreshTokenRepository) RevokeByFamilyReturningAccessJTIs(ctx context.Context, familyID string, at time.Time) (int64, []repository.RevokedRefreshTokenAccessJTI, error) {
	if familyID == "" {
		return 0, nil, nil
	}
	const q = `
		UPDATE oauth_refresh_tokens
		SET    revoked_at = $2
		WHERE  family_id  = $1
		  AND  revoked_at IS NULL
		  AND  expires_at > $2
		RETURNING access_jti, expires_at`
	rows, err := r.db.Query(ctx, q, familyID, at)
	if err != nil {
		return 0, nil, fmt.Errorf("postgres: revoke oauth_refresh_tokens by family returning access_jti: %w", err)
	}
	defer rows.Close()

	var (
		count int64
		jtis  []repository.RevokedRefreshTokenAccessJTI
	)
	for rows.Next() {
		var (
			accessJTI *string
			expiresAt time.Time
		)
		if err := rows.Scan(&accessJTI, &expiresAt); err != nil {
			return 0, nil, fmt.Errorf("postgres: scan revoked oauth_refresh_tokens by family access_jti: %w", err)
		}
		count++
		if accessJTI == nil || *accessJTI == "" {
			continue
		}
		jtis = append(jtis, repository.RevokedRefreshTokenAccessJTI{
			JTI:       *accessJTI,
			ExpiresAt: expiresAt,
		})
	}
	if err := rows.Err(); err != nil {
		return 0, nil, fmt.Errorf("postgres: iterate revoked oauth_refresh_tokens by family access_jti: %w", err)
	}
	return count, jtis, nil
}

// RevokeAllBySubjectReturningAccessJTIs is the access-token-aware
// variant of RevokeAllBySubject. It returns only the access_jti and
// expires_at projection for rows newly revoked by this call; rows that
// were already revoked are skipped by the same idempotency predicate.
func (r *PgxRefreshTokenRepository) RevokeAllBySubjectReturningAccessJTIs(ctx context.Context, subject string, at time.Time) (int64, []repository.RevokedRefreshTokenAccessJTI, error) {
	if subject == "" {
		return 0, nil, nil
	}
	const q = `
		UPDATE oauth_refresh_tokens
		SET    revoked_at = $2
		WHERE  subject    = $1
		  AND  revoked_at IS NULL
		RETURNING access_jti, expires_at`
	rows, err := r.db.Query(ctx, q, subject, at)
	if err != nil {
		return 0, nil, fmt.Errorf("postgres: revoke oauth_refresh_tokens by subject returning access_jti: %w", err)
	}
	defer rows.Close()

	var (
		count int64
		jtis  []repository.RevokedRefreshTokenAccessJTI
	)
	for rows.Next() {
		var (
			accessJTI *string
			expiresAt time.Time
		)
		if err := rows.Scan(&accessJTI, &expiresAt); err != nil {
			return 0, nil, fmt.Errorf("postgres: scan revoked oauth_refresh_tokens access_jti: %w", err)
		}
		count++
		if accessJTI == nil || *accessJTI == "" {
			continue
		}
		jtis = append(jtis, repository.RevokedRefreshTokenAccessJTI{
			JTI:       *accessJTI,
			ExpiresAt: expiresAt,
		})
	}
	if err := rows.Err(); err != nil {
		return 0, nil, fmt.Errorf("postgres: iterate revoked oauth_refresh_tokens access_jti: %w", err)
	}
	return count, jtis, nil
}

// DeleteExpiredBefore prunes rows whose ExpiresAt is at or before
// the supplied cutoff. Returns the row count for observability.
func (r *PgxRefreshTokenRepository) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `DELETE FROM oauth_refresh_tokens WHERE expires_at <= $1`
	tag, err := r.db.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres: prune oauth_refresh_tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// scanRefreshToken decodes a single oauth_refresh_tokens row into
// the domain projection. The metadata JSONB column is decoded into
// a map[string]any; callers MUST treat the map as read-only.
func scanRefreshToken(row pgx.Row) (*domain.RefreshToken, error) {
	var (
		id            uuid.UUID
		validatorHash string
		clientID      string
		clientKind    string
		subject       string
		scope         string
		audience      string
		expiresAt     time.Time
		revokedAt     *time.Time
		replacedBy    *uuid.UUID
		accessJTI     *string
		createdAt     time.Time
		lastUsedAt    *time.Time
		metaBytes     []byte
		familyID      *uuid.UUID
	)
	if err := row.Scan(
		&id, &validatorHash, &clientID, &clientKind, &subject,
		&scope, &audience, &expiresAt, &revokedAt, &replacedBy,
		&accessJTI, &createdAt, &lastUsedAt, &metaBytes, &familyID,
	); err != nil {
		return nil, err
	}
	out := &domain.RefreshToken{
		ID:            id,
		ValidatorHash: validatorHash,
		ClientID:      clientID,
		ClientKind:    domain.RefreshTokenKind(clientKind),
		Subject:       subject,
		Scope:         scope,
		Audience:      audience,
		ExpiresAt:     expiresAt,
		RevokedAt:     revokedAt,
		ReplacedBy:    replacedBy,
		CreatedAt:     createdAt,
		LastUsedAt:    lastUsedAt,
	}
	if accessJTI != nil {
		out.AccessJTI = *accessJTI
	}
	if familyID != nil {
		out.FamilyID = familyID.String()
	}
	if len(metaBytes) > 0 {
		var meta map[string]any
		if err := json.Unmarshal(metaBytes, &meta); err == nil {
			out.Metadata = meta
		}
	}
	return out, nil
}

// nullableString returns nil for empty strings so the column lands
// as SQL NULL — matters for the partial-index on access_jti.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableUUIDString maps a string-form UUID to a uuid.UUID for a UUID
// column, or nil (SQL NULL) when empty. A malformed value also lands as
// NULL — defensive only; the service always supplies a valid UUIDv7 or "".
func nullableUUIDString(s string) any {
	if s == "" {
		return nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return id
}
