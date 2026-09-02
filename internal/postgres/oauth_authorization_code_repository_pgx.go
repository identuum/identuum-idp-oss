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

// PgxOAuthAuthorizationCodeRepository implements the new
// OAuthAuthorizationCodeRepository against the
// oauth_authorization_codes table. It is intentionally separate
// from the legacy AuthCodeRepository (against auth_codes).
type PgxOAuthAuthorizationCodeRepository struct {
	db DBTX
}

// NewPgxOAuthAuthorizationCodeRepository constructs the repo.
func NewPgxOAuthAuthorizationCodeRepository(db DBTX) *PgxOAuthAuthorizationCodeRepository {
	return &PgxOAuthAuthorizationCodeRepository{db: db}
}

// Compile-time interface check.
var _ repository.OAuthAuthorizationCodeRepository = (*PgxOAuthAuthorizationCodeRepository)(nil)

// Insert persists a fresh row.
func (r *PgxOAuthAuthorizationCodeRepository) Insert(ctx context.Context, code *domain.OAuthAuthorizationCode) error {
	if code == nil {
		return errors.New("postgres: nil OAuthAuthorizationCode")
	}
	if code.ID == uuid.Nil {
		return errors.New("postgres: OAuthAuthorizationCode.ID required")
	}
	if code.CodeHash == "" {
		return errors.New("postgres: OAuthAuthorizationCode.CodeHash required")
	}
	if code.ClientID == "" {
		return errors.New("postgres: OAuthAuthorizationCode.ClientID required")
	}
	if code.UserID == uuid.Nil {
		return errors.New("postgres: OAuthAuthorizationCode.UserID required")
	}
	if code.SessionID == uuid.Nil {
		return errors.New("postgres: OAuthAuthorizationCode.SessionID required")
	}
	if code.ExpiresAt.IsZero() {
		return errors.New("postgres: OAuthAuthorizationCode.ExpiresAt required")
	}
	metaJSON := []byte("{}")
	if len(code.Metadata) > 0 {
		b, err := json.Marshal(code.Metadata)
		if err != nil {
			return fmt.Errorf("postgres: encode oauth_authorization_codes metadata: %w", err)
		}
		metaJSON = b
	}
	// THE-CLAIMS-PARAMETER: the parsed §5.5 request rides with the code;
	// NULL when nothing emittable was requested.
	var requestedClaims *string
	if enc := code.RequestedClaims.Encode(); enc != "" {
		requestedClaims = &enc
	}
	const q = `
		INSERT INTO oauth_authorization_codes (
			id, code_hash, client_id, user_id, organization_id,
			session_id, redirect_uri, scope, audience,
			code_challenge, code_challenge_method, nonce,
			expires_at, metadata, created_at, requested_claims
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, NOW(), $15
		)`
	_, err := r.db.Exec(ctx, q,
		code.ID,
		code.CodeHash,
		code.ClientID,
		code.UserID,
		code.OrganizationID,
		code.SessionID,
		code.RedirectURI,
		code.Scope,
		code.Audience,
		code.CodeChallenge,
		code.CodeChallengeMethod,
		code.Nonce,
		code.ExpiresAt,
		metaJSON,
		requestedClaims,
	)
	if err != nil {
		return fmt.Errorf("postgres: insert oauth_authorization_codes: %w", err)
	}
	return nil
}

// GetActiveByCodeHash looks up the row by code_hash, gated on
// consumed_at IS NULL AND expires_at > now.
// GetByCodeHashAnyState implements repository.OAuthAuthorizationCodeRepository.
// No consumed_at or expires_at predicate: the caller is asking whether this
// code was EVER issued, not whether it is usable right now.
func (r *PgxOAuthAuthorizationCodeRepository) GetByCodeHashAnyState(ctx context.Context, codeHash string) (*domain.OAuthAuthorizationCode, error) {
	if codeHash == "" {
		return nil, nil
	}
	const q = `
		SELECT id, code_hash, client_id, user_id, organization_id,
		       session_id, redirect_uri, scope, audience,
		       code_challenge, code_challenge_method, nonce,
		       expires_at, consumed_at, created_at, metadata,
		       issued_access_jti, issued_access_expires_at, issued_refresh_token_id,
		       requested_claims
		FROM   oauth_authorization_codes
		WHERE  code_hash = $1`
	row := r.db.QueryRow(ctx, q, codeHash)
	out, err := scanOAuthAuthorizationCode(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres: get oauth_authorization_codes any state: %w", err)
	}
	return out, nil
}

func (r *PgxOAuthAuthorizationCodeRepository) GetActiveByCodeHash(ctx context.Context, codeHash string, now time.Time) (*domain.OAuthAuthorizationCode, error) {
	if codeHash == "" {
		return nil, nil
	}
	const q = `
		SELECT id, code_hash, client_id, user_id, organization_id,
		       session_id, redirect_uri, scope, audience,
		       code_challenge, code_challenge_method, nonce,
		       expires_at, consumed_at, created_at, metadata,
		       issued_access_jti, issued_access_expires_at, issued_refresh_token_id,
		       requested_claims
		FROM   oauth_authorization_codes
		WHERE  code_hash = $1
		  AND  consumed_at IS NULL
		  AND  expires_at > $2`
	row := r.db.QueryRow(ctx, q, codeHash, now)
	out, err := scanOAuthAuthorizationCode(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("postgres: get oauth_authorization_codes: %w", err)
	}
	return out, nil
}

// MarkConsumed stamps consumed_at on the row identified by id.
// Idempotent.
func (r *PgxOAuthAuthorizationCodeRepository) MarkConsumed(ctx context.Context, id uuid.UUID, at time.Time) (bool, error) {
	const q = `UPDATE oauth_authorization_codes SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL`
	ct, err := r.db.Exec(ctx, q, id, at)
	if err != nil {
		return false, fmt.Errorf("postgres: consume oauth_authorization_codes: %w", err)
	}
	// RowsAffected is the atomic single-use proof. Under READ COMMITTED
	// two concurrent consumes of the same code serialize on the row
	// lock: the first flips consumed_at (1 row); the second re-checks
	// `consumed_at IS NULL` against the freshly committed row, matches
	// nothing (0 rows), and loses. Returning that fact — instead of
	// discarding the command tag with `_` — is what makes the losing
	// caller reject instead of double-spend the code.
	return ct.RowsAffected() == 1, nil
}

// RecordIssuedTokens stamps what the exchange minted onto the consumed code
// row (THE-CODE-REUSE-REVOKER). Plain UPDATE by id: the row was consumed a
// moment ago by the same request, and a later replay reads these columns
// through GetByCodeHashAnyState to revoke exactly what they name.
func (r *PgxOAuthAuthorizationCodeRepository) RecordIssuedTokens(ctx context.Context, id uuid.UUID, accessJTI string, accessExpiresAt time.Time, refreshTokenID *uuid.UUID) error {
	if id == uuid.Nil {
		return errors.New("postgres: RecordIssuedTokens requires a code id")
	}
	if accessJTI == "" || accessExpiresAt.IsZero() {
		return errors.New("postgres: RecordIssuedTokens requires the access token jti and expiry")
	}
	const q = `
		UPDATE oauth_authorization_codes
		SET    issued_access_jti = $2,
		       issued_access_expires_at = $3,
		       issued_refresh_token_id = $4
		WHERE  id = $1`
	if _, err := r.db.Exec(ctx, q, id, accessJTI, accessExpiresAt, refreshTokenID); err != nil {
		return fmt.Errorf("postgres: record issued tokens on oauth_authorization_codes: %w", err)
	}
	return nil
}

// DeleteExpiredBefore prunes rows whose expires_at is at or
// before the supplied cutoff.
func (r *PgxOAuthAuthorizationCodeRepository) DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `DELETE FROM oauth_authorization_codes WHERE expires_at <= $1`
	tag, err := r.db.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres: prune oauth_authorization_codes: %w", err)
	}
	return tag.RowsAffected(), nil
}

func scanOAuthAuthorizationCode(row pgx.Row) (*domain.OAuthAuthorizationCode, error) {
	var (
		id                  uuid.UUID
		codeHash            string
		clientID            string
		userID              uuid.UUID
		orgID               *uuid.UUID
		sessionID           uuid.UUID
		redirectURI         string
		scope               string
		audience            string
		codeChallenge       string
		codeChallengeMethod string
		nonce               string
		expiresAt           time.Time
		consumedAt          *time.Time
		createdAt           time.Time
		metaBytes           []byte
		issuedAccessJTI     *string
		issuedAccessExpires *time.Time
		issuedRefreshID     *uuid.UUID
		requestedClaims     []byte
	)
	if err := row.Scan(
		&id, &codeHash, &clientID, &userID, &orgID,
		&sessionID, &redirectURI, &scope, &audience,
		&codeChallenge, &codeChallengeMethod, &nonce,
		&expiresAt, &consumedAt, &createdAt, &metaBytes,
		&issuedAccessJTI, &issuedAccessExpires, &issuedRefreshID,
		&requestedClaims,
	); err != nil {
		return nil, err
	}
	out := &domain.OAuthAuthorizationCode{
		ID:                    id,
		CodeHash:              codeHash,
		ClientID:              clientID,
		UserID:                userID,
		OrganizationID:        orgID,
		SessionID:             sessionID,
		RedirectURI:           redirectURI,
		Scope:                 scope,
		Audience:              audience,
		CodeChallenge:         codeChallenge,
		CodeChallengeMethod:   codeChallengeMethod,
		Nonce:                 nonce,
		ExpiresAt:             expiresAt,
		ConsumedAt:            consumedAt,
		CreatedAt:             createdAt,
		IssuedAccessExpiresAt: issuedAccessExpires,
		IssuedRefreshTokenID:  issuedRefreshID,
	}
	if issuedAccessJTI != nil {
		out.IssuedAccessJTI = *issuedAccessJTI
	}
	if len(requestedClaims) > 0 {
		out.RequestedClaims = domain.DecodeClaimsRequest(string(requestedClaims))
	}
	if len(metaBytes) > 0 {
		var meta map[string]any
		if err := json.Unmarshal(metaBytes, &meta); err == nil {
			out.Metadata = meta
		}
	}
	return out, nil
}
