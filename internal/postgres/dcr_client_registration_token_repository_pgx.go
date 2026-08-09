package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxDCRClientRegistrationTokenRepository implements
// repository.DCRClientRegistrationTokenRepository against the
// dcr_client_registration_tokens table.
type PgxDCRClientRegistrationTokenRepository struct {
	db DBTX
}

// NewPgxDCRClientRegistrationTokenRepository constructs the repo.
func NewPgxDCRClientRegistrationTokenRepository(db DBTX) *PgxDCRClientRegistrationTokenRepository {
	return &PgxDCRClientRegistrationTokenRepository{db: db}
}

// Compile-time interface check.
var _ repository.DCRClientRegistrationTokenRepository = (*PgxDCRClientRegistrationTokenRepository)(nil)

// Upsert inserts (or replaces) the RAT row for clientID.
func (r *PgxDCRClientRegistrationTokenRepository) Upsert(ctx context.Context, clientID uuid.UUID, tokenHash string) (*domain.DCRClientRegistrationToken, error) {
	if clientID == uuid.Nil {
		return nil, errors.New("postgres: Upsert requires non-nil client_id")
	}
	if tokenHash == "" {
		return nil, errors.New("postgres: Upsert requires non-empty token_hash")
	}
	const q = `
INSERT INTO dcr_client_registration_tokens (client_id, token_hash, created_at, updated_at)
VALUES ($1, $2, NOW(), NOW())
ON CONFLICT (client_id) DO UPDATE
SET token_hash = EXCLUDED.token_hash,
    updated_at = NOW()
RETURNING client_id, token_hash, created_at, updated_at`
	var row domain.DCRClientRegistrationToken
	if err := r.db.QueryRow(ctx, q, clientID, tokenHash).Scan(
		&row.ClientID, &row.TokenHash, &row.CreatedAt, &row.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("postgres: upsert dcr_client_registration_tokens: %w", err)
	}
	row.TokenHash = ""
	return &row, nil
}

// GetByClientID returns the row identified by clientID with
// TokenHash scrubbed.
func (r *PgxDCRClientRegistrationTokenRepository) GetByClientID(ctx context.Context, clientID uuid.UUID) (*domain.DCRClientRegistrationToken, error) {
	const q = `SELECT client_id, token_hash, created_at, updated_at FROM dcr_client_registration_tokens WHERE client_id = $1`
	var row domain.DCRClientRegistrationToken
	if err := r.db.QueryRow(ctx, q, clientID).Scan(
		&row.ClientID, &row.TokenHash, &row.CreatedAt, &row.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrDCRClientRegistrationTokenNotFound
		}
		return nil, fmt.Errorf("postgres: get dcr_client_registration_tokens: %w", err)
	}
	row.TokenHash = ""
	return &row, nil
}

// LookupByClientIDAndHash performs the authentication compare.
// The hash comparison is done with crypto/subtle.ConstantTimeCompare
// AFTER the DB lookup so we do not leak presence-vs-mismatch via
// timing — both branches read one row and then memcmp two strings.
func (r *PgxDCRClientRegistrationTokenRepository) LookupByClientIDAndHash(ctx context.Context, clientID uuid.UUID, tokenHash string) (*domain.DCRClientRegistrationToken, error) {
	if tokenHash == "" {
		return nil, repository.ErrDCRClientRegistrationTokenNotFound
	}
	const q = `SELECT client_id, token_hash, created_at, updated_at FROM dcr_client_registration_tokens WHERE client_id = $1`
	var row domain.DCRClientRegistrationToken
	if err := r.db.QueryRow(ctx, q, clientID).Scan(
		&row.ClientID, &row.TokenHash, &row.CreatedAt, &row.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrDCRClientRegistrationTokenNotFound
		}
		return nil, fmt.Errorf("postgres: lookup dcr_client_registration_tokens: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(row.TokenHash), []byte(tokenHash)) != 1 {
		return nil, repository.ErrDCRClientRegistrationTokenNotFound
	}
	row.TokenHash = ""
	return &row, nil
}

// DeleteByClientID removes the RAT row for clientID. Idempotent.
func (r *PgxDCRClientRegistrationTokenRepository) DeleteByClientID(ctx context.Context, clientID uuid.UUID) error {
	const q = `DELETE FROM dcr_client_registration_tokens WHERE client_id = $1`
	if _, err := r.db.Exec(ctx, q, clientID); err != nil {
		return fmt.Errorf("postgres: delete dcr_client_registration_tokens: %w", err)
	}
	return nil
}
