package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// PgxDCRRegistrationLimitRepository keeps the limits an initial access token
// set on the client it registered (dcr_client_registration_limits, migration
// 0049).
type PgxDCRRegistrationLimitRepository struct {
	db DBTX
}

// NewPgxDCRRegistrationLimitRepository constructs the repository.
func NewPgxDCRRegistrationLimitRepository(db DBTX) *PgxDCRRegistrationLimitRepository {
	return &PgxDCRRegistrationLimitRepository{db: db}
}

// SaveRegistrationLimits records the limits for the client; an empty list is
// stored as NULL (no limit of that kind).
func (r *PgxDCRRegistrationLimitRepository) SaveRegistrationLimits(ctx context.Context, clientID uuid.UUID, l domain.DCRRegistrationLimits) error {
	const q = `
INSERT INTO dcr_client_registration_limits (client_id, allowed_grant_types, allowed_token_endpoint_auth_methods)
VALUES ($1, $2, $3)
ON CONFLICT (client_id) DO UPDATE
SET allowed_grant_types = EXCLUDED.allowed_grant_types,
    allowed_token_endpoint_auth_methods = EXCLUDED.allowed_token_endpoint_auth_methods
`
	_, err := r.db.Exec(ctx, q, clientID, nullableTextArray(l.AllowedGrantTypes), nullableTextArray(l.AllowedTokenEndpointAuthMethods))
	return err
}

// RegistrationLimits returns the client's limits, or nil when it was
// registered without any.
func (r *PgxDCRRegistrationLimitRepository) RegistrationLimits(ctx context.Context, clientID uuid.UUID) (*domain.DCRRegistrationLimits, error) {
	const q = `
SELECT allowed_grant_types, allowed_token_endpoint_auth_methods
FROM dcr_client_registration_limits
WHERE client_id = $1
`
	var l domain.DCRRegistrationLimits
	if err := r.db.QueryRow(ctx, q, clientID).Scan(&l.AllowedGrantTypes, &l.AllowedTokenEndpointAuthMethods); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &l, nil
}

// nullableTextArray stores an empty list as NULL.
func nullableTextArray(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	return v
}
