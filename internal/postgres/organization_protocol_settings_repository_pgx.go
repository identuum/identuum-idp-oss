package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxOrganizationProtocolSettingsRepository implements
// repository.OrganizationProtocolSettingsRepository against the
// organization_protocol_settings table.
type PgxOrganizationProtocolSettingsRepository struct {
	db DBTX
}

// NewPgxOrganizationProtocolSettingsRepository constructs the repo.
func NewPgxOrganizationProtocolSettingsRepository(db DBTX) *PgxOrganizationProtocolSettingsRepository {
	return &PgxOrganizationProtocolSettingsRepository{db: db}
}

// Compile-time interface check.
var _ repository.OrganizationProtocolSettingsRepository = (*PgxOrganizationProtocolSettingsRepository)(nil)

// GetByOrgID returns the settings row for orgID or
// ErrOrganizationProtocolSettingsNotFound when absent.
func (r *PgxOrganizationProtocolSettingsRepository) GetByOrgID(ctx context.Context, orgID uuid.UUID) (*domain.OrganizationProtocolSettings, error) {
	const q = `
SELECT organization_id, dcr_enabled, scim_enabled, created_at, updated_at
FROM   organization_protocol_settings
WHERE  organization_id = $1`
	var s domain.OrganizationProtocolSettings
	if err := r.db.QueryRow(ctx, q, orgID).Scan(
		&s.OrganizationID, &s.DCREnabled, &s.SCIMEnabled, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrOrganizationProtocolSettingsNotFound
		}
		return nil, fmt.Errorf("postgres: get organization_protocol_settings: %w", err)
	}
	return &s, nil
}

// Upsert inserts or replaces the row for the supplied
// OrganizationID. A nil-OrganizationID is a programmer error and
// is rejected early.
func (r *PgxOrganizationProtocolSettingsRepository) Upsert(ctx context.Context, s *domain.OrganizationProtocolSettings) (*domain.OrganizationProtocolSettings, error) {
	if s == nil {
		return nil, errors.New("postgres: nil OrganizationProtocolSettings")
	}
	if s.OrganizationID == uuid.Nil {
		return nil, errors.New("postgres: OrganizationProtocolSettings requires non-nil OrganizationID")
	}
	const q = `
INSERT INTO organization_protocol_settings (organization_id, dcr_enabled, scim_enabled, created_at, updated_at)
VALUES ($1, $2, $3, NOW(), NOW())
ON CONFLICT (organization_id) DO UPDATE
SET dcr_enabled = EXCLUDED.dcr_enabled,
    scim_enabled = EXCLUDED.scim_enabled,
    updated_at  = NOW()
RETURNING organization_id, dcr_enabled, scim_enabled, created_at, updated_at`
	var out domain.OrganizationProtocolSettings
	if err := r.db.QueryRow(ctx, q,
		s.OrganizationID, s.DCREnabled, s.SCIMEnabled,
	).Scan(&out.OrganizationID, &out.DCREnabled, &out.SCIMEnabled, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return nil, fmt.Errorf("postgres: upsert organization_protocol_settings: %w", err)
	}
	return &out, nil
}
