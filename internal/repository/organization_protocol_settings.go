package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ErrOrganizationProtocolSettingsNotFound is the sentinel returned
// when a lookup hits no row. The service layer maps this to the
// system default (both booleans false) so the caller never has to
// distinguish "missing row" from "row that says false".
var ErrOrganizationProtocolSettingsNotFound = errors.New("repository: organization protocol settings not found")

// OrganizationProtocolSettingsRepository persists per-organization
// DCR + SCIM toggles. Upsert is the load-bearing write so a single
// caller can both create and update a row atomically. Delete is
// implicit via the ON DELETE CASCADE on the organizations FK.
type OrganizationProtocolSettingsRepository interface {
	// GetByOrgID returns the row for orgID, or
	// ErrOrganizationProtocolSettingsNotFound when absent.
	GetByOrgID(ctx context.Context, orgID uuid.UUID) (*domain.OrganizationProtocolSettings, error)

	// Upsert inserts (or replaces) the row for the supplied
	// OrganizationID. Returns the persisted row.
	Upsert(ctx context.Context, s *domain.OrganizationProtocolSettings) (*domain.OrganizationProtocolSettings, error)
}
