package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ServiceAccountRepository defines data access for service accounts and API keys
type ServiceAccountRepository interface {
	// Service Account Operations
	Create(ctx context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.ServiceAccount, error)
	GetByName(ctx context.Context, orgID uuid.UUID, name string) (*domain.ServiceAccount, error)
	ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*domain.ServiceAccount, error)
	Update(ctx context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error)
	Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error
	UpdateLastUsedAt(ctx context.Context, id uuid.UUID) error
	// UpdateActive flips the service_accounts.active column for an
	// already-existing, non-deleted row in the given organization.
	// Slice identuum-20260530-service-account-disable-enable-backend.
	// Distinct from Update (which touches name/description/role) so
	// disable/enable cannot accidentally clobber unrelated fields, and
	// distinct from Delete (which sets deleted_at). Returns an error
	// when no row matches; callers upstream mask that as ErrForbidden
	// for cross-org callers via the service-layer guards.
	UpdateActive(ctx context.Context, id uuid.UUID, orgID uuid.UUID, active bool) error
}
