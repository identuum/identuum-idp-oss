package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// IdentityProviderRepository defines data access for Identity Providers
type IdentityProviderRepository interface {
	// Create persists a new identity provider
	Create(ctx context.Context, provider *domain.IdentityProvider) (*domain.IdentityProvider, error)

	// GetByID retrieves a provider by its unique ID
	GetByID(ctx context.Context, id uuid.UUID) (*domain.IdentityProvider, error)

	// GetByOrgAndType retrieves a provider for an org by its type (e.g. "ldap")
	// If multiple exist (rare for same type), returns the first/highest priority
	GetByOrgAndType(ctx context.Context, orgID uuid.UUID, providerType domain.IdentityProviderType) (*domain.IdentityProvider, error)

	// ListByOrganization retrieves all providers for an organization, ordered by priority
	ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*domain.IdentityProvider, error)

	// Update updates a provider's configuration
	Update(ctx context.Context, provider *domain.IdentityProvider) (*domain.IdentityProvider, error)

	// Delete removes a provider
	Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error
}
