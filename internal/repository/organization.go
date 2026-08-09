package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// UpdateOrganizationOptions contains parameters for updating an organization.
//
// 4.4g.4b re-narrowing: AG-side fields removed (third-party agent issuance,
// user-initiated agents, ID-JAG issuance/consumption + lifetime, consent-per-
// session, agent-issuance rate-limit overrides, agent webhook domain allowlist,
// CBAA poll, reviewer-side ACR floor + freshness, ADC chain-depth override,
// default consent IdP pointer, default max input/session tokens, ITDR
// Cluster 1/2/Phase-1 fields). Agentic settings updates live in identuum-ag.
type UpdateOrganizationOptions struct {
	Name                        *string
	Domain                      *string
	Active                      *bool
	MaxSessionsPerUser          *int
	MFAPolicy                   *string
	AuthPolicy                  *string
	ApiAuthorizationPolicy      *string
	AllowPublicRegistration     *bool
	RequireRegistrationApproval *bool
	ServiceAccountExpiryDays    *int

	M2MAnomalyLimit           *int
	M2MAnomalyWindowSeconds   *int
	RequireStrictReauth       *bool
	Tier                      *domain.Tier
	LocalAdminOnly            *bool
	PasswordComplexityEnabled *bool
	ComplianceContactEmail    *string
}

// OrganizationRepository defines the interface for organization data access
type OrganizationRepository interface {
	// Create creates a new organization
	Create(ctx context.Context, org *domain.Organization) (*domain.Organization, error)

	// CreateWithAdmin atomically creates an organization and its first admin user in a single
	// database transaction. If either write fails, both are rolled back — no dangling org shell.
	CreateWithAdmin(ctx context.Context, org *domain.Organization, adminUser *domain.User) (*domain.Organization, *domain.User, error)

	// GetByID retrieves an organization by ID
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error)

	// GetByDomain retrieves an organization by domain
	GetByDomain(ctx context.Context, domain string) (*domain.Organization, error)

	// GetBySlug retrieves an organization by slug
	GetBySlug(ctx context.Context, slug string) (*domain.Organization, error)

	// Update updates an organization's information
	Update(ctx context.Context, id uuid.UUID, opts UpdateOrganizationOptions) (*domain.Organization, error)

	// Delete soft-deletes an organization and all its users (cascade)
	Delete(ctx context.Context, id uuid.UUID) error

	// Undelete restores a soft-deleted organization and all its users (cascade)
	Undelete(ctx context.Context, id uuid.UUID) error

	// List retrieves organizations with filtering, pagination, and sorting
	List(ctx context.Context, filter OrganizationFilter, pagination Pagination, sort Sort) ([]*domain.Organization, int, error)

	// CountUsers counts the number of users in an organization
	CountUsers(ctx context.Context, id uuid.UUID) (int, error)

	// CountSessions counts the number of active sessions for an organization
	CountSessions(ctx context.Context, id uuid.UUID) (int, error)

	// GetDetails retrieves organization with additional stats (user count, session count)
	GetDetails(ctx context.Context, id uuid.UUID) (*domain.Organization, map[string]int, error)
}

// AdminOrganizationRepository extends OrganizationRepository with admin operations
type AdminOrganizationRepository interface {
	OrganizationRepository

	// GetByIDAdmin retrieves an organization by ID including deleted orgs
	GetByIDAdmin(ctx context.Context, id uuid.UUID) (*domain.Organization, error)

	// ListDeleted retrieves all soft-deleted organizations
	ListDeleted(ctx context.Context, pagination Pagination) ([]*domain.Organization, int, error)

	// ListAll retrieves all organizations including deleted (admin only)
	ListAll(ctx context.Context, filter OrganizationFilter, pagination Pagination, sort Sort) ([]*domain.Organization, int, error)

	// GetDetailsAdmin retrieves organization details including statistics (admin only, includes inactive/deleted)
	GetDetailsAdmin(ctx context.Context, id uuid.UUID) (*domain.Organization, map[string]int, error)

	// HardDelete permanently deletes an organization (admin only, dangerous)
	HardDelete(ctx context.Context, id uuid.UUID) error

	// UpdateID updates the organization ID (admin only, migration/maintenance)
	UpdateID(ctx context.Context, oldID, newID uuid.UUID) error
}
