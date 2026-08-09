package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// UpdateUserOptions contains fields for updating a user
type UpdateUserOptions struct {
	Email            *string
	Password         *string
	Name             *string
	Role             *domain.UserRole
	Banned           *bool
	EmailVerified    *bool
	MFAEnabled       *bool
	MFASecret        *string
	MFARecoveryCodes []string
	ExternalID       *string
	AuthSource       *string

	LastLoginAt *time.Time

	// Compliance Fields
	RequiresPasswordChange   *bool
	OIDCLinked               *bool
	OIDCIssuer               *string
	ActivationTokenExpiresAt *time.Time

	// Security: single-use activation token burn.
	// Set to a non-nil pointer to write the hash; set to pointer-to-empty-string to clear it.
	ActivationTokenHash *string

	// Security: single-use verification token burn.
	// Set to a non-nil pointer to write the hash; set to pointer-to-empty-string to clear it.
	VerificationTokenHash *string

	// RequireEmailVerifiedFalse, when true, appends `AND email_verified = false`
	// to the UPDATE's WHERE clause so concurrent callers race at the SQL layer —
	// only one writer wins. Used by ConsumeInvitationToken (§1.15) to make
	// invitation consumption atomic against double-submit / replay.
	RequireEmailVerifiedFalse bool
}

// ListUserOptions contains options for listing users
type ListUserOptions struct {
	Filter     UserFilter
	Pagination Pagination
	Sort       Sort
}

// UserRepository defines the interface for user data access
// This is the NEW pattern - repository interface that will be implemented by PostgreSQL
type UserRepository interface {
	// Create creates a new user
	Create(ctx context.Context, user *domain.User) (*domain.User, error)

	// GetByID retrieves a user by ID
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)

	// FindUsersByEmail retrieves all users with the given email across all organizations.
	// Used for login resolution to detect ambiguity.
	FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error)

	// GetByEmailAndOrgID retrieves a user by email within a specific organization
	GetByEmailAndOrgID(ctx context.Context, orgID uuid.UUID, email string) (*domain.User, error)

	// GetByExternalID retrieves a user by their external ID within a specific organization
	// Used for IDP lookups (LDAP/OIDC)
	GetByExternalID(ctx context.Context, orgID uuid.UUID, externalID string) (*domain.User, error)

	// GetByIDWithOrg retrieves a user by ID with organization details
	GetByIDWithOrg(ctx context.Context, id uuid.UUID) (*domain.User, error)

	// Update updates a user's information
	// Only non-nil fields in the update struct will be updated
	Update(ctx context.Context, id uuid.UUID, orgID uuid.UUID, opts UpdateUserOptions) (*domain.User, error)

	// ConsumeRecoveryCode atomically removes a SINGLE MFA recovery code (by its
	// stored SHA-256 hash) only while it is still present; a concurrent redeemer
	// that already removed it gets ok=false — the same code cannot be redeemed
	// twice (P0-11).
	ConsumeRecoveryCode(ctx context.Context, id uuid.UUID, codeHash string) (*domain.User, bool, error)

	// Delete soft-deletes a user (sets deleted_at = NOW())
	Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error

	// Undelete restores a soft-deleted user (sets deleted_at = NULL)
	Undelete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error

	// List retrieves users with filtering, pagination, and sorting
	List(ctx context.Context, opts ListUserOptions) ([]*domain.User, int, error)

	// ListByOrganization retrieves users for a specific organization
	ListByOrganization(ctx context.Context, orgID uuid.UUID, opts ListUserOptions) ([]*domain.User, int, error)

	// UpdateLastLogin updates the last login timestamp for a user
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error

	// CountByOrganization counts users in an organization (for admin stats)
	CountByOrganization(ctx context.Context, orgID uuid.UUID) (int, error)

	// CountOrgAdminsByOrganization counts active (non-deleted, non-banned) org_admin users
	// in an organization. Used to enforce the last-admin invariant.
	CountOrgAdminsByOrganization(ctx context.Context, orgID uuid.UUID) (int, error)

	// CountOrgAdminsByOrganizations counts active org_admin users for a batch of org IDs.
	// Returns a map of orgID -> count. Used by the org list handler to avoid N+1 queries.
	CountOrgAdminsByOrganizations(ctx context.Context, orgIDs []uuid.UUID) (map[uuid.UUID]int, error)

	// CountVerifiedOrgAdminsByOrganization counts org_admin users with email_verified=true
	// for a single org. Zero means no blocking admin exists → can_assign_admin=true when
	// CountOrgAdminsByOrganization > 0 (expired-pending invitation state).
	CountVerifiedOrgAdminsByOrganization(ctx context.Context, orgID uuid.UUID) (int, error)

	// CountVerifiedOrgAdminsByOrganizations is the batch version of
	// CountVerifiedOrgAdminsByOrganization for use in list endpoints.
	CountVerifiedOrgAdminsByOrganizations(ctx context.Context, orgIDs []uuid.UUID) (map[uuid.UUID]int, error)

	// VerifyPassword verifies a password against a stored hash
	VerifyPassword(ctx context.Context, password, hash string) error

	// HashPassword hashes a password using argon2id
	HashPassword(password string) (string, error)

	// GetUserOrganization retrieves the organization for a user
	GetUserOrganization(ctx context.Context, userID uuid.UUID) (*domain.Organization, error)

	// UpdateOrganizationID updates the organization a user belongs to (migration/admin use)
	UpdateOrganizationID(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error
}

// AdminUserRepository extends UserRepository with admin-specific operations
// These operations can access deleted records and have elevated privileges
type AdminUserRepository interface {
	UserRepository

	// GetByIDAdmin retrieves a user by ID including deleted users
	GetByIDAdmin(ctx context.Context, id uuid.UUID) (*domain.User, error)

	// GetByEmailAdmin retrieves a user by email including deleted users
	GetByEmailAdmin(ctx context.Context, email string) (*domain.User, error)

	// ListDeleted retrieves all soft-deleted users
	ListDeleted(ctx context.Context, pagination Pagination) ([]*domain.User, int, error)

	// ListAll retrieves all users including deleted (admin only)
	ListAll(ctx context.Context, opts ListUserOptions) ([]*domain.User, int, error)

	// HardDelete permanently deletes a user from the database (admin only, dangerous)
	HardDelete(ctx context.Context, id uuid.UUID) error
}
