package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OrgRoleRepository governs database operations for org-defined custom roles,
// their scope assignments, and user-role bindings.
type OrgRoleRepository interface {
	// Role CRUD
	Create(ctx context.Context, role *domain.OrgRole) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.OrgRole, error)
	ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*domain.OrgRole, error)
	Update(ctx context.Context, role *domain.OrgRole) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Scope management
	AddScope(ctx context.Context, roleID, resourceID uuid.UUID, scopeName string) error
	RemoveScope(ctx context.Context, roleID uuid.UUID, scopeName string) error

	// User-role bindings
	AssignRoleToUser(ctx context.Context, userID, roleID, assignedBy uuid.UUID) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error
	ListRolesForUser(ctx context.Context, userID uuid.UUID) ([]*domain.OrgRole, error)

	// ListUserIDsForRole returns the user IDs of every user currently assigned to a role.
	// Used by RemoveScope / DeleteRole to fire synchronous session revocation on privilege
	// demotion per §2.8 RBAC.
	ListUserIDsForRole(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error)

	// GetScopesForUser is the hot path: returns the distinct union of all scope_name
	// values from org_role_scopes for all roles assigned to the given user.
	// When resourceID is non-nil, only scopes linked to that API Resource are returned
	// (audience filtering: a user requesting api://billing only gets billing:* scopes).
	GetScopesForUser(ctx context.Context, userID uuid.UUID, resourceID *uuid.UUID) ([]string, error)
}
