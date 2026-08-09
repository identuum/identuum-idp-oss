package types

import (
	"time"

	"github.com/google/uuid"
)

// OrgRoleResponse is the public API DTO for a custom org role.
type OrgRoleResponse struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"org_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Scopes      []string  `json:"scopes"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateOrgRoleRequest is the DTO for creating an org role.
type CreateOrgRoleRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=100"`
	Description string `json:"description"`
}

// UpdateOrgRoleRequest is the DTO for updating an org role.
type UpdateOrgRoleRequest struct {
	Name        *string `json:"name,omitempty" binding:"omitempty,min=1,max=100"`
	Description *string `json:"description,omitempty"`
}

// AddScopeRequest is the DTO for adding a scope to a role.
type AddScopeRequest struct {
	ResourceID string `json:"resource_id" binding:"required"`
	ScopeName  string `json:"scope_name" binding:"required"`
}

// AssignRoleRequest is the DTO for assigning a role to a user.
type AssignRoleRequest struct {
	RoleID string `json:"role_id" binding:"required"`
}
