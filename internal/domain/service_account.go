package domain

import (
	"time"

	"github.com/google/uuid"
)

// AllowedServiceAccountRoles defines the complete set of roles that may be
// assigned to a ServiceAccount. site_admin is intentionally excluded — SA tokens
// are always scoped to a single organization and must never carry cross-tenant authority.
// Add or remove entries here to centrally govern SA role policy.
var AllowedServiceAccountRoles = map[UserRole]struct{}{
	RoleOrgUser:  {},
	RoleOrgAdmin: {},
}

// IsAllowedSARole reports whether the given role is valid for a ServiceAccount.
func IsAllowedSARole(r UserRole) bool {
	_, ok := AllowedServiceAccountRoles[r]
	return ok
}

// ServiceAccount represents a non-human identity for M2M authentication.
// SPIFFE-origin annotations are part of the commercial overlay and are
// not modeled in the OSS shape.
type ServiceAccount struct {
	CreatedAt      time.Time
	UpdatedAt      time.Time
	ExpiresAt      *time.Time
	Name           string
	Description    string
	Role           UserRole
	ID             uuid.UUID
	OrganizationID uuid.UUID
	OwnerUserID    *uuid.UUID
	Active         bool
}

// ServiceAccountWithSecret represents a service account with its associated client credentials (creation only)
type ServiceAccountWithSecret struct {
	ServiceAccount
	ClientID     string
	ClientSecret string
}
