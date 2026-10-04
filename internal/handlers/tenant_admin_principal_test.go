package handlers

import (
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// tenantAdminOf is an org_admin of org. D-025 (owner ruling, 2026-10-03): a
// site_admin never acts on a tenant's users, so a test of the user-management
// routes that is not about authority acts as the organization's own admin.
func tenantAdminOf(org uuid.UUID) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Email:          "tenant-admin@example.test",
		Role:           domain.RoleOrgAdmin,
		// What an org_admin session token carries, so the scope guards on
		// the user-management routes admit it as they do in production.
		Scope: domain.SessionScopesForRole(domain.RoleOrgAdmin),
	}
}
