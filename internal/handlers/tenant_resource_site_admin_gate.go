package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// refuseSiteAdminOnTenantResource is the group gate THE-REMAINING-FOUR
// (2026-08-30) mounts on the route-scoped tenant-resource families — domains,
// protocol-settings, rbac-roles — AFTER their existing
// RequireSiteAdminOrSameOrgAdmin[WithScopesAudit] guard.
//
// That shared guard admits site_admin, and it MUST keep doing so: it has
// legitimate site_admin neighbours the model grants (org lifecycle —
// create/delete/activate — resend-activation, admin-recovery), so it is not
// touched. But AdminPermissionsModel.md forbids site_admin from managing a
// tenant's OWN resources ("site_admin ... cannot manage the resources ...
// belong to that organizations"). This gate refuses site_admin with a clean
// 403 while leaving the underlying guard's other decisions intact —
// org_admin-same-org still 200, org_admin-cross-org still 403 (route-scoped),
// org_user still 403. Measured live before the fix: each of these families
// showed ONLY the site_admin cell wrong (200 where the model says DENY).
//
// This mirrors the clients handler gate (requireClientOrgAdmin);
// service-accounts is fixed at its own service layer (requireOrgAdmin).
func refuseSiteAdminOnTenantResource() gin.HandlerFunc {
	return func(c *gin.Context) {
		if actor, ok := mw.PrincipalFromContext(c); ok && actor != nil && actor.IsSiteAdmin() {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}
