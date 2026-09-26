package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// writeOrgAdminGuardError answers the OSS-GUARDS refusals with
// identuum-idp-ce's names and statuses (contracts/AdminPermissionsModel.md
// line 3: the rules are the same in both editions):
//
//	403 {"error":"cannot_change_self"}       the caller's own active state, role, or deletion
//	403 {"error":"cannot_change_own_roles"}  the caller's own RBAC roles
//	403 {"error":"cannot_reset_self"}        the caller's own MFA through the admin reset
//	409 {"error":"last_org_admin"}           the organization's last active org_admin
//
// It reports whether err was one of them and the answer was written.
func writeOrgAdminGuardError(c *gin.Context, err error) bool {
	switch {
	case errors.Is(err, domain.ErrCannotChangeSelf):
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot_change_self"})
	case errors.Is(err, domain.ErrCannotChangeOwnRoles):
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot_change_own_roles"})
	case errors.Is(err, domain.ErrCannotResetSelf):
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot_reset_self"})
	case errors.Is(err, domain.ErrLastOrgAdmin):
		c.JSON(http.StatusConflict, gin.H{"error": "last_org_admin"})
	default:
		return false
	}
	return true
}
