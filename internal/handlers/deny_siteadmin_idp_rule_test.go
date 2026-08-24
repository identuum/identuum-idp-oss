package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// denySiteAdminTenantIDP enforces the admin model: site_admin is infrastructure
// authority, not a tenant super-admin, so it is FORBIDDEN (403) from managing a
// tenant's identity providers; an org_admin is not denied.
// RULE: SA-TENANT-IDP-1
func TestDenySiteAdminTenantIDP(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	run := func(role domain.UserRole) (denied bool, code int) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		mw.SetPrincipal(c, &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: role})
		return denySiteAdminTenantIDP(c), w.Code
	}

	// site_admin -> denied with 403.
	if denied, code := run(domain.RoleSiteAdmin); !denied || code != http.StatusForbidden {
		t.Errorf("site_admin must be denied tenant IDP management (403), got denied=%v code=%d", denied, code)
	}
	// org_admin -> not denied.
	if denied, _ := run(domain.RoleOrgAdmin); denied {
		t.Errorf("org_admin must NOT be denied tenant IDP management")
	}
}
