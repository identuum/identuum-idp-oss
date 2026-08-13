package handlers

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AdminPermissionsModel.md via THE-MODEL-IS-LAW order C: an org_admin reaching
// a site_admin account must get 404, not 403.
//
// "Cannot read or modify site_admin accounts" — and the STATUS matters. A 403
// says "this exists and you may not have it"; across a tenant boundary that
// turns the admin API into an existence oracle, letting one tenant's admin
// enumerate ids in another. 404 says nothing.
//
// Measured live before this landed: read → HTTP 403, modify → HTTP 403.
// RULE: MODEL-404-SA-1
func TestModel_OrgAdminSeesSiteAdminAs404(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          domain.SessionScopesForRole(domain.RoleOrgAdmin),
	})
	sa := uuid.MustParse(domain.SiteAdminID)
	seedTenantUser(eng, sa, uuid.MustParse(domain.SystemOrgID), domain.RoleSiteAdmin, "site_admin@system.local")

	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/users/"+sa.String(), nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("org_admin READS the site_admin row → %d, want 404 (a 403 confirms it exists)", rec.Code)
	}
	rec = tenantReq(t, eng, http.MethodPut, "/api/v1/users/"+sa.String(), map[string]any{"name": "hax"})
	if rec.Code != http.StatusNotFound {
		t.Errorf("org_admin MODIFIES the site_admin row → %d, want 404", rec.Code)
	}
}

// The same rule across an ordinary tenant boundary.
// RULE: MODEL-404-CROSSORG-1
func TestModel_OrgAdminSeesOtherOrgUserAs404(t *testing.T) {
	mine, theirs := uuid.New(), uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: mine,
		Role:           domain.RoleOrgAdmin,
		Scope:          domain.SessionScopesForRole(domain.RoleOrgAdmin),
	})
	other := uuid.New()
	seedTenantUser(eng, other, theirs, domain.RoleOrgUser, "someone@other.test")

	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/users/"+other.String(), nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("org_admin reads ANOTHER org's user → %d, want 404", rec.Code)
	}

	// CONTROL: its OWN users still answer 200, or the 404 above would just be
	// a broken read path.
	own := uuid.New()
	seedTenantUser(eng, own, mine, domain.RoleOrgUser, "mine@own.test")
	rec = tenantReq(t, eng, http.MethodGet, "/api/v1/users/"+own.String(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("CONTROL FAILED: org_admin reading its OWN user → %d, want 200", rec.Code)
	}
}
