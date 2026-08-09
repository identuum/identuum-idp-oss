package mw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func buildEngineWithGuard(t *testing.T, principal *domain.Principal, route string, guard gin.HandlerFunc) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(InjectPrincipalForTest(principal))
	}
	r.GET(route, guard, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func doGET(r *gin.Engine, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// -------- RequireSiteAdminOrSameOrgAdmin --------

func TestRequireSameOrgAdmin_NoPrincipalReturns401(t *testing.T) {
	r := buildEngineWithGuard(t, nil, "/orgs/:id", RequireSiteAdminOrSameOrgAdmin("id"))
	rec := doGET(r, "/orgs/"+uuid.NewString())
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireSameOrgAdmin_InvalidUUIDReturns400(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}, "/orgs/:id", RequireSiteAdminOrSameOrgAdmin("id"))
	rec := doGET(r, "/orgs/not-a-uuid")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestRequireSameOrgAdmin_SiteAdminAlwaysAllowed(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleSiteAdmin}, "/orgs/:id", RequireSiteAdminOrSameOrgAdmin("id"))
	rec := doGET(r, "/orgs/"+uuid.NewString())
	if rec.Code != http.StatusOK {
		t.Errorf("site_admin status = %d, want 200", rec.Code)
	}
}

func TestRequireSameOrgAdmin_SameOrgAllowed(t *testing.T) {
	org := uuid.New()
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org}, "/orgs/:id", RequireSiteAdminOrSameOrgAdmin("id"))
	rec := doGET(r, "/orgs/"+org.String())
	if rec.Code != http.StatusOK {
		t.Errorf("same-org org_admin status = %d, want 200", rec.Code)
	}
}

func TestRequireSameOrgAdmin_CrossOrgForbidden(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}, "/orgs/:id", RequireSiteAdminOrSameOrgAdmin("id"))
	rec := doGET(r, "/orgs/"+uuid.NewString())
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-org org_admin status = %d, want 403", rec.Code)
	}
}

func TestRequireSameOrgAdmin_OrgUserForbidden(t *testing.T) {
	org := uuid.New()
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgUser, OrganizationID: org}, "/orgs/:id", RequireSiteAdminOrSameOrgAdmin("id"))
	rec := doGET(r, "/orgs/"+org.String())
	if rec.Code != http.StatusForbidden {
		t.Errorf("org_user same-org status = %d, want 403", rec.Code)
	}
}

func TestRequireSameOrgAdmin_NilOrgPrincipalForbidden(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin}, "/orgs/:id", RequireSiteAdminOrSameOrgAdmin("id"))
	rec := doGET(r, "/orgs/"+uuid.NewString())
	if rec.Code != http.StatusForbidden {
		t.Errorf("nil-org org_admin status = %d, want 403", rec.Code)
	}
}

// -------- RequireSiteAdminOrPrincipalOrg --------

func TestRequirePrincipalOrg_NoPrincipal401(t *testing.T) {
	r := buildEngineWithGuard(t, nil, "/me", RequireSiteAdminOrPrincipalOrg())
	rec := doGET(r, "/me")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequirePrincipalOrg_SiteAdminWithoutOrgAllowed(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleSiteAdmin}, "/me", RequireSiteAdminOrPrincipalOrg())
	rec := doGET(r, "/me")
	if rec.Code != http.StatusOK {
		t.Errorf("site_admin without org status = %d, want 200", rec.Code)
	}
}

func TestRequirePrincipalOrg_OrgAdminWithOrgAllowed(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}, "/me", RequireSiteAdminOrPrincipalOrg())
	rec := doGET(r, "/me")
	if rec.Code != http.StatusOK {
		t.Errorf("org_admin with org status = %d, want 200", rec.Code)
	}
}

func TestRequirePrincipalOrg_NoOrgReturns400(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgUser}, "/me", RequireSiteAdminOrPrincipalOrg())
	rec := doGET(r, "/me")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("nil-org non-site-admin status = %d, want 400", rec.Code)
	}
}

// -------- RequireSiteAdminOrSelf --------

func TestRequireSelf_NoPrincipal401(t *testing.T) {
	r := buildEngineWithGuard(t, nil, "/u/:uid", RequireSiteAdminOrSelf(nil, "uid"))
	rec := doGET(r, "/u/"+uuid.NewString())
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireSelf_InvalidUUID400(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgUser, UserID: uuid.New()}, "/u/:uid", RequireSiteAdminOrSelf(nil, "uid"))
	rec := doGET(r, "/u/not-a-uuid")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestRequireSelf_SiteAdminAllowed(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleSiteAdmin, UserID: uuid.New()}, "/u/:uid", RequireSiteAdminOrSelf(nil, "uid"))
	rec := doGET(r, "/u/"+uuid.NewString())
	if rec.Code != http.StatusOK {
		t.Errorf("site_admin status = %d, want 200", rec.Code)
	}
}

func TestRequireSelf_SelfAllowed(t *testing.T) {
	uid := uuid.New()
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgUser, UserID: uid}, "/u/:uid", RequireSiteAdminOrSelf(nil, "uid"))
	rec := doGET(r, "/u/"+uid.String())
	if rec.Code != http.StatusOK {
		t.Errorf("self status = %d, want 200", rec.Code)
	}
}

func TestRequireSelf_OtherUserForbidden(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgUser, UserID: uuid.New()}, "/u/:uid", RequireSiteAdminOrSelf(nil, "uid"))
	rec := doGET(r, "/u/"+uuid.NewString())
	if rec.Code != http.StatusForbidden {
		t.Errorf("other-user status = %d, want 403", rec.Code)
	}
}

// -------- RequireSiteAdminOrSameOrgAdminWithScopes --------

func TestSameOrgAdminScoped_NoPrincipal401(t *testing.T) {
	r := buildEngineWithGuard(t, nil, "/orgs/:id", RequireSiteAdminOrSameOrgAdminWithScopes(nil, "id", "users:read"))
	rec := doGET(r, "/orgs/"+uuid.NewString())
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestSameOrgAdminScoped_InvalidUUID400(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New(), Scope: "users:read"}, "/orgs/:id", RequireSiteAdminOrSameOrgAdminWithScopes(nil, "id", "users:read"))
	rec := doGET(r, "/orgs/not-a-uuid")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestSameOrgAdminScoped_SiteAdminBypassesScope(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleSiteAdmin}, "/orgs/:id", RequireSiteAdminOrSameOrgAdminWithScopes(nil, "id", "users:read"))
	rec := doGET(r, "/orgs/"+uuid.NewString())
	if rec.Code != http.StatusOK {
		t.Errorf("site_admin status = %d, want 200 (scope bypass)", rec.Code)
	}
}

func TestSameOrgAdminScoped_SameOrgWithScopeAllowed(t *testing.T) {
	org := uuid.New()
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, Scope: "users:read"}, "/orgs/:id", RequireSiteAdminOrSameOrgAdminWithScopes(nil, "id", "users:read"))
	rec := doGET(r, "/orgs/"+org.String())
	if rec.Code != http.StatusOK {
		t.Errorf("same-org+scope status = %d, want 200", rec.Code)
	}
}

func TestSameOrgAdminScoped_SameOrgMissingScopeForbidden(t *testing.T) {
	org := uuid.New()
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, Scope: "wrong:scope"}, "/orgs/:id", RequireSiteAdminOrSameOrgAdminWithScopes(nil, "id", "users:read"))
	rec := doGET(r, "/orgs/"+org.String())
	if rec.Code != http.StatusForbidden {
		t.Errorf("missing-scope status = %d, want 403", rec.Code)
	}
}

func TestSameOrgAdminScoped_CrossOrgWithScopeForbidden(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New(), Scope: "users:read"}, "/orgs/:id", RequireSiteAdminOrSameOrgAdminWithScopes(nil, "id", "users:read"))
	rec := doGET(r, "/orgs/"+uuid.NewString())
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-org status = %d, want 403", rec.Code)
	}
}

func TestSameOrgAdminScoped_OrgUserForbidden(t *testing.T) {
	org := uuid.New()
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgUser, OrganizationID: org, Scope: "users:read"}, "/orgs/:id", RequireSiteAdminOrSameOrgAdminWithScopes(nil, "id", "users:read"))
	rec := doGET(r, "/orgs/"+org.String())
	if rec.Code != http.StatusForbidden {
		t.Errorf("org_user status = %d, want 403", rec.Code)
	}
}

// -------- RequireSiteAdminOrOrgAdminWithScopes --------

func TestOrgAdminScoped_NoPrincipal401(t *testing.T) {
	r := buildEngineWithGuard(t, nil, "/users", RequireSiteAdminOrOrgAdminWithScopes("users:read"))
	rec := doGET(r, "/users")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestOrgAdminScoped_SiteAdminBypassesScope(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleSiteAdmin}, "/users", RequireSiteAdminOrOrgAdminWithScopes("users:read"))
	rec := doGET(r, "/users")
	if rec.Code != http.StatusOK {
		t.Errorf("site_admin status = %d, want 200", rec.Code)
	}
}

func TestOrgAdminScoped_OrgAdminWithScopeAllowed(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New(), Scope: "users:read"}, "/users", RequireSiteAdminOrOrgAdminWithScopes("users:read"))
	rec := doGET(r, "/users")
	if rec.Code != http.StatusOK {
		t.Errorf("org_admin+scope status = %d, want 200", rec.Code)
	}
}

func TestOrgAdminScoped_OrgAdminMissingScopeForbidden(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New(), Scope: "other:scope"}, "/users", RequireSiteAdminOrOrgAdminWithScopes("users:read"))
	rec := doGET(r, "/users")
	if rec.Code != http.StatusForbidden {
		t.Errorf("missing-scope status = %d, want 403", rec.Code)
	}
}

func TestOrgAdminScoped_OrgAdminNilOrgForbidden(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, Scope: "users:read"}, "/users", RequireSiteAdminOrOrgAdminWithScopes("users:read"))
	rec := doGET(r, "/users")
	if rec.Code != http.StatusForbidden {
		t.Errorf("nil-org status = %d, want 403", rec.Code)
	}
}

func TestOrgAdminScoped_OrgUserForbidden(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgUser, OrganizationID: uuid.New(), Scope: "users:read"}, "/users", RequireSiteAdminOrOrgAdminWithScopes("users:read"))
	rec := doGET(r, "/users")
	if rec.Code != http.StatusForbidden {
		t.Errorf("org_user status = %d, want 403", rec.Code)
	}
}

// -------- RequireSiteAdminOrSelfOrSameOrgAdminWithScopes --------

func TestSelfOrSameOrgScoped_NoPrincipal401(t *testing.T) {
	r := buildEngineWithGuard(t, nil, "/orgs/:id/u/:uid", RequireSiteAdminOrSelfOrSameOrgAdminWithScopes("id", "uid", "users:read"))
	rec := doGET(r, "/orgs/"+uuid.NewString()+"/u/"+uuid.NewString())
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestSelfOrSameOrgScoped_SelfBranchAllowed(t *testing.T) {
	uid := uuid.New()
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgUser, UserID: uid}, "/orgs/:id/u/:uid", RequireSiteAdminOrSelfOrSameOrgAdminWithScopes("id", "uid", "users:read"))
	rec := doGET(r, "/orgs/"+uuid.NewString()+"/u/"+uid.String())
	if rec.Code != http.StatusOK {
		t.Errorf("self status = %d, want 200", rec.Code)
	}
}

func TestSelfOrSameOrgScoped_SameOrgAdminWithScopeAllowed(t *testing.T) {
	org := uuid.New()
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New(), Scope: "users:read"}, "/orgs/:id/u/:uid", RequireSiteAdminOrSelfOrSameOrgAdminWithScopes("id", "uid", "users:read"))
	rec := doGET(r, "/orgs/"+org.String()+"/u/"+uuid.NewString())
	if rec.Code != http.StatusOK {
		t.Errorf("same-org+scope status = %d, want 200", rec.Code)
	}
}

func TestSelfOrSameOrgScoped_SameOrgAdminMissingScopeForbidden(t *testing.T) {
	org := uuid.New()
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New(), Scope: ""}, "/orgs/:id/u/:uid", RequireSiteAdminOrSelfOrSameOrgAdminWithScopes("id", "uid", "users:read"))
	rec := doGET(r, "/orgs/"+org.String()+"/u/"+uuid.NewString())
	if rec.Code != http.StatusForbidden {
		t.Errorf("missing-scope status = %d, want 403", rec.Code)
	}
}

func TestSelfOrSameOrgScoped_OrgUserOtherUserForbidden(t *testing.T) {
	r := buildEngineWithGuard(t, &domain.Principal{Role: domain.RoleOrgUser, OrganizationID: uuid.New(), UserID: uuid.New()}, "/orgs/:id/u/:uid", RequireSiteAdminOrSelfOrSameOrgAdminWithScopes("id", "uid", "users:read"))
	rec := doGET(r, "/orgs/"+uuid.NewString()+"/u/"+uuid.NewString())
	if rec.Code != http.StatusForbidden {
		t.Errorf("org_user-other-user status = %d, want 403", rec.Code)
	}
}
