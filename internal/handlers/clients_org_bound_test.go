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

// ORG-ADMIN-SCOPES, clients surface. ClientsHandlerDeps takes the CONCRETE
// *service.ClientService, so a handler-level fake is not available; the org
// binding is therefore pinned at its own seam — orgAdminClientScope, the single
// function every clients handler routes its org decision through (list filter,
// get/update/rotate ownership check, create pin).
//
// This is the ORG-BOUND half of the ruling. The scope half is pinned by
// TestSessionScopeTrio_* and TestIssueForSession_MintsRoleDerivedScopes.
//
// THE-CLIENTS-GUARD (2026-08-30): orgAdminClientScope NO LONGER frees
// site_admin with a nil (unscoped) filter — that let the superuser read EVERY
// tenant's clients, which AdminPermissionsModel.md forbids. site_admin is now
// confined to its own (System) organization here AND refused outright with a
// 403 by requireClientOrgAdmin at each handler; NO actor ever yields a nil
// filter now.
// RULE: CLIENT-SCOPE-1
func TestOrgAdminClientScope_BindsOrgAdminAndConfinesSiteAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	org := uuid.New()
	sysOrg := uuid.New()

	cases := []struct {
		name  string
		actor *domain.Principal
		want  *uuid.UUID
	}{
		{"site_admin is confined to its own org, NEVER freed to nil", &domain.Principal{
			UserID: uuid.New(), OrganizationID: sysOrg, Role: domain.RoleSiteAdmin,
			Scope: domain.SessionScopesForRole(domain.RoleSiteAdmin),
		}, &sysOrg},
		{"org_admin is confined to its own org", &domain.Principal{
			UserID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgAdmin,
			Scope: domain.SessionScopesForRole(domain.RoleOrgAdmin),
		}, &org},
		{"a nil principal is confined, not freed", nil, &uuid.Nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/clients", nil)
			if tc.actor != nil {
				mw.InjectPrincipalForTest(tc.actor)(c)
			}
			got := orgAdminClientScope(c)
			// The load-bearing invariant: NO actor is ever freed to a nil
			// (unscoped) filter — that was the site_admin cross-tenant hole.
			if got == nil {
				t.Fatalf("%s got NO filter — it would see every tenant's clients", tc.name)
			}
			if *got != *tc.want {
				t.Fatalf("filter = %v, want %v", *got, *tc.want)
			}
		})
	}
}

// TestRequireClientOrgAdmin_RefusesSiteAdminAndOrgUser pins the handler gate:
// the tenant clients surface answers to the org's own org_admin ONLY. This is
// the teeth for THE-CLIENTS-GUARD's site_admin refusal (measured live:
// site_admin had listed all 10 orgs' clients before this slice).
func TestRequireClientOrgAdmin_RefusesSiteAdminAndOrgUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for name, tc := range map[string]struct {
		actor *domain.Principal
		allow bool
	}{
		"site_admin refused": {&domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleSiteAdmin}, false},
		"org_user refused":   {&domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser}, false},
		"nil actor refused":  {nil, false},
		"org_admin admitted": {&domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgAdmin}, true},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/clients", nil)
			if tc.actor != nil {
				mw.InjectPrincipalForTest(tc.actor)(c)
			}
			ok := requireClientOrgAdmin(c)
			if ok != tc.allow {
				t.Fatalf("requireClientOrgAdmin = %v, want %v", ok, tc.allow)
			}
			if !tc.allow && rec.Code != http.StatusForbidden {
				t.Fatalf("refused actor got %d, want 403", rec.Code)
			}
		})
	}
}

// The clients:* scopes must be in the org_admin session set, or the guards
// mounted on the clients routes refuse every org_admin regardless of the
// org-binding above.
func TestOrgAdminSessionScopes_CoverTheClientsSurface(t *testing.T) {
	held := map[string]bool{}
	for _, s := range domain.OrgAdminSessionScopes {
		held[s] = true
	}
	for _, want := range []string{
		domain.ScopeClientsRead, domain.ScopeClientsCreate,
		domain.ScopeClientsUpdate, domain.ScopeClientsDelete,
	} {
		if !held[want] {
			t.Errorf("OrgAdminSessionScopes is missing %q — the clients routes would 403 every org_admin", want)
		}
	}
	// CONTROL: site-only authority must NOT leak into the org_admin set.
	for _, forbidden := range []string{
		domain.ScopeOrgsCreate, domain.ScopeOrgsDelete, domain.ScopeKeysRotate,
		domain.ScopeBackupsRestore, domain.ScopeSystemConfigUpdate, domain.ScopeAuditExport,
	} {
		if held[forbidden] {
			t.Errorf("OrgAdminSessionScopes wrongly grants site-scope %q", forbidden)
		}
	}
	// CONTROL: every scope in the set must be a REGISTERED scope name.
	for _, s := range domain.OrgAdminSessionScopes {
		if !domain.IsKnownScope(s) {
			t.Errorf("OrgAdminSessionScopes contains unregistered scope %q", s)
		}
	}
}
