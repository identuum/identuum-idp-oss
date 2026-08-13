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
// RULE: CLIENT-SCOPE-1
func TestOrgAdminClientScope_BindsOrgAdminAndFreesSiteAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	org := uuid.New()

	cases := []struct {
		name  string
		actor *domain.Principal
		want  *uuid.UUID
	}{
		{"site_admin sees every org", &domain.Principal{
			UserID: uuid.New(), Role: domain.RoleSiteAdmin,
			Scope: domain.SessionScopesForRole(domain.RoleSiteAdmin),
		}, nil},
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
			switch {
			case tc.want == nil:
				if got != nil {
					t.Fatalf("site_admin got org filter %v, want nil (unfiltered)", *got)
				}
			case got == nil:
				t.Fatalf("org-bound actor got NO filter — it would see every tenant's clients")
			case *got != *tc.want:
				t.Fatalf("filter = %v, want %v", *got, *tc.want)
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
