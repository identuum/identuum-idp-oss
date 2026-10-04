package mw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// roleSeenBy returns the role the guards downstream of BearerPrincipal see for
// the principal the verifier returns, or "" when none was planted.
func roleSeenBy(t *testing.T, p *domain.Principal) domain.UserRole {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BearerPrincipal(nil, &stubVerifier{principal: p}, nil, nil))
	var seen domain.UserRole
	r.GET("/probe", func(c *gin.Context) {
		if got, ok := PrincipalFromContext(c); ok {
			seen = got.Role
		}
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer some-token-value")
	r.ServeHTTP(httptest.NewRecorder(), req)
	return seen
}

// A scope narrows a role. An org_admin token that carries none of the org-admin
// scopes (an identity-only token) holds no administrative authority: the routes
// that check the role alone must see a plain member, as they would for any
// org_user.
func TestBearerPrincipal_OrgAdminWithoutAnAdminScopeIsAPlainMember(t *testing.T) {
	user, org := uuid.New(), uuid.New()

	identityOnly := &domain.Principal{Role: domain.RoleOrgAdmin, ActorType: "user", UserID: user, OrganizationID: org, Scope: "openid profile email"}
	if got := roleSeenBy(t, identityOnly); got != domain.RoleOrgUser {
		t.Errorf("org_admin with an identity-only scope: role = %q, want org_user", got)
	}

	noScope := &domain.Principal{Role: domain.RoleOrgAdmin, ActorType: "user", UserID: user, OrganizationID: org}
	if got := roleSeenBy(t, noScope); got != domain.RoleOrgUser {
		t.Errorf("org_admin with no scope: role = %q, want org_user", got)
	}

	console := &domain.Principal{Role: domain.RoleOrgAdmin, ActorType: "user", UserID: user, OrganizationID: org, Scope: domain.SessionScopesForRole(domain.RoleOrgAdmin)}
	if got := roleSeenBy(t, console); got != domain.RoleOrgAdmin {
		t.Errorf("org_admin console session token: role = %q, want org_admin", got)
	}

	oneScope := &domain.Principal{Role: domain.RoleOrgAdmin, ActorType: "user", UserID: user, OrganizationID: org, Scope: "openid users:read"}
	if got := roleSeenBy(t, oneScope); got != domain.RoleOrgAdmin {
		t.Errorf("org_admin holding one org-admin scope: role = %q, want org_admin", got)
	}

	// site_admin is infrastructure authority and carries no scopes by design.
	site := &domain.Principal{Role: domain.RoleSiteAdmin, ActorType: "user", UserID: user}
	if got := roleSeenBy(t, site); got != domain.RoleSiteAdmin {
		t.Errorf("site_admin console token: role = %q, want site_admin", got)
	}
}
