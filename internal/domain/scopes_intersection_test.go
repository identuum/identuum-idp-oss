package domain

import (
	"strings"
	"testing"
)

// THE-CONSENTED-SCOPE: consent NARROWS, never grants beyond the role.
func TestIntersectConsentedScope(t *testing.T) {
	cases := []struct {
		name      string
		consented string
		role      UserRole
		want      string
	}{
		{"org_user keeps identity scopes only", "openid profile email offline_access", RoleOrgUser, "openid profile email offline_access"},
		{"org_user: consented admin scope never lands", "openid clients:read users:read", RoleOrgUser, "openid"},
		{"org_admin: consented admin scope lands", "openid clients:read", RoleOrgAdmin, "openid clients:read"},
		{"org_admin: unconsented admin scopes never land", "openid", RoleOrgAdmin, "openid"},
		{"org_admin: site-only scope never lands", "openid keys:read orgs:create", RoleOrgAdmin, "openid"},
		{"site_admin has no role scopes to lend", "openid clients:read", RoleSiteAdmin, "openid"},
		{"unknown scope dropped", "openid no:such", RoleOrgUser, "openid"},
		{"order preserved, duplicates collapse", "email openid email profile", RoleOrgUser, "email openid profile"},
		{"empty consent", "", RoleOrgAdmin, ""},
		{"whitespace only", "  \t ", RoleOrgAdmin, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IntersectConsentedScope(tc.consented, tc.role); got != tc.want {
				t.Errorf("IntersectConsentedScope(%q, %s) = %q, want %q", tc.consented, tc.role, got, tc.want)
			}
		})
	}
}

// The permitted set is exactly identity scopes ∪ role session scopes — so
// every org_admin session scope is reachable by consent and nothing else is.
func TestPermittedScopesForRole(t *testing.T) {
	admin := PermittedScopesForRole(RoleOrgAdmin)
	if len(admin) != len(OIDCIdentityScopes)+len(OrgAdminSessionScopes) {
		t.Fatalf("org_admin permitted = %d scopes, want %d identity + %d session", len(admin), len(OIDCIdentityScopes), len(OrgAdminSessionScopes))
	}
	joined := " " + strings.Join(admin, " ") + " "
	for _, s := range OrgAdminSessionScopes {
		if !strings.Contains(joined, " "+s+" ") {
			t.Errorf("org_admin permitted set lacks session scope %q", s)
		}
	}
	for _, role := range []UserRole{RoleOrgUser, RoleSiteAdmin} {
		got := PermittedScopesForRole(role)
		if strings.Join(got, " ") != strings.Join(OIDCIdentityScopes, " ") {
			t.Errorf("%s permitted = %v, want identity scopes only", role, got)
		}
	}
}

// Introspection companion: the live set may revoke but never widen.
func TestNarrowScopeToLive(t *testing.T) {
	cases := []struct {
		name  string
		token string
		live  []string
		want  string
	}{
		{"identity scopes survive an empty live set", "openid profile clients:read", nil, "openid profile"},
		{"live grants beyond the token never appear", "openid clients:read", []string{"clients:read", "users:read", "billing:read"}, "openid clients:read"},
		{"revoked role scope disappears", "openid clients:read users:read", []string{"users:read"}, "openid users:read"},
		{"empty token stays empty", "", []string{"users:read"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NarrowScopeToLive(tc.token, tc.live); got != tc.want {
				t.Errorf("NarrowScopeToLive(%q, %v) = %q, want %q", tc.token, tc.live, got, tc.want)
			}
		})
	}
}
