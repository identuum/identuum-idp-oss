package service

import (
	"context"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ORG-ADMIN-SCOPES: the session token MINTS the role-derived scope claim.
// The guards were always tested with hand-written Scope strings; this pins the
// production side — what IssueForSession actually puts on the wire — so the
// two can never diverge again.
func TestIssueForSession_MintsRoleDerivedScopes(t *testing.T) {
	svc, _, _ := newUserTokenSvc(t)

	// org_admin → the full org-bound admin set, verbatim.
	user, session := newUserAndSession(t)
	user.Role = domain.RoleOrgAdmin
	resp, err := svc.IssueForSession(context.Background(), user, session)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, _, _ := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	claims := tok.Claims.(jwt.MapClaims)
	got, _ := claims["scope"].(string)
	if got == "" {
		t.Fatal("org_admin session token carries NO scope claim — every admin guard reads that " +
			"claim, so this org_admin is 403 on its own org (the exact live failure this fixes)")
	}
	if want := strings.Join(domain.OrgAdminSessionScopes, " "); got != want {
		t.Fatalf("org_admin scope claim = %q, want the canonical OrgAdminSessionScopes set %q", got, want)
	}
	for _, must := range []string{"users:create", "clients:read", "m2m:create"} {
		if !strings.Contains(" "+got+" ", " "+must+" ") {
			t.Errorf("scope claim is missing %q", must)
		}
	}

	// org_user → NO scope claim at all (administers nothing).
	user2, session2 := newUserAndSession(t)
	user2.Role = domain.RoleOrgUser
	resp2, err := svc.IssueForSession(context.Background(), user2, session2)
	if err != nil {
		t.Fatalf("issue org_user: %v", err)
	}
	tok2, _, _ := parser.ParseUnverified(resp2.AccessToken, jwt.MapClaims{})
	if sc, ok := tok2.Claims.(jwt.MapClaims)["scope"]; ok {
		t.Fatalf("org_user session token carries scope %v, want NO scope claim", sc)
	}
}
