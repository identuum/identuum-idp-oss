package handlers

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ORG-ADMIN-SCOPES failing-first trio (owner ruling, THE-TENANT-ADMIN order B).
//
// The tenant-scoped tests in this package hand the principal a HAND-WRITTEN
// Scope string — proving the guards and services work when scopes are present.
// Production never minted any: a password-login session token carried no scope
// claim, so a real org_admin failed the same guard these tests passed. That is
// how "tested" and "works" diverged (pinned live as HANDS-ON-TODAY authz.6).
//
// This trio therefore derives the principal's Scope from
// domain.SessionScopesForRole — the SAME function (*UserTokenService).
// IssueForSession now mints into the token — so what is asserted here is what
// a real session token carries, not what a test wishes it carried.
//
// RED (before the minting existed): domain.SessionScopesForRole is undefined /
// returns nothing for org_admin, and the own-org create is 403 exactly as
// observed live.
func TestSessionScopeTrio_OrgAdminOwnOrgCreate201(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          domain.SessionScopesForRole(domain.RoleOrgAdmin),
	})
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users", map[string]any{
		"email":    "trio-user@tenant.test",
		"password": "Trio-Passw0rd-1!",
		"role":     "org_user",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("own-org create-user = %d, want 201 — a session-token org_admin still cannot "+
			"administer its own org (body=%q)", rec.Code, rec.Body.String())
	}
}

func TestSessionScopeTrio_OrgAdminOtherOrg403(t *testing.T) {
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgAdmin,
		Scope:          domain.SessionScopesForRole(domain.RoleOrgAdmin),
	})
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users", map[string]any{
		"organization_id": uuid.NewString(), // explicitly someone ELSE's org
		"email":           "trio-cross@tenant.test",
		"password":        "Trio-Passw0rd-1!",
		"role":            "org_user",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-org create-user = %d, want 403 — the role-derived scopes must stay "+
			"ORG-BOUND (body=%q)", rec.Code, rec.Body.String())
	}
}

func TestSessionScopeTrio_OrgUser403(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgUser,
		// The REAL derivation: an org_user's session token carries no scopes.
		Scope: domain.SessionScopesForRole(domain.RoleOrgUser),
	})
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users", map[string]any{
		"email":    "trio-esc@tenant.test",
		"password": "Trio-Passw0rd-1!",
		"role":     "org_user",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("org_user create-user = %d, want 403 (body=%q)", rec.Code, rec.Body.String())
	}
	// CONTROL: the derivation really is empty — if org_user ever gains scopes
	// this test must be REVISITED, not silently keep passing for a new reason.
	if got := domain.SessionScopesForRole(domain.RoleOrgUser); got != "" {
		t.Fatalf("CONTROL: SessionScopesForRole(org_user) = %q, want empty", got)
	}
}
