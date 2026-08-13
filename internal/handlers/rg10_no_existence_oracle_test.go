package handlers

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// Rg10 — no existence oracle on the write-side cross-org probes
// (compliance-audit gap G10).
//
// THE ASYMMETRY THIS CLOSES. The READ path already gets this right:
// GetUserForActor answers errUserNotFound for a user in another organization,
// which is why TestModel_OrgAdminSeesOtherOrgUserAs404 passes. Three WRITE
// paths — reset-MFA, approve-registration and restore-user — answered
// domain.ErrForbidden instead:
//
//	if actor.OrganizationID == uuid.Nil || target.OrganizationID != actor.OrganizationID {
//		return nil, domain.ErrForbidden
//	}
//
// 403 and 404 are different answers to different questions. 404 says "no such
// user, as far as you are concerned"; 403 says "that user EXISTS and you may
// not touch it". An org_admin who can tell those apart can enumerate the user
// ids of every other tenant on the installation, one probe at a time, using
// nothing but their own legitimate credentials.
//
// The fix is not new policy — it is making three routes agree with the one
// beside them that was already right.
// RULE: RG10
func TestRg10_CrossOrgWriteProbesAreIndistinguishableFromAMiss(t *testing.T) {
	mine, theirs := uuid.New(), uuid.New()
	actor := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: mine,
		Role:           domain.RoleOrgAdmin,
		Scope:          domain.SessionScopesForRole(domain.RoleOrgAdmin),
	}
	eng := newTenantEngine(t, actor)

	// A user that EXISTS, in someone else's organization.
	foreign := uuid.New()
	seedTenantUser(eng, foreign, theirs, domain.RoleOrgUser, "someone@other.test")

	// An id that exists NOWHERE. The two must be indistinguishable.
	absent := uuid.New()

	// reachable says whether an org_admin may use the route AT ALL. Measured on
	// its OWN organization's user: reset-mfa → 200, approve → 409 (reachable,
	// wrong state), restore → 403.
	//
	// THE AUDIT IS MISDESCRIBED FOR RESTORE. It listed three routes; restore is
	// not an oracle, because it refuses an org_admin UNIFORMLY — own org,
	// foreign org and absent id all answer 403, so the response carries no
	// information about whether the id exists. A 403 that depends on the CALLER
	// tells you nothing; a 403 that depends on the TARGET tells you it exists.
	// Only the second is an oracle, and only the first two routes had one.
	for _, route := range []struct {
		name      string
		reachable bool
		path      func(id uuid.UUID) string
	}{
		{"reset-MFA", true, func(id uuid.UUID) string { return "/api/v1/users/" + id.String() + "/recovery/reset-mfa" }},
		{"approve", true, func(id uuid.UUID) string { return "/api/v1/users/" + id.String() + "/approve" }},
		{"restore", false, func(id uuid.UUID) string { return "/api/v1/users/" + id.String() + "/restore" }},
	} {
		route := route
		t.Run(route.name, func(t *testing.T) {
			foreignRec := tenantReq(t, eng, http.MethodPost, route.path(foreign), nil)
			absentRec := tenantReq(t, eng, http.MethodPost, route.path(absent), nil)

			if foreignRec.Code != absentRec.Code {
				t.Errorf("%s: a FOREIGN user answers %d and an ABSENT id answers %d — the "+
					"difference tells an org_admin which ids exist in other tenants, which is "+
					"an enumeration oracle built from their own legitimate credentials",
					route.name, foreignRec.Code, absentRec.Code)
			}
			if route.reachable && foreignRec.Code != http.StatusNotFound {
				t.Errorf("%s: cross-org probe → %d, want 404 — the READ path beside it already "+
					"answers 404 for exactly this reason", route.name, foreignRec.Code)
			}
		})
	}

	// CONTROL: the actor's OWN organization must still be reachable on these
	// routes. Without it, a change that 404'd every write would satisfy every
	// assertion above while removing the feature.
	t.Run("CONTROL: the actor's own user is still reachable", func(t *testing.T) {
		own := uuid.New()
		seedTenantUser(eng, own, mine, domain.RoleOrgUser, "mine@own.test")
		// reset-MFA is the one that both succeeds and is scoped, so it is the
		// honest control: if the fence had simply started refusing everyone,
		// this would go 404 and the assertions above would be vacuous.
		rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/"+own.String()+"/recovery/reset-mfa", nil)
		if rec.Code != http.StatusOK {
			t.Errorf("CONTROL FAILED: the org_admin can no longer reset MFA for its OWN user "+
				"(%d, want 200) — the cross-org assertions above would then prove nothing", rec.Code)
		}
	})
}
