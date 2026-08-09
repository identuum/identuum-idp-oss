package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// seedPendingRegistrant seeds a user in the public_registration hold
// state — Banned=true — for the given role, so approval tests have a
// concrete pending row to clear (or to reject when the role is wrong).
func seedPendingRegistrant(eng tenantEngine, id, orgID uuid.UUID, role domain.UserRole) *domain.User {
	now := time.Now().UTC()
	u := &domain.User{
		ID:             id,
		OrganizationID: orgID,
		Email:          "pending-" + id.String() + "@tenant.test",
		Role:           role,
		Banned:         true, // the registration hold
		PasswordHash:   "PASSWORD-HASH-MUST-NOT-LEAK",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	_, _ = eng.userRepo.Create(context.Background(), u)
	return u
}

// (a) + (b): approving a pending registrant (banned=true, org_user)
// succeeds, no longer 501s, and clears the hold — the persisted state
// (banned=false) is exactly the condition the login path accepts.
func TestUserApprove_PendingUser_ClearsHold(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, siteAdminPrincipal())
	uid := uuid.New()
	seedPendingRegistrant(eng, uid, org, domain.RoleOrgUser)

	// Before: the seeded registrant is held (banned=true) — the login
	// path rejects banned users, so it cannot authenticate yet.
	before, _ := eng.userRepo.GetByID(context.Background(), uid)
	if before == nil || !before.Banned {
		t.Fatalf("precondition: seeded user must be banned=true (pending)")
	}

	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/"+uid.String()+"/approve", nil)
	if rec.Code == http.StatusNotImplemented {
		t.Fatalf("approve still returns 501 — the OSS port did not take effect")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s want 200", rec.Code, rec.Body.String())
	}

	// Response reflects the cleared hold; the role is preserved.
	var out safeUser
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Banned {
		t.Errorf("response banned=true, want false (hold cleared)")
	}
	if out.Role != domain.RoleOrgUser {
		t.Errorf("response role=%q, want org_user (approval keeps role)", out.Role)
	}

	// After: persisted state now satisfies the login accept condition.
	after, _ := eng.userRepo.GetByID(context.Background(), uid)
	if after == nil || after.Banned {
		t.Fatalf("persisted banned=%v, want false — the login path accepts non-banned users", after != nil && after.Banned)
	}
	if after.Role != domain.RoleOrgUser {
		t.Errorf("persisted role=%q, want org_user", after.Role)
	}
}

// (a-positive scope gate): a same-org org_admin holding users:update
// passes the scope gate and the service-layer authority, and approves.
func TestUserApprove_OrgAdminSameOrgWithScope_Succeeds(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:update",
	})
	uid := uuid.New()
	seedPendingRegistrant(eng, uid, org, domain.RoleOrgUser)
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/"+uid.String()+"/approve", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-org org_admin with users:update = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// (c) authorization: an org_admin lacking users:update is rejected at
// the scope gate (403), consistent with the sibling update route, and
// the hold is NOT cleared.
func TestUserApprove_OrgAdminWithoutScope_Forbidden(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:read", // NOT users:update
	})
	uid := uuid.New()
	seedPendingRegistrant(eng, uid, org, domain.RoleOrgUser)
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/"+uid.String()+"/approve", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("org_admin without users:update = %d, want 403", rec.Code)
	}
	after, _ := eng.userRepo.GetByID(context.Background(), uid)
	if after == nil || !after.Banned {
		t.Errorf("hold was cleared despite failed authz (banned=%v)", after != nil && after.Banned)
	}
}

// (c) authorization: unauthenticated caller is rejected 401, consistent
// with the sibling user routes.
func TestUserApprove_Unauthenticated_401(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, nil)
	uid := uuid.New()
	seedPendingRegistrant(eng, uid, org, domain.RoleOrgUser)
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/"+uid.String()+"/approve", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated approve = %d, want 401", rec.Code)
	}
}

// (c) authority: a scoped org_admin cannot approve a user in another
// org — the service layer returns 403 (cross-org guard).
// RENAMED: the verdict changed with G10. A 403 confirmed the target EXISTS in
// another tenant, turning the route into an enumeration oracle an org_admin
// could drive with their own credentials. It answers not-found now, matching
// the read path that always did.
func TestUserApprove_OrgAdminCrossOrgIs404(t *testing.T) {
	adminOrg := uuid.New()
	targetOrg := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: adminOrg,
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:update",
	})
	uid := uuid.New()
	seedPendingRegistrant(eng, uid, targetOrg, domain.RoleOrgUser)
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/"+uid.String()+"/approve", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-org org_admin approve = %d, want 403", rec.Code)
	}
}

// (d) guard: approving an already-active user (banned=false) is a 409,
// not a silent success — approval is not a no-op re-approve.
func TestUserApprove_AlreadyActiveUser_Conflict(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, siteAdminPrincipal())
	uid := uuid.New()
	seedTenantUser(eng, uid, org, domain.RoleOrgUser, "active@tenant.test") // banned=false
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/"+uid.String()+"/approve", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("approving already-active user = %d, want 409", rec.Code)
	}
}

// (d) guard: approval is NOT a general un-ban. A banned org_admin is not
// a pending self-registration → 409, and the admin stays banned.
func TestUserApprove_BannedAdmin_NotUnbanned(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, siteAdminPrincipal())
	uid := uuid.New()
	seedPendingRegistrant(eng, uid, org, domain.RoleOrgAdmin) // banned=true, but role=org_admin
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/"+uid.String()+"/approve", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("approving a banned org_admin = %d, want 409 (not a pending registrant)", rec.Code)
	}
	after, _ := eng.userRepo.GetByID(context.Background(), uid)
	if after == nil || !after.Banned {
		t.Errorf("admin was un-banned via approve (banned=%v) — approval must not be a general un-ban", after != nil && after.Banned)
	}
}

// (d) guard: a missing user is a 404, not a silent success.
func TestUserApprove_MissingUser_NotFound(t *testing.T) {
	eng := newTenantEngine(t, siteAdminPrincipal())
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/"+uuid.NewString()+"/approve", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("approving missing user = %d, want 404", rec.Code)
	}
}

// A non-UUID :id is a 400 before any lookup.
func TestUserApprove_InvalidID_400(t *testing.T) {
	eng := newTenantEngine(t, siteAdminPrincipal())
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/not-a-uuid/approve", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid id = %d, want 400", rec.Code)
	}
}
