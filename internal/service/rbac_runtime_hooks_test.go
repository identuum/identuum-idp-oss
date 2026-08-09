package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// inMemoryOrgRoleRepoForHooks extends the basic in-memory repo
// with ListUserIDsForRole + GetScopesForUser support so the
// revocation-hook + scope-lookup tests can exercise the new code
// paths.
type inMemoryOrgRoleRepoForHooks struct {
	*inMemoryOrgRoleRepo
	scopes map[uuid.UUID][]string // userID → scope strings
}

func newOrgRoleRepoForHooks() *inMemoryOrgRoleRepoForHooks {
	return &inMemoryOrgRoleRepoForHooks{
		inMemoryOrgRoleRepo: newOrgRoleRepo(),
		scopes:              map[uuid.UUID][]string{},
	}
}

func (r *inMemoryOrgRoleRepoForHooks) ListUserIDsForRole(_ context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]uuid.UUID, 0)
	for uid, rids := range r.userRoles {
		for _, rid := range rids {
			if rid == roleID {
				out = append(out, uid)
				break
			}
		}
	}
	return out, nil
}

func (r *inMemoryOrgRoleRepoForHooks) GetScopesForUser(_ context.Context, userID uuid.UUID, _ *uuid.UUID) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.scopes[userID]...)
	return out, nil
}

// ---------- NoopSessionRevoker baseline ----------

func TestNoopSessionRevoker_ReturnsNil(t *testing.T) {
	err := NoopSessionRevoker{}.RevokeUserSessions(context.Background(), uuid.New(), "rbac_role_deleted", nil)
	if err != nil {
		t.Errorf("Noop returned err = %v, want nil", err)
	}
}

func TestRecorderSessionRevoker_CapturesCalls(t *testing.T) {
	rec := &RecorderSessionRevoker{}
	uid1, uid2 := uuid.New(), uuid.New()
	_ = rec.RevokeUserSessions(context.Background(), uid1, "r1", map[string]any{"a": 1})
	_ = rec.RevokeUserSessions(context.Background(), uid2, "r2", nil)
	calls := rec.Calls()
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	if calls[0].UserID != uid1 || calls[0].Reason != "r1" {
		t.Errorf("first call = %+v", calls[0])
	}
	if calls[1].UserID != uid2 || calls[1].Reason != "r2" {
		t.Errorf("second call = %+v", calls[1])
	}
}

func TestRecorderSessionRevoker_PinsErr(t *testing.T) {
	want := errors.New("boom")
	rec := &RecorderSessionRevoker{Err: want}
	got := rec.RevokeUserSessions(context.Background(), uuid.New(), "x", nil)
	if !errors.Is(got, want) {
		t.Errorf("err = %v, want %v", got, want)
	}
}

func TestRecorderSessionRevoker_MetadataIsDefensiveCopy(t *testing.T) {
	rec := &RecorderSessionRevoker{}
	src := map[string]any{"k": "v"}
	_ = rec.RevokeUserSessions(context.Background(), uuid.New(), "r", src)
	src["k"] = "mutated"
	if rec.Calls()[0].Metadata["k"] != "v" {
		t.Errorf("metadata not copied; got %v", rec.Calls()[0].Metadata)
	}
}

// ---------- WithSessionRevoker contract ----------

func TestOrgRoleService_WithSessionRevokerNilDefaultsNoop(t *testing.T) {
	svc := NewOrgRoleService(nil, newOrgRoleRepoForHooks(), nil).WithSessionRevoker(nil)
	// Should not panic and should be safe to call mutations.
	actor := &domain.Principal{Role: domain.RoleSiteAdmin}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, uuid.New(), "X", "")
	if err := svc.DeleteRoleForActor(context.Background(), actor, role.ID); err != nil {
		t.Errorf("Delete with nil revoker (defaulted to Noop) failed: %v", err)
	}
}

// ---------- Revoker fires on Delete / RemoveScope / RemoveRoleFromUser ----------

func TestOrgRoleService_DeleteFiresRevokeForEachHolder(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	rev := &RecorderSessionRevoker{}
	svc := NewOrgRoleService(nil, repo, nil).WithSessionRevoker(rev)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
	role, err := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	uid1, uid2 := uuid.New(), uuid.New()
	_ = repo.AssignRoleToUser(context.Background(), uid1, role.ID, actor.UserID)
	_ = repo.AssignRoleToUser(context.Background(), uid2, role.ID, actor.UserID)
	if err := svc.DeleteRoleForActor(context.Background(), actor, role.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	calls := rev.Calls()
	if len(calls) != 2 {
		t.Fatalf("revoker calls = %d, want 2", len(calls))
	}
	seen := map[uuid.UUID]bool{}
	for _, c := range calls {
		if c.Reason != "rbac_role_deleted" {
			t.Errorf("reason = %q, want rbac_role_deleted", c.Reason)
		}
		seen[c.UserID] = true
	}
	if !seen[uid1] || !seen[uid2] {
		t.Errorf("expected revocation for both holders; got %v", seen)
	}
}

func TestOrgRoleService_RemoveScopeFiresRevokeForEachHolder(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	rev := &RecorderSessionRevoker{}
	svc := NewOrgRoleService(nil, repo, nil).WithSessionRevoker(rev)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	_ = repo.AddScope(context.Background(), role.ID, uuid.New(), "billing:read")
	uid := uuid.New()
	_ = repo.AssignRoleToUser(context.Background(), uid, role.ID, actor.UserID)
	if err := svc.RemoveScopeForActor(context.Background(), actor, role.ID, "billing:read"); err != nil {
		t.Fatalf("RemoveScope: %v", err)
	}
	calls := rev.Calls()
	if len(calls) != 1 || calls[0].UserID != uid || calls[0].Reason != "rbac_role_scope_removed" {
		t.Errorf("unexpected revoke calls: %+v", calls)
	}
	if calls[0].Metadata["scope_name"] != "billing:read" {
		t.Errorf("metadata.scope_name = %v, want billing:read", calls[0].Metadata["scope_name"])
	}
}

func TestOrgRoleService_RemoveRoleFromUserFiresRevokeForTargetOnly(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	rev := &RecorderSessionRevoker{}
	svc := NewOrgRoleService(nil, repo, nil).WithSessionRevoker(rev)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	uid1, uid2 := uuid.New(), uuid.New()
	_ = repo.AssignRoleToUser(context.Background(), uid1, role.ID, actor.UserID)
	_ = repo.AssignRoleToUser(context.Background(), uid2, role.ID, actor.UserID)
	if err := svc.RemoveRoleFromUserForActor(context.Background(), actor, uid1, role.ID); err != nil {
		t.Fatalf("RemoveRoleFromUser: %v", err)
	}
	calls := rev.Calls()
	if len(calls) != 1 || calls[0].UserID != uid1 || calls[0].Reason != "rbac_role_unassigned" {
		t.Errorf("expected single revoke for uid1; got %+v", calls)
	}
}

// ---------- Revoker error is swallowed ----------

func TestOrgRoleService_RevokerErrorIsSwallowed(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	rev := &RecorderSessionRevoker{Err: errors.New("revoker down")}
	svc := NewOrgRoleService(nil, repo, nil).WithSessionRevoker(rev)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	uid := uuid.New()
	_ = repo.AssignRoleToUser(context.Background(), uid, role.ID, actor.UserID)
	// Per the warn-and-continue policy, the revoker error must NOT
	// surface to the caller. The Delete returns nil.
	if err := svc.DeleteRoleForActor(context.Background(), actor, role.ID); err != nil {
		t.Errorf("revoker error leaked through Delete: %v", err)
	}
	// And the revoker WAS still called for the holder.
	if len(rev.Calls()) != 1 {
		t.Errorf("expected 1 revoke call despite error; got %d", len(rev.Calls()))
	}
}

// ---------- Non-mutating calls do NOT fire revoker ----------

func TestOrgRoleService_CreateDoesNotFireRevoker(t *testing.T) {
	rev := &RecorderSessionRevoker{}
	svc := NewOrgRoleService(nil, newOrgRoleRepoForHooks(), nil).WithSessionRevoker(rev)
	actor := &domain.Principal{Role: domain.RoleSiteAdmin}
	if _, err := svc.CreateRoleForActor(context.Background(), actor, uuid.New(), "X", ""); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(rev.Calls()) != 0 {
		t.Errorf("Create fired revoker; expected zero calls")
	}
}

// ---------- GetScopesForUserForActor ----------

func TestGetScopesForUser_SiteAdminCrossOrg(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	svc := NewOrgRoleService(nil, repo, nil)
	uid := uuid.New()
	repo.scopes[uid] = []string{"billing:read", "billing:write"}
	out, err := svc.GetScopesForUserForActor(context.Background(), &domain.Principal{Role: domain.RoleSiteAdmin}, uid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("scopes = %v, want 2", out)
	}
}

func TestGetScopesForUser_OrgAdminSameOrg(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	svc := NewOrgRoleService(nil, repo, nil)
	org := uuid.New()
	role := &domain.OrgRole{ID: uuid.New(), OrgID: org, Name: "X"}
	_ = repo.Create(context.Background(), role)
	uid := uuid.New()
	_ = repo.AssignRoleToUser(context.Background(), uid, role.ID, uuid.New())
	repo.scopes[uid] = []string{"users:read"}
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org}
	out, err := svc.GetScopesForUserForActor(context.Background(), actor, uid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(out) != 1 || out[0] != "users:read" {
		t.Errorf("scopes = %v", out)
	}
}

func TestGetScopesForUser_OrgAdminCrossOrgForbidden(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	svc := NewOrgRoleService(nil, repo, nil)
	otherOrg := uuid.New()
	role := &domain.OrgRole{ID: uuid.New(), OrgID: otherOrg, Name: "Other"}
	_ = repo.Create(context.Background(), role)
	uid := uuid.New()
	_ = repo.AssignRoleToUser(context.Background(), uid, role.ID, uuid.New())
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}
	_, err := svc.GetScopesForUserForActor(context.Background(), actor, uid)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("cross-org = %v, want ErrForbidden", err)
	}
}

func TestGetScopesForUser_SelfAlwaysAllowed(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	svc := NewOrgRoleService(nil, repo, nil)
	uid := uuid.New()
	repo.scopes[uid] = []string{"profile:read"}
	actor := &domain.Principal{Role: domain.RoleOrgUser, UserID: uid, OrganizationID: uuid.New()}
	out, err := svc.GetScopesForUserForActor(context.Background(), actor, uid)
	if err != nil {
		t.Errorf("self Get: %v", err)
	}
	if len(out) != 1 || out[0] != "profile:read" {
		t.Errorf("self scopes = %v", out)
	}
}

func TestGetScopesForUser_OrgUserOtherForbidden(t *testing.T) {
	svc := NewOrgRoleService(nil, newOrgRoleRepoForHooks(), nil)
	actor := &domain.Principal{Role: domain.RoleOrgUser, UserID: uuid.New(), OrganizationID: uuid.New()}
	_, err := svc.GetScopesForUserForActor(context.Background(), actor, uuid.New())
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("org_user other-user = %v, want ErrForbidden", err)
	}
}

func TestGetScopesForUser_UnauthenticatedNilActor(t *testing.T) {
	svc := NewOrgRoleService(nil, newOrgRoleRepoForHooks(), nil)
	_, err := svc.GetScopesForUserForActor(context.Background(), nil, uuid.New())
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("nil actor = %v, want ErrUnauthorized", err)
	}
}

// Empty target (no role bindings) returns an empty slice without
// signaling cross-tenant existence. The org_admin path treats the
// target as "no observable cross-tenant state" — consistent with
// the documented privacy posture.
func TestGetScopesForUser_OrgAdminUnboundTargetReturnsEmpty(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	svc := NewOrgRoleService(nil, repo, nil)
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}
	out, err := svc.GetScopesForUserForActor(context.Background(), actor, uuid.New())
	if err != nil {
		t.Errorf("unbound target Get: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("unbound target scopes = %v, want empty", out)
	}
}
