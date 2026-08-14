package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// Service-layer tests for the AssignRoleToUserForActor target-
// user tenant guard. The handler tests in
// internal/handlers/rbac_test.go cover the wire behavior; these
// pin the service-direct contract so a future caller that bypasses
// the HTTP composed guard cannot land cross-org assignments.

func newGuardedOrgRoleSvc(t *testing.T) (*OrgRoleService, *inMemoryOrgRoleRepoForHooks, *inMemoryUserRepo, *RecorderSessionRevoker) {
	t.Helper()
	roleRepo := newOrgRoleRepoForHooks()
	userRepo := newUserRepo()
	rev := &RecorderSessionRevoker{}
	svc := NewOrgRoleService(nil, roleRepo, nil).
		WithUserRepository(userRepo).
		WithSessionRevoker(rev)
	return svc, roleRepo, userRepo, rev
}

// ---------- Nil UserRepository fail-closed ----------

func TestAssignRoleForActor_NilUserRepoFailsClosed(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	rev := &RecorderSessionRevoker{}
	svc := NewOrgRoleService(nil, repo, nil).WithSessionRevoker(rev) // no WithUserRepository
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleSiteAdmin}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	err := svc.AssignRoleToUserForActor(context.Background(), actor, uuid.New(), role.ID)
	if !errors.Is(err, ErrUserRepositoryUnavailable) {
		t.Errorf("nil userRepo = %v, want ErrUserRepositoryUnavailable", err)
	}
	if len(rev.Calls()) != 0 {
		t.Errorf("revoker fired despite fail-closed; calls=%d", len(rev.Calls()))
	}
}

func TestWithUserRepository_NilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("WithUserRepository(nil) did not panic")
		}
	}()
	repo := newOrgRoleRepoForHooks()
	svc := NewOrgRoleService(nil, repo, nil)
	_ = svc.WithUserRepository(nil)
}

// ---------- site_admin actor ----------

func TestAssignRoleForActor_SiteAdminSameOrgAllowed(t *testing.T) {
	svc, roleRepo, userRepo, rev := newGuardedOrgRoleSvc(t)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleSiteAdmin}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	target := uuid.New()
	seedTargetUser(t, userRepo, target, org, domain.RoleOrgUser)
	if err := svc.AssignRoleToUserForActor(context.Background(), actor, target, role.ID); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if len(rev.Calls()) != 1 || rev.Calls()[0].UserID != target {
		t.Errorf("expected one revoke for target; got %+v", rev.Calls())
	}
	_ = roleRepo
}

func TestAssignRoleForActor_SiteAdminCrossOrgTargetForbidden(t *testing.T) {
	svc, _, userRepo, rev := newGuardedOrgRoleSvc(t)
	roleOrg := uuid.New()
	otherOrg := uuid.New()
	actor := &domain.Principal{Role: domain.RoleSiteAdmin}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, roleOrg, "X", "")
	target := uuid.New()
	seedTargetUser(t, userRepo, target, otherOrg, domain.RoleOrgUser)
	err := svc.AssignRoleToUserForActor(context.Background(), actor, target, role.ID)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("cross-org target by site_admin = %v, want ErrForbidden", err)
	}
	if len(rev.Calls()) != 0 {
		t.Errorf("revoker fired on rejection; calls=%d", len(rev.Calls()))
	}
}

// ---------- org_admin actor ----------

func TestAssignRoleForActor_OrgAdminSameOrgAllowed(t *testing.T) {
	svc, _, userRepo, rev := newGuardedOrgRoleSvc(t)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	target := uuid.New()
	seedTargetUser(t, userRepo, target, org, domain.RoleOrgUser)
	if err := svc.AssignRoleToUserForActor(context.Background(), actor, target, role.ID); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if len(rev.Calls()) != 1 {
		t.Errorf("expected one revoke; got %d", len(rev.Calls()))
	}
}

// RULE: ROLE-ASSIGN-SCOPE-1
func TestAssignRoleForActor_OrgAdminCrossOrgTargetForbidden(t *testing.T) {
	svc, _, userRepo, rev := newGuardedOrgRoleSvc(t)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	target := uuid.New()
	seedTargetUser(t, userRepo, target, uuid.New(), domain.RoleOrgUser) // different org
	err := svc.AssignRoleToUserForActor(context.Background(), actor, target, role.ID)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("cross-org target = %v, want ErrForbidden", err)
	}
	if len(rev.Calls()) != 0 {
		t.Errorf("revoker fired on rejection; calls=%d", len(rev.Calls()))
	}
}

func TestAssignRoleForActor_OrgAdminSiteAdminTargetForbidden(t *testing.T) {
	svc, _, userRepo, rev := newGuardedOrgRoleSvc(t)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	target := uuid.New()
	seedTargetUser(t, userRepo, target, org, domain.RoleSiteAdmin)
	err := svc.AssignRoleToUserForActor(context.Background(), actor, target, role.ID)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("org_admin assigning to site_admin = %v, want ErrForbidden", err)
	}
	if len(rev.Calls()) != 0 {
		t.Errorf("revoker fired on rejection; calls=%d", len(rev.Calls()))
	}
}

func TestAssignRoleForActor_SiteAdminCanAssignToSiteAdminInSameOrg(t *testing.T) {
	// The org_admin → site_admin block is OSS-tightening; site_admin
	// actors may still assign roles to site_admin users when the
	// target's org matches the role.
	svc, _, userRepo, rev := newGuardedOrgRoleSvc(t)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleSiteAdmin}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	target := uuid.New()
	seedTargetUser(t, userRepo, target, org, domain.RoleSiteAdmin)
	if err := svc.AssignRoleToUserForActor(context.Background(), actor, target, role.ID); err != nil {
		t.Errorf("site_admin assigning to site_admin same-org = %v, want nil", err)
	}
	if len(rev.Calls()) != 1 {
		t.Errorf("expected one revoke; got %d", len(rev.Calls()))
	}
}

// ---------- Missing target user ----------

func TestAssignRoleForActor_MissingTargetUserForbidden(t *testing.T) {
	svc, _, _, rev := newGuardedOrgRoleSvc(t)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	err := svc.AssignRoleToUserForActor(context.Background(), actor, uuid.New(), role.ID)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("missing target = %v, want ErrForbidden", err)
	}
	if len(rev.Calls()) != 0 {
		t.Errorf("revoker fired on missing target; calls=%d", len(rev.Calls()))
	}
}

// ---------- org_user actor ----------

func TestAssignRoleForActor_OrgUserForbidden(t *testing.T) {
	svc, _, userRepo, rev := newGuardedOrgRoleSvc(t)
	org := uuid.New()
	// org_user actor; their authorization is denied at GetRoleForActor
	// before the target-user check fires. The target seed is irrelevant.
	actor := &domain.Principal{Role: domain.RoleOrgUser, OrganizationID: org, UserID: uuid.New()}
	// Create role using a separate site_admin so the org_user can
	// hold a UUID to attempt the call on.
	siteActor := &domain.Principal{Role: domain.RoleSiteAdmin}
	role, _ := svc.CreateRoleForActor(context.Background(), siteActor, org, "X", "")
	target := uuid.New()
	seedTargetUser(t, userRepo, target, org, domain.RoleOrgUser)
	err := svc.AssignRoleToUserForActor(context.Background(), actor, target, role.ID)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("org_user assign = %v, want ErrForbidden", err)
	}
	if len(rev.Calls()) != 0 {
		t.Errorf("revoker fired on org_user denial; calls=%d", len(rev.Calls()))
	}
}

// ---------- Revoker NOT fired on any forbidden branch ----------

func TestAssignRoleForActor_RevokerNotFiredOnAnyRejection(t *testing.T) {
	cases := []struct {
		name    string
		setup   func() (svc *OrgRoleService, target uuid.UUID, roleID uuid.UUID, actor *domain.Principal, rev *RecorderSessionRevoker)
		wantErr error
	}{
		{
			name: "cross-org target",
			setup: func() (*OrgRoleService, uuid.UUID, uuid.UUID, *domain.Principal, *RecorderSessionRevoker) {
				svc, _, userRepo, rev := newGuardedOrgRoleSvc(t)
				org := uuid.New()
				actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
				role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
				target := uuid.New()
				seedTargetUser(t, userRepo, target, uuid.New(), domain.RoleOrgUser)
				return svc, target, role.ID, actor, rev
			},
			wantErr: domain.ErrForbidden,
		},
		{
			name: "site_admin target",
			setup: func() (*OrgRoleService, uuid.UUID, uuid.UUID, *domain.Principal, *RecorderSessionRevoker) {
				svc, _, userRepo, rev := newGuardedOrgRoleSvc(t)
				org := uuid.New()
				actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
				role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
				target := uuid.New()
				seedTargetUser(t, userRepo, target, org, domain.RoleSiteAdmin)
				return svc, target, role.ID, actor, rev
			},
			wantErr: domain.ErrForbidden,
		},
		{
			name: "missing target",
			setup: func() (*OrgRoleService, uuid.UUID, uuid.UUID, *domain.Principal, *RecorderSessionRevoker) {
				svc, _, _, rev := newGuardedOrgRoleSvc(t)
				org := uuid.New()
				actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
				role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
				return svc, uuid.New(), role.ID, actor, rev
			},
			wantErr: domain.ErrForbidden,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, target, roleID, actor, rev := tc.setup()
			err := svc.AssignRoleToUserForActor(context.Background(), actor, target, roleID)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
			if len(rev.Calls()) != 0 {
				t.Errorf("revoker fired on rejection: calls=%+v", rev.Calls())
			}
		})
	}
}
