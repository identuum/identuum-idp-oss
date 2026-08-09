package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AdminPermissionsModel.md, the two sentinel-immutability rules:
//
//	"System organization CANNOT be deleted and renamed."
//	"site_admin CANNOT be deleted and there can only be site_admin user."
//
// Measured live before this landed: PUT the System org's name → HTTP 200,
// DELETE the System org → HTTP 200, DELETE the site_admin → HTTP 200. The last
// two are not merely wrong, they BRICK the installation: the site_admin's own
// organization (or the account itself) disappears and every later request
// answers 401 from a dead session. That is also why the compliance probe had to
// run them on isolated stacks — measured in sequence, they turned every
// following rule into a false COMPLIES.
func TestModel_SystemOrgCannotBeRenamed(t *testing.T) {
	svc := NewOrganizationService(nil, newOrgRepo())
	sys := uuid.MustParse(domain.SystemOrgID)
	name := "Renamed By Test"

	_, err := svc.Update(context.Background(), sys, UpdateOrganizationOptions{Name: &name})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("renaming the System organization returned %v, want ErrForbidden — the model says "+
			"it CANNOT be renamed", err)
	}
}

func TestModel_SystemOrgCannotBeDeleted(t *testing.T) {
	svc := NewOrganizationService(nil, newOrgRepo())
	sys := uuid.MustParse(domain.SystemOrgID)

	if err := svc.Delete(context.Background(), sys); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("deleting the System organization returned %v, want ErrForbidden — deleting it "+
			"destroys the site_admin's own organization and bricks the installation", err)
	}
}

func TestModel_SiteAdminCannotBeDeleted(t *testing.T) {
	repo := newUserRepo()
	svc := NewUserService(nil, repo)
	sa := uuid.MustParse(domain.SiteAdminID)
	sysOrg := uuid.MustParse(domain.SystemOrgID)

	if err := svc.Delete(context.Background(), sa, sysOrg); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("deleting the site_admin returned %v, want ErrForbidden", err)
	}
}

// CONTROL: org_admins stay deletable. The model's lost-all-org_admins clause
// REQUIRES it — "If somehow, an organization lose the org_admin's and left with
// no org_admins, then site_admin can create/assign another org_admin" — and a
// guard that over-reaches into ordinary users would make that clause
// unreachable.
func TestModel_OrdinaryUsersStayDeletable(t *testing.T) {
	repo := newUserRepo()
	svc := NewUserService(nil, repo)
	org := uuid.New()

	u, err := svc.Create(context.Background(), CreateUserOptions{
		OrganizationID: org, Email: "org-admin@tenant.test",
		Password: "Tenant-Passw0rd-1!", Role: domain.RoleOrgAdmin,
	})
	if err != nil {
		t.Fatalf("CONTROL: seeding an org_admin failed: %v", err)
	}
	if err := svc.Delete(context.Background(), u.ID, org); err != nil {
		t.Fatalf("CONTROL FAILED: an ordinary org_admin is no longer deletable (%v) — the "+
			"lost-all-org_admins clause depends on it", err)
	}
}

// "Only site_admin user CAN be a member of System organization."
func TestModel_OnlySiteAdminMayJoinTheSystemOrg(t *testing.T) {
	repo := newUserRepo()
	svc := NewUserService(nil, repo)
	sysOrg := uuid.MustParse(domain.SystemOrgID)

	for _, role := range []domain.UserRole{domain.RoleOrgUser, domain.RoleOrgAdmin} {
		_, err := svc.Create(context.Background(), CreateUserOptions{
			OrganizationID: sysOrg, Email: string(role) + "@system.local",
			Password: "Intruder-Passw0rd-1!", Role: role,
		})
		if !errors.Is(err, domain.ErrForbidden) {
			t.Errorf("creating a %s in the System organization returned %v, want ErrForbidden", role, err)
		}
	}

	// CONTROL: the site_admin itself must still be writable there, or bootstrap
	// and recover-site-admin cannot run at all.
	if _, err := svc.Create(context.Background(), CreateUserOptions{
		OrganizationID: sysOrg, Email: domain.SiteAdminEmail,
		Password: "Bootstrap-Passw0rd-1!", Role: domain.RoleSiteAdmin,
	}); err != nil {
		t.Fatalf("CONTROL FAILED: the site_admin can no longer be created in the System "+
			"organization (%v) — bootstrap would be impossible", err)
	}
}

// The ACTOR-scoped delete path reached the repository directly, so the guard on
// UserService.Delete never saw it — and its comment promised that
// "last-site-admin invariants are enforced by higher-tier code" that did not
// exist. Measured live: DELETE the sentinel → HTTP 200.
func TestModel_SiteAdminCannotBeDeletedByAnyActor(t *testing.T) {
	repo := newUserRepo()
	svc := NewUserService(nil, repo)
	sysOrg := uuid.MustParse(domain.SystemOrgID)
	sa := uuid.MustParse(domain.SiteAdminID)

	if _, err := repo.Create(context.Background(), &domain.User{
		ID: sa, OrganizationID: sysOrg, Email: domain.SiteAdminEmail, Role: domain.RoleSiteAdmin,
	}); err != nil {
		t.Fatalf("seeding the site_admin failed: %v", err)
	}

	actor := &domain.Principal{UserID: uuid.New(), Role: domain.RoleSiteAdmin}
	if err := svc.DeleteUserForActor(context.Background(), actor, sa); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("site_admin deleted the site_admin via DeleteUserForActor (%v), want ErrForbidden", err)
	}

	// CONTROL: an ordinary user is still deletable through the same path.
	org := uuid.New()
	u, err := svc.Create(context.Background(), CreateUserOptions{
		OrganizationID: org, Email: "ordinary@tenant.test",
		Password: "Tenant-Passw0rd-1!", Role: domain.RoleOrgAdmin,
	})
	if err != nil {
		t.Fatalf("CONTROL: seeding an org_admin failed: %v", err)
	}
	if err := svc.DeleteUserForActor(context.Background(), actor, u.ID); err != nil {
		t.Fatalf("CONTROL FAILED: an ordinary org_admin is no longer deletable: %v", err)
	}
}
