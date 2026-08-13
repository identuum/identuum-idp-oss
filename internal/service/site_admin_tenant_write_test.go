package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// SITE-ADMIN-TENANT-WRITE failing-first trio (owner ruling, THE-TENANT-ADMIN
// order C: THE MODEL WINS).
//
// The workspace authority model says, verbatim:
//
//	site_admin can:
//	- delegate/create an org_admin only when the target organization has zero
//	  active org_admin users
//	site_admin cannot:
//	- create regular org_user accounts in tenant organizations
//	- create extra org_admin accounts if the organization already has at least
//	  one active org_admin
//
// The enforced rule permitted site_admin to create ANY role in ANY org given an
// organization_id. NARROWEST READING pinned here: the delegation exception
// covers org_admin creation ONLY, and ONLY while the org has zero active
// org_admins. It never covers org_user creation, and it closes the moment a
// live org_admin exists.
//
// The system organization is exempt: it is infrastructure, not a tenant, and
// bootstrap/recover-site-admin write into it.
func siteAdmin() *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), Role: domain.RoleSiteAdmin}
}

// RULE: SA-TENANT-USER-1
func TestSiteAdminTenantWrite_OrgUserInTenantForbidden(t *testing.T) {
	repo := newUserRepo()
	svc := NewUserService(nil, repo)
	org := uuid.New()

	_, err := svc.CreateUserForActor(context.Background(), siteAdmin(), CreateUserOptions{
		OrganizationID: org,
		Email:          "tenant-user@tenant.test",
		Password:       "Tenant-Passw0rd-1!",
		Role:           domain.RoleOrgUser,
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("site_admin created a plain org_user inside a tenant (err=%v) — the model says it "+
			"\"cannot create regular org_user accounts in tenant organizations\"", err)
	}
}

// RULE: SA-TENANT-FIRST-1
func TestSiteAdminTenantWrite_FirstOrgAdminAllowed(t *testing.T) {
	repo := newUserRepo()
	svc := NewUserService(nil, repo)
	org := uuid.New()

	got, err := svc.CreateUserForActor(context.Background(), siteAdmin(), CreateUserOptions{
		OrganizationID: org,
		Email:          "first-admin@tenant.test",
		Password:       "Tenant-Passw0rd-1!",
		Role:           domain.RoleOrgAdmin,
	})
	if err != nil {
		t.Fatalf("site_admin could not seed the FIRST org_admin of an org with none: %v — that is "+
			"the delegation the model explicitly permits", err)
	}
	if got == nil || got.Role != domain.RoleOrgAdmin {
		t.Fatalf("created user = %+v, want an org_admin", got)
	}
}

// RULE: SA-TENANT-SECOND-1
func TestSiteAdminTenantWrite_SecondOrgAdminForbidden(t *testing.T) {
	repo := newUserRepo()
	svc := NewUserService(nil, repo)
	org := uuid.New()

	if _, err := svc.CreateUserForActor(context.Background(), siteAdmin(), CreateUserOptions{
		OrganizationID: org, Email: "first-admin@tenant.test",
		Password: "Tenant-Passw0rd-1!", Role: domain.RoleOrgAdmin,
	}); err != nil {
		t.Fatalf("CONTROL: seeding the first org_admin failed: %v", err)
	}

	_, err := svc.CreateUserForActor(context.Background(), siteAdmin(), CreateUserOptions{
		OrganizationID: org, Email: "second-admin@tenant.test",
		Password: "Tenant-Passw0rd-1!", Role: domain.RoleOrgAdmin,
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("site_admin created a SECOND org_admin (err=%v) — the delegation window closes "+
			"once the organization has at least one active org_admin", err)
	}
}

// The system organization is NOT a tenant: bootstrap and recover-site-admin
// write the site_admin into it, and this rule must never block that.
// RULE: SA-TENANT-SYSORG-1
func TestSiteAdminTenantWrite_SystemOrgIsNotATenant(t *testing.T) {
	repo := newUserRepo()
	svc := NewUserService(nil, repo)
	systemOrg := uuid.MustParse(domain.SystemOrgID)

	// The role is site_admin, not org_user: MODEL-SYSTEMORG-MEMBERSHIP now
	// enforces "Only site_admin user CAN be a member of System organization",
	// so an org_user there is refused by a DIFFERENT rule. What this case
	// pins is that the TENANT rule does not leak into the system org — the
	// bootstrap write must still work.
	if _, err := svc.CreateUserForActor(context.Background(), siteAdmin(), CreateUserOptions{
		OrganizationID: systemOrg, Email: domain.SiteAdminEmail,
		Password: "System-Passw0rd-1!", Role: domain.RoleSiteAdmin,
	}); err != nil {
		t.Fatalf("the tenant rule leaked into the SYSTEM organization: %v", err)
	}
}
