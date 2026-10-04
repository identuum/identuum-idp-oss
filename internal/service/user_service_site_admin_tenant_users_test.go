package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// D-025: a site administrator manages infrastructure only. It never edits,
// resets, deletes, restores or approves a user that belongs to a tenant
// organization; those are the organization admin's work. The one tenant write
// it keeps is appointing the first org_admin of an organization that has none
// (CreateUserForActor). A user in the system organization is not a tenant's.
func TestSiteAdminNeverActsOnATenantUser(t *testing.T) {
	ctx := context.Background()
	tenantOrg := uuid.New()
	password := "N3w-Passw0rd!x"
	banned := true

	t.Run("update", func(t *testing.T) {
		repo := newUserRepo()
		svc := NewUserService(nil, repo)
		target := uuid.New()
		seedRow(repo, target, tenantOrg, domain.RoleOrgUser)
		_, err := svc.UpdateUserForActor(ctx, siteAdminActor(), target, UpdateUserOptions{Password: &password, Banned: &banned})
		if !errors.Is(err, domain.ErrForbidden) {
			t.Errorf("update of a tenant user: err=%v, want ErrForbidden", err)
		}
		if repo.rows[target].Banned {
			t.Error("the tenant user was changed")
		}
	})

	t.Run("reset MFA", func(t *testing.T) {
		repo := newUserRepo()
		svc := NewUserService(nil, repo)
		target := uuid.New()
		seedMFARow(repo, target, tenantOrg, domain.RoleOrgUser)
		if _, err := svc.ResetMFAForActor(ctx, siteAdminActor(), target); !errors.Is(err, domain.ErrForbidden) {
			t.Errorf("MFA reset of a tenant user: err=%v, want ErrForbidden", err)
		}
		if !repo.rows[target].MFAEnabled {
			t.Error("the tenant user's MFA was reset")
		}
	})

	t.Run("delete", func(t *testing.T) {
		repo := newUserRepo()
		svc := NewUserService(nil, repo)
		target := uuid.New()
		seedRow(repo, target, tenantOrg, domain.RoleOrgAdmin)
		if err := svc.DeleteUserForActor(ctx, siteAdminActor(), target); !errors.Is(err, domain.ErrForbidden) {
			t.Errorf("delete of a tenant user: err=%v, want ErrForbidden", err)
		}
		if _, ok := repo.rows[target]; !ok || repo.rows[target].DeletedAt != nil {
			t.Error("the tenant user was deleted")
		}
	})

	t.Run("approve a held registration", func(t *testing.T) {
		repo := newUserRepo()
		svc := NewUserService(nil, repo)
		target := uuid.New()
		seedRow(repo, target, tenantOrg, domain.RoleOrgUser)
		repo.rows[target].Banned = true
		if _, err := svc.ApproveRegistrationForActor(ctx, siteAdminActor(), target); !errors.Is(err, domain.ErrForbidden) {
			t.Errorf("approval of a tenant registration: err=%v, want ErrForbidden", err)
		}
		if !repo.rows[target].Banned {
			t.Error("the registration was approved")
		}
	})
}
