//go:build integration

package postgres_test

// OSS-0912-C2 against the live SQL (migration 0053): every statement that
// reads a user row carries email_verified_via, so no read path drops the
// proof (a dropped value reads as NULL, never proven); Create stores it; the
// two consume statements record admin_link unless a proof is recorded; and
// Update's rules hold — false clears, true keeps a proof, an address change
// drops one.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func c2ViaOf(u *domain.User) string {
	if u == nil || u.EmailVerifiedVia == nil {
		return ""
	}
	return *u.EmailVerifiedVia
}

func TestUserRepository_EmailVerifiedViaOnEveryReadPath(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgID := uuid.MustParse(seedScratchOrg(t, pool))
	repo := postgres.NewPgxUserRepository(pool)
	via := domain.EmailVerifiedViaUpstreamIDP
	extID := "c2-ext-" + uuid.NewString()
	email := "c2-roundtrip-" + uuid.NewString()[:8] + "@example.invalid"
	activation := "c2-activation-" + uuid.NewString()
	created, err := repo.Create(ctx, &domain.User{ID: uuid.New(), OrganizationID: orgID, Email: email, PasswordHash: "c2-" + uuid.NewString(),
		Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true, EmailVerifiedVia: &via, ExternalID: &extID,
		ActivationTokenHash: &activation})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE organization_id = $1`, orgID) })
	if c2ViaOf(created) != via {
		t.Errorf("Create RETURNING via = %q; want %q", c2ViaOf(created), via)
	}

	one := func(name string, u *domain.User, err error) {
		t.Helper()
		if err != nil || c2ViaOf(u) != via {
			t.Errorf("%s via = %q (err %v); want %q", name, c2ViaOf(u), err, via)
		}
	}
	u, err := repo.GetByID(ctx, created.ID)
	one("GetByID", u, err)
	u, err = repo.GetByIDWithOrg(ctx, created.ID)
	one("GetByIDWithOrg", u, err)
	u, err = repo.GetByEmailAndOrgID(ctx, orgID, email)
	one("GetByEmailAndOrgID", u, err)
	u, err = repo.GetByExternalID(ctx, orgID, extID)
	one("GetByExternalID", u, err)
	u, err = repo.GetByIDAdmin(ctx, created.ID)
	one("GetByIDAdmin", u, err)
	u, err = repo.GetByEmailAdmin(ctx, email)
	one("GetByEmailAdmin", u, err)
	u, err = repo.FindByActivationTokenHash(ctx, activation)
	one("FindByActivationTokenHash", u, err)
	found, err := repo.FindUsersByEmail(ctx, email)
	if len(found) != 1 {
		t.Errorf("FindUsersByEmail = %d users (err %v); want 1", len(found), err)
	} else {
		one("FindUsersByEmail", found[0], err)
	}
	listed, _, err := repo.List(ctx, repository.ListUserOptions{Filter: repository.UserFilter{Email: email}})
	if len(listed) != 1 {
		t.Errorf("List = %d users (err %v); want 1", len(listed), err)
	} else {
		one("List", listed[0], err)
	}
	listed, _, err = repo.ListByOrganization(ctx, orgID, repository.ListUserOptions{})
	if len(listed) != 1 {
		t.Errorf("ListByOrganization = %d users (err %v); want 1", len(listed), err)
	} else {
		one("ListByOrganization", listed[0], err)
	}
	name := "Renamed"
	u, err = repo.Update(ctx, created.ID, orgID, repository.UpdateUserOptions{Name: &name})
	one("Update RETURNING (unrelated edit)", u, err)
	if _, err := pool.Exec(ctx, `UPDATE users SET mfa_recovery_codes = '["c2-code"]'::jsonb WHERE id = $1`, created.ID); err != nil {
		t.Fatalf("seed recovery code: %v", err)
	}
	u, ok, err := repo.ConsumeRecoveryCode(ctx, created.ID, "c2-code")
	if !ok {
		t.Errorf("ConsumeRecoveryCode did not claim (err %v)", err)
	}
	one("ConsumeRecoveryCode RETURNING", u, err)

	// Update's rules.
	no, yes := false, true
	adminSet, cleared := domain.EmailVerifiedViaAdminSet, ""
	u, err = repo.Update(ctx, created.ID, orgID, repository.UpdateUserOptions{EmailVerified: &yes, EmailVerifiedVia: &adminSet, KeepProvenEmailVerifiedVia: true})
	one("true over a proof (kept)", u, err)
	u, err = repo.Update(ctx, created.ID, orgID, repository.UpdateUserOptions{Email: &email})
	one("the same address again", u, err)
	moved := "c2-moved-" + uuid.NewString()[:8] + "@example.invalid"
	if u, err = repo.Update(ctx, created.ID, orgID, repository.UpdateUserOptions{Email: &moved}); err != nil || c2ViaOf(u) != adminSet {
		t.Errorf("an address change on an activated row: via %q (err %v); want admin_set", c2ViaOf(u), err)
	}
	if u, err = repo.Update(ctx, created.ID, orgID, repository.UpdateUserOptions{EmailVerified: &no, EmailVerifiedVia: &cleared}); err != nil || u.EmailVerifiedVia != nil {
		t.Errorf("false: via %q (err %v); want NULL", c2ViaOf(u), err)
	}
	other := "c2-other-" + uuid.NewString()[:8] + "@example.invalid"
	if u, err = repo.Update(ctx, created.ID, orgID, repository.UpdateUserOptions{Email: &other}); err != nil || u.EmailVerifiedVia != nil {
		t.Errorf("an address change on an unactivated row: via %q (err %v); want NULL", c2ViaOf(u), err)
	}

	if err := repo.Delete(ctx, created.ID, orgID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET email_verified_via = 'legacy' WHERE id = $1`, created.ID); err != nil {
		t.Fatalf("mark legacy: %v", err)
	}
	deleted, _, err := repo.ListDeleted(ctx, repository.Pagination{})
	seen := false
	for _, d := range deleted {
		if d.ID == created.ID {
			seen = true
			if c2ViaOf(d) != domain.EmailVerifiedViaLegacy {
				t.Errorf("ListDeleted via = %q; want legacy", c2ViaOf(d))
			}
		}
	}
	if !seen {
		t.Errorf("ListDeleted did not return the row (err %v)", err)
	}
}

// The organization activation's consume records admin_link, and keeps a
// proof recorded before it (the invite consume is covered end to end in
// internal/e2e).
func TestUserRepository_ConsumeActivationTokenRecordsAdminLink(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	repo := postgres.NewPgxUserRepository(pool)
	for _, c := range []struct {
		before *string
		want   string
	}{
		{nil, domain.EmailVerifiedViaAdminLink},
		{func() *string { s := domain.EmailVerifiedViaEmailLink; return &s }(), domain.EmailVerifiedViaEmailLink},
	} {
		orgID := uuid.MustParse(seedScratchOrg(t, pool))
		if _, err := pool.Exec(ctx, `UPDATE organizations SET active = false WHERE id = $1`, orgID); err != nil {
			t.Fatalf("deactivate org: %v", err)
		}
		hash := "c2-act-" + uuid.NewString()
		exp := time.Now().Add(time.Hour)
		if _, err := repo.Create(ctx, &domain.User{ID: uuid.New(), OrganizationID: orgID, Email: "c2-act-" + uuid.NewString()[:8] + "@example.invalid",
			PasswordHash: "c2-" + uuid.NewString(), Role: domain.RoleOrgAdmin, AuthSource: domain.AuthSourceLocal,
			EmailVerifiedVia: c.before, ActivationTokenHash: &hash, ActivationTokenExpiresAt: &exp}); err != nil {
			t.Fatalf("create pending admin: %v", err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE organization_id = $1`, orgID) })
		u, ok, err := repo.ConsumeActivationToken(ctx, hash, "$argon2id$v=19$m=65536,t=1,p=4$c2c2c2c2c2c2c2c2$c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2")
		if err != nil || !ok || !u.EmailVerified || c2ViaOf(u) != c.want {
			t.Errorf("consume activation (before %v): ok %v verified %v via %q (err %v); want true, true, %q", c.before, ok, u != nil && u.EmailVerified, c2ViaOf(u), err, c.want)
		}
	}
}
