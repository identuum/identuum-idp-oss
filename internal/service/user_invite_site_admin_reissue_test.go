package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// verifiedCountRepo gives the shared in-memory repository the production
// CountVerifiedOrgAdminsByOrganization query: org_admin, email_verified, not
// deleted, not banned, in the organization.
type verifiedCountRepo struct{ *inMemoryUserRepo }

func (r verifiedCountRepo) CountVerifiedOrgAdminsByOrganization(_ context.Context, org uuid.UUID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, u := range r.rows {
		if u.OrganizationID == org && u.Role == domain.RoleOrgAdmin && u.EmailVerified && u.DeletedAt == nil && !u.Banned {
			n++
		}
	}
	return n, nil
}

// D-025: the one tenant write a site_admin keeps is appointing the first
// org_admin of an organization that has none. Re-issuing the invite of a
// pending org_admin is part of that; it is refused once the organization has
// a verified org_admin, so it can never be used to take over a live one.
func TestReissueInviteForActor_SiteAdminOnlyForAnOrganizationWithoutAnActiveAdmin(t *testing.T) {
	ctx := context.Background()
	hash := "pending-invite-hash"
	fixed := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	cfg := UserInviteConfig{Now: func() time.Time { return fixed }}

	seed := func(repo *inMemoryUserRepo, org uuid.UUID, verified bool, withToken bool) uuid.UUID {
		id := uuid.New()
		seedRow(repo, id, org, domain.RoleOrgAdmin)
		repo.rows[id].EmailVerified = verified
		if withToken {
			h := hash
			repo.rows[id].ActivationTokenHash = &h
		}
		return id
	}

	t.Run("no verified admin yet: the pending first admin's invite is re-issued", func(t *testing.T) {
		repo := newUserRepo()
		svc := NewUserService(nil, verifiedCountRepo{repo}).WithInvite(cfg)
		org := uuid.New()
		pending := seed(repo, org, false, true)
		if _, _, _, err := svc.ReissueInviteForActor(ctx, siteAdminActor(), pending); err != nil {
			t.Errorf("re-issue for the first org_admin: %v", err)
		}
	})

	t.Run("a verified org_admin exists: refused", func(t *testing.T) {
		repo := newUserRepo()
		svc := NewUserService(nil, verifiedCountRepo{repo}).WithInvite(cfg)
		org := uuid.New()
		seed(repo, org, true, false) // the live admin
		pending := seed(repo, org, false, true)
		if _, _, _, err := svc.ReissueInviteForActor(ctx, siteAdminActor(), pending); !errors.Is(err, domain.ErrForbidden) {
			t.Errorf("re-issue while a verified org_admin exists: err=%v, want ErrForbidden", err)
		}
	})
}
