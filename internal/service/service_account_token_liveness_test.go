package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// A service-account token is good only while its account is: active, not
// expired, and in an organization that is operational. The token itself stays
// signed and unexpired for its hour, so the check runs at use.

type fakeSAOrgs struct {
	orgs map[uuid.UUID]*domain.Organization
	err  error
}

func (f fakeSAOrgs) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	if f.err != nil {
		return nil, f.err
	}
	if o, ok := f.orgs[id]; ok {
		return o, nil
	}
	return nil, domain.ErrOrganizationNotFound
}

type errSARepo struct{ *inMemoryServiceAccountRepo }

func (errSARepo) GetByID(context.Context, uuid.UUID) (*domain.ServiceAccount, error) {
	return nil, errors.New("store down")
}

func TestServiceAccountTokenLiveness(t *testing.T) {
	ctx := context.Background()
	liveOrg, inactiveOrg, deletedOrg := uuid.New(), uuid.New(), uuid.New()
	deleted := time.Now().Add(-time.Hour)
	orgs := fakeSAOrgs{orgs: map[uuid.UUID]*domain.Organization{
		liveOrg:     {ID: liveOrg, Active: true},
		inactiveOrg: {ID: inactiveOrg, Active: false},
		deletedOrg:  {ID: deletedOrg, Active: true, DeletedAt: &deleted},
	}}
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	seed := func(org uuid.UUID, active bool, exp *time.Time) (*ServiceAccountService, string) {
		repo := newInMemorySARepo()
		id := uuid.New()
		repo.byID[id] = &domain.ServiceAccount{ID: id, OrganizationID: org, Active: active, ExpiresAt: exp, Role: domain.RoleOrgUser}
		return NewServiceAccountService(nil, repo), id.String()
	}

	cases := []struct {
		name  string
		build func() (*ServiceAccountService, string)
		want  bool
	}{
		{"active, unexpired, live organization", func() (*ServiceAccountService, string) { return seed(liveOrg, true, &future) }, true},
		{"no expiry", func() (*ServiceAccountService, string) { return seed(liveOrg, true, nil) }, true},
		{"disabled", func() (*ServiceAccountService, string) { return seed(liveOrg, false, nil) }, false},
		{"expired", func() (*ServiceAccountService, string) { return seed(liveOrg, true, &past) }, false},
		{"deleted account", func() (*ServiceAccountService, string) {
			s, _ := seed(liveOrg, true, nil)
			return s, uuid.NewString()
		}, false},
		{"a subject that is not an account id", func() (*ServiceAccountService, string) {
			s, _ := seed(liveOrg, true, nil)
			return s, "cli-1"
		}, false},
		{"organization deactivated", func() (*ServiceAccountService, string) { return seed(inactiveOrg, true, nil) }, false},
		{"organization deleted", func() (*ServiceAccountService, string) { return seed(deletedOrg, true, nil) }, false},
		{"organization gone", func() (*ServiceAccountService, string) { return seed(uuid.New(), true, nil) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, sub := tc.build()
			got, err := ServiceAccountTokenLiveness(svc, orgs)(ctx, sub)
			if err != nil || got != tc.want {
				t.Errorf("live = %v, %v; want %v, nil", got, err, tc.want)
			}
		})
	}

	t.Run("a store failure is an error, not a verdict", func(t *testing.T) {
		failing := NewServiceAccountService(nil, errSARepo{newInMemorySARepo()})
		if got, err := ServiceAccountTokenLiveness(failing, orgs)(ctx, uuid.NewString()); err == nil || got || !domain.IsAuthStoreUnavailable(err) {
			t.Errorf("account store down = %v, %v; want a store-unavailable error", got, err)
		}
		svc, sub := seed(liveOrg, true, nil)
		if got, err := ServiceAccountTokenLiveness(svc, fakeSAOrgs{err: errors.New("org store down")})(ctx, sub); err == nil || got || !domain.IsAuthStoreUnavailable(err) {
			t.Errorf("organization store down = %v, %v; want a store-unavailable error", got, err)
		}
	})
}
