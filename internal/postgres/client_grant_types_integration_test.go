//go:build integration

package postgres_test

// The grant types a client registered, against the live SQL: stored by the
// create, returned by every read, rewritten by an update, NULL (unrestricted)
// when none were registered, and refused by the schema when they name a grant
// the token endpoint does not serve.

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func TestClientRepository_GrantTypesRoundTrip(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgID := uuid.MustParse(seedScratchOrg(t, pool))
	repo := postgres.NewPgxClientRepository(pool)

	register := func(name string, grants []string) *domain.Client {
		t.Helper()
		c := &domain.Client{
			ID: uuid.New(), Name: name, OrganizationID: &orgID,
			RedirectURIs: []string{"https://grants.example/cb"}, GrantTypes: grants,
		}
		if err := repo.RegisterClient(ctx, c); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		return c
	}
	restricted := register("restricted", []string{"authorization_code", "refresh_token"})
	open := register("open", nil)

	for _, tc := range []struct {
		c    *domain.Client
		want []string
	}{{restricted, []string{"authorization_code", "refresh_token"}}, {open, nil}} {
		byID, err := repo.GetClientByID(ctx, tc.c.ID)
		if err != nil || !slices.Equal(byID.GrantTypes, tc.want) {
			t.Errorf("GetClientByID(%s) = %v, %v; want GrantTypes %v", tc.c.Name, byID, err, tc.want)
		}
		byClientID, err := repo.GetClientByClientID(ctx, tc.c.ClientID)
		if err != nil || !slices.Equal(byClientID.GrantTypes, tc.want) {
			t.Errorf("GetClientByClientID(%s) = %v, %v; want GrantTypes %v", tc.c.Name, byClientID, err, tc.want)
		}
	}
	listed, _, err := repo.List(ctx, repository.Pagination{Page: 1, PageSize: 50}, &orgID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	seen := map[string][]string{}
	for _, c := range listed {
		seen[c.Name] = c.GrantTypes
	}
	if !slices.Equal(seen["restricted"], []string{"authorization_code", "refresh_token"}) || len(seen["open"]) != 0 {
		t.Errorf("List grant types = %v; want restricted=[authorization_code refresh_token] open=none", seen)
	}

	// An update carries the set it is given.
	changed := *restricted
	changed.GrantTypes = []string{"authorization_code"}
	if err := repo.Update(ctx, &changed); err != nil {
		t.Fatalf("Update: %v", err)
	}
	after, err := repo.GetClientByID(ctx, restricted.ID)
	if err != nil || !slices.Equal(after.GrantTypes, []string{"authorization_code"}) {
		t.Errorf("after Update = %v, %v; want GrantTypes [authorization_code]", after, err)
	}

	// The schema refuses a grant the token endpoint does not serve.
	bad := &domain.Client{
		ID: uuid.New(), Name: "bad", OrganizationID: &orgID,
		RedirectURIs: []string{"https://grants.example/cb"}, GrantTypes: []string{"password"},
	}
	if err := repo.RegisterClient(ctx, bad); err == nil {
		t.Error("a client with the grant type \"password\" was stored; want the check constraint to refuse it")
	}
}
