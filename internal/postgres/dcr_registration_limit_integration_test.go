//go:build integration

package postgres_test

// The limits an initial access token set on the client it registered, against
// the live SQL (migration 0049): stored and read back, empty lists kept as no
// limit, nil for a client registered without limits, gone with the client.

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestDCRRegistrationLimitRepository_RoundTripAndCascade(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgID := uuid.MustParse(seedScratchOrg(t, pool))
	clients := postgres.NewPgxClientRepository(pool)
	limits := postgres.NewPgxDCRRegistrationLimitRepository(pool)

	register := func(name string) *domain.Client {
		t.Helper()
		c := &domain.Client{ID: uuid.New(), Name: name, OrganizationID: &orgID, RedirectURIs: []string{"https://limits.example/cb"}}
		if err := clients.RegisterClient(ctx, c); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		return c
	}
	limited, open := register("limited"), register("open")

	if err := limits.SaveRegistrationLimits(ctx, limited.ID, domain.DCRRegistrationLimits{
		AllowedGrantTypes: []string{"authorization_code", "refresh_token"},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := limits.RegistrationLimits(ctx, limited.ID)
	if err != nil || got == nil || !slices.Equal(got.AllowedGrantTypes, []string{"authorization_code", "refresh_token"}) || len(got.AllowedTokenEndpointAuthMethods) != 0 {
		t.Fatalf("limits = %+v, %v; want the grant types and no auth-method limit", got, err)
	}
	if got, err := limits.RegistrationLimits(ctx, open.ID); err != nil || got != nil {
		t.Fatalf("a client without limits = %+v, %v; want nil", got, err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM oauth_clients WHERE id = $1`, limited.ID); err != nil {
		t.Fatalf("delete client: %v", err)
	}
	if got, err := limits.RegistrationLimits(ctx, limited.ID); err != nil || got != nil {
		t.Errorf("limits after the client's deletion = %+v, %v; want them gone with it", got, err)
	}
}
