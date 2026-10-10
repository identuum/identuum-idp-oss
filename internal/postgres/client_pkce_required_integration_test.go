//go:build integration

package postgres_test

// OSS-PUBLIC-CLIENT-PKCE-OPTION against the live SQL (migration 0052): a row
// written without naming pkce_required — every row that existed before the
// column — is PKCE required; a public client's opt-out is stored, read back by
// every read and reversed by an update; and the schema refuses an opt-out on a
// confidential client.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func TestClientRepository_PKCERequiredRoundTrip(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgID := uuid.MustParse(seedScratchOrg(t, pool))
	repo := postgres.NewPgxClientRepository(pool)

	// A row inserted without the column, as every pre-0052 row was, takes
	// the column default.
	legacyID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO oauth_clients (id, client_id, client_secret_hash, name, organization_id, redirect_uris, scope, is_public, token_endpoint_auth_method)
		VALUES ($1, $2, '', 'legacy public', $3, ARRAY['https://pkce.example/cb'], 'openid', true, 'none')`, legacyID, "legacy-"+legacyID.String()[:8], orgID); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	legacy, err := repo.GetClientByID(ctx, legacyID)
	if err != nil || legacy.PKCEOptOut || !legacy.RequiresPKCE() {
		t.Fatalf("legacy row = %+v, %v; want PKCE required", legacy, err)
	}

	register := func(name string, public, optOut bool) *domain.Client {
		t.Helper()
		c := &domain.Client{
			ID: uuid.New(), Name: name, OrganizationID: &orgID, IsPublic: public, PKCEOptOut: optOut,
			RedirectURIs: []string{"https://pkce.example/cb"},
		}
		if err := repo.RegisterClient(ctx, c); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		return c
	}
	defaulted := register("public default", true, false)
	optedOut := register("public opted out", true, true)

	for _, tc := range []struct {
		c          *domain.Client
		wantOptOut bool
	}{{defaulted, false}, {optedOut, true}} {
		byID, err := repo.GetClientByID(ctx, tc.c.ID)
		if err != nil || byID.PKCEOptOut != tc.wantOptOut {
			t.Errorf("GetClientByID(%s) = %v, %v; want PKCEOptOut %v", tc.c.Name, byID, err, tc.wantOptOut)
		}
		byClientID, err := repo.GetClientByClientID(ctx, tc.c.ClientID)
		if err != nil || byClientID.PKCEOptOut != tc.wantOptOut {
			t.Errorf("GetClientByClientID(%s) = %v, %v; want PKCEOptOut %v", tc.c.Name, byClientID, err, tc.wantOptOut)
		}
	}
	listed, _, err := repo.List(ctx, repository.Pagination{Page: 1, PageSize: 50}, &orgID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range listed {
		seen[c.Name] = c.PKCEOptOut
	}
	if seen["public opted out"] != true || seen["public default"] != false || seen["legacy public"] != false {
		t.Errorf("List opt-outs = %v; want only the opted-out client off", seen)
	}

	// An update turns it back on.
	back := *optedOut
	back.PKCEOptOut = false
	if err := repo.Update(ctx, &back); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if after, err := repo.GetClientByID(ctx, optedOut.ID); err != nil || after.PKCEOptOut {
		t.Errorf("after Update = %v, %v; want PKCE required again", after, err)
	}

	// The schema refuses an opt-out on a confidential client.
	bad := &domain.Client{
		ID: uuid.New(), Name: "confidential opted out", OrganizationID: &orgID, PKCEOptOut: true,
		RedirectURIs: []string{"https://pkce.example/cb"},
	}
	if err := repo.RegisterClient(ctx, bad); err == nil {
		t.Error("a confidential client with pkce_required false was stored; want the check constraint to refuse it")
	}
}
