//go:build integration

package postgres_test

// D-026 against the live SQL: the dynamically_registered marker is stored when
// an app is created through dynamic registration, comes back on every read,
// is never rewritten by an update, and the migration's backfill marks the apps
// that already hold a registration access token and clears their skip_consent.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/migrations"
)

func TestClientRepository_DynamicallyRegisteredMarker(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgID := uuid.MustParse(seedScratchOrg(t, pool))
	repo := postgres.NewPgxClientRepository(pool)

	register := func(name string, dynamic bool) *domain.Client {
		t.Helper()
		c := &domain.Client{
			ID: uuid.New(), Name: name, OrganizationID: &orgID,
			RedirectURIs: []string{"https://marker.example/cb"}, DynamicallyRegistered: dynamic,
		}
		if err := repo.RegisterClient(ctx, c); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		return c
	}
	dyn := register("dynamic", true)
	console := register("console", false)

	for _, tc := range []struct {
		c    *domain.Client
		want bool
	}{{dyn, true}, {console, false}} {
		byID, err := repo.GetClientByID(ctx, tc.c.ID)
		if err != nil || byID.DynamicallyRegistered != tc.want {
			t.Errorf("GetClientByID(%s) = %v, %v; want DynamicallyRegistered=%v", tc.c.Name, byID, err, tc.want)
		}
		byClientID, err := repo.GetClientByClientID(ctx, tc.c.ClientID)
		if err != nil || byClientID.DynamicallyRegistered != tc.want {
			t.Errorf("GetClientByClientID(%s) = %v, %v; want DynamicallyRegistered=%v", tc.c.Name, byClientID, err, tc.want)
		}
	}
	listed, _, err := repo.List(ctx, repository.Pagination{Page: 1, PageSize: 50}, &orgID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range listed {
		seen[c.Name] = c.DynamicallyRegistered
	}
	if !seen["dynamic"] || seen["console"] {
		t.Errorf("List markers = %v; want dynamic=true console=false", seen)
	}

	// An update never rewrites the marker, whatever the struct carries.
	stale := *dyn
	stale.DynamicallyRegistered = false
	stale.Name = "renamed"
	if err := repo.Update(ctx, &stale); err != nil {
		t.Fatalf("Update: %v", err)
	}
	after, err := repo.GetClientByID(ctx, dyn.ID)
	if err != nil || !after.DynamicallyRegistered || after.Name != "renamed" {
		t.Errorf("after Update = %v, %v; want the rename applied and DynamicallyRegistered still true", after, err)
	}
}

// The migration's backfill, run against rows: an app holding a registration
// access token is marked and loses skip_consent; a console app is untouched.
func TestMigration0044_BackfillMarksAppsHoldingARegistrationToken(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgID := seedScratchOrg(t, pool)
	org := uuid.MustParse(orgID)
	repo := postgres.NewPgxClientRepository(pool)

	mk := func(name string, skip bool) *domain.Client {
		t.Helper()
		c := &domain.Client{ID: uuid.New(), Name: name, OrganizationID: &org, RedirectURIs: []string{"https://backfill.example/cb"}, SkipConsent: skip}
		if err := repo.RegisterClient(ctx, c); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		return c
	}
	withToken := mk("has-token", true)
	console := mk("console", true)
	if _, err := pool.Exec(ctx, `INSERT INTO dcr_client_registration_tokens (client_id, token_hash, created_at, updated_at) VALUES ($1, 'h', NOW(), NOW())`, withToken.ID); err != nil {
		t.Fatalf("seed registration token: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM dcr_client_registration_tokens WHERE client_id = $1`, withToken.ID)
	})

	data, err := migrations.EmbedFS.ReadFile("0044_oauth_clients_dynamically_registered.sql")
	if err != nil {
		t.Fatalf("read 0044: %v", err)
	}
	up, _, _ := strings.Cut(string(data), "-- +goose Down")
	ran := 0
	for _, stmt := range strings.Split(up, ";") {
		var kept []string
		for _, line := range strings.Split(stmt, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") {
				kept = append(kept, line)
			}
		}
		if s := strings.TrimSpace(strings.Join(kept, "\n")); strings.HasPrefix(s, "UPDATE") {
			if _, err := pool.Exec(ctx, s); err != nil {
				t.Fatalf("backfill statement failed: %v", err)
			}
			ran++
		}
	}
	if ran != 2 {
		t.Fatalf("ran %d backfill statements, want 2", ran)
	}

	got, err := repo.GetClientByID(ctx, withToken.ID)
	if err != nil || !got.DynamicallyRegistered || got.SkipConsent {
		t.Errorf("app holding a registration token = %+v, %v; want marked and skip_consent cleared", got, err)
	}
	other, err := repo.GetClientByID(ctx, console.ID)
	if err != nil || other.DynamicallyRegistered || !other.SkipConsent {
		t.Errorf("console app = %+v, %v; want untouched (unmarked, skip_consent kept)", other, err)
	}
}
