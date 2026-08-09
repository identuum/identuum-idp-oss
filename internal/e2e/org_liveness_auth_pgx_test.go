//go:build integration

// Package e2e — P0-3 regression: tenant deletion is an authentication
// boundary. Every auth-time credential LOOKUP whose parent organization is
// not operational (soft-deleted OR deactivated) — and every soft-deleted
// credential row under a live org — MUST fail to resolve. These pins run
// against real Postgres so the org-liveness JOIN / deleted_at filters that
// live in SQL are exercised end to end.
//
// Org-live predicate mirrored in SQL: organizations.deleted_at IS NULL AND
// organizations.active (domain.Organization.IsOperational).
//
// Run:
//
//	go test -tags integration -v ./internal/e2e/...
//
// Safety: no secret/hash/DB URL is echoed; each subtest hard-deletes its
// seed org on cleanup (FK ON DELETE CASCADE reaps the child rows).
package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func boolPtr(b bool) *bool { return &b }

func TestE2E_OSS_OrgLiveness_CredentialsRejected(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())

	// hardDeleteOrg cascades to children via the FK ON DELETE CASCADE.
	hardDeleteOrg := func(id uuid.UUID) {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", id)
	}

	// newActiveOrg seeds an active org and schedules its hard-delete cleanup.
	newActiveOrg := func(t *testing.T) uuid.UUID {
		t.Helper()
		suffix := uuid.NewString()
		org, err := repos.Organization.Create(ctx, &domain.Organization{
			Name:      "e2e-liveorg-" + suffix,
			Domain:    "e2e-liveorg-" + suffix + ".example.invalid",
			OrgSlug:   "e2e-liveorg-" + suffix[:8],
			Active:    true,
			MFAPolicy: "optional",
		})
		if err != nil {
			t.Fatalf("seed org: %v", err)
		}
		t.Cleanup(func() { hardDeleteOrg(org.ID) })
		return org.ID
	}

	deactivate := func(t *testing.T, orgID uuid.UUID) {
		t.Helper()
		if _, err := repos.Organization.Update(ctx, orgID, repository.UpdateOrganizationOptions{Active: boolPtr(false)}); err != nil {
			t.Fatalf("deactivate org: %v", err)
		}
	}
	softDeleteOrg := func(t *testing.T, orgID uuid.UUID) {
		t.Helper()
		if err := repos.Organization.Delete(ctx, orgID); err != nil {
			t.Fatalf("soft-delete org: %v", err)
		}
	}

	// ── OAuth client (P0-3b) ────────────────────────────────────────────────
	seedClient := func(t *testing.T, orgID uuid.UUID) string {
		t.Helper()
		clientID := "e2e-cli-" + uuid.NewString()
		oid := orgID
		if err := repos.Client.RegisterClient(ctx, &domain.Client{
			ID:                      uuid.New(),
			OrganizationID:          &oid,
			ClientID:                clientID,
			Name:                    "e2e client",
			ClientSecretHash:        "placeholder-not-a-real-hash",
			RedirectURIs:            []string{"https://app.example.com/cb"},
			Scope:                   "openid",
			IsPublic:                false,
			TokenEndpointAuthMethod: "client_secret_basic",
		}); err != nil {
			t.Fatalf("seed client: %v", err)
		}
		return clientID
	}

	t.Run("oauth_client/live_org_resolves", func(t *testing.T) {
		clientID := seedClient(t, newActiveOrg(t))
		got, _ := repos.Client.GetClientByClientID(ctx, clientID)
		if got == nil {
			t.Fatalf("live org: client must resolve")
		}
	})
	t.Run("oauth_client/deactivated_org_rejected", func(t *testing.T) {
		orgID := newActiveOrg(t)
		clientID := seedClient(t, orgID)
		deactivate(t, orgID)
		if got, _ := repos.Client.GetClientByClientID(ctx, clientID); got != nil {
			t.Fatalf("deactivated org: client MUST NOT resolve")
		}
	})
	t.Run("oauth_client/deleted_org_rejected", func(t *testing.T) {
		orgID := newActiveOrg(t)
		clientID := seedClient(t, orgID)
		softDeleteOrg(t, orgID)
		if got, _ := repos.Client.GetClientByClientID(ctx, clientID); got != nil {
			t.Fatalf("deleted org: client MUST NOT resolve")
		}
	})
	t.Run("oauth_client/soft_deleted_row_live_org_rejected", func(t *testing.T) {
		orgID := newActiveOrg(t)
		clientID := seedClient(t, orgID)
		if _, err := pool.Exec(ctx, "UPDATE oauth_clients SET deleted_at = now() WHERE client_id = $1", clientID); err != nil {
			t.Fatalf("soft-delete client: %v", err)
		}
		if got, _ := repos.Client.GetClientByClientID(ctx, clientID); got != nil {
			t.Fatalf("soft-deleted client under live org: MUST NOT resolve")
		}
	})

	// ── API resource (P0-3a) ────────────────────────────────────────────────
	seedAPIResource := func(t *testing.T, orgID uuid.UUID) string {
		t.Helper()
		audience := "https://api-" + uuid.NewString() + ".example.com"
		if err := repos.APIResource.Create(ctx, &domain.APIResource{
			ID:                 uuid.New(),
			OrganizationID:     orgID,
			Name:               "e2e api",
			Audience:           audience,
			Active:             true,
			TokenTTLSecs:       3600,
			ResourceSecretHash: "placeholder-not-a-real-hash",
		}, []domain.APIScope{{Name: "read"}}); err != nil {
			t.Fatalf("seed api resource: %v", err)
		}
		return audience
	}

	t.Run("api_resource/live_org_resolves", func(t *testing.T) {
		aud := seedAPIResource(t, newActiveOrg(t))
		got, _ := repos.APIResource.GetByAudienceGlobal(ctx, aud)
		if got == nil {
			t.Fatalf("live org: api resource must resolve")
		}
	})
	t.Run("api_resource/deactivated_org_rejected", func(t *testing.T) {
		orgID := newActiveOrg(t)
		aud := seedAPIResource(t, orgID)
		deactivate(t, orgID)
		if got, _ := repos.APIResource.GetByAudienceGlobal(ctx, aud); got != nil {
			t.Fatalf("deactivated org: api resource MUST NOT resolve")
		}
	})
	t.Run("api_resource/deleted_org_rejected", func(t *testing.T) {
		orgID := newActiveOrg(t)
		aud := seedAPIResource(t, orgID)
		softDeleteOrg(t, orgID)
		if got, _ := repos.APIResource.GetByAudienceGlobal(ctx, aud); got != nil {
			t.Fatalf("deleted org: api resource MUST NOT resolve")
		}
	})

	// ── Identity provider (P0-3c) ───────────────────────────────────────────
	seedProvider := func(t *testing.T, orgID uuid.UUID) uuid.UUID {
		t.Helper()
		providerID, _ := uuid.NewV7()
		if _, err := pool.Exec(ctx,
			`INSERT INTO identity_providers (id, organization_id, type, name, slug)
			 VALUES ($1, $2, 'oidc', 'e2e-provider', $3)`,
			providerID, orgID, "e2e-idp-"+uuid.NewString()[:8]); err != nil {
			t.Fatalf("seed provider: %v", err)
		}
		return providerID
	}

	t.Run("identity_provider/live_org_resolves", func(t *testing.T) {
		pid := seedProvider(t, newActiveOrg(t))
		got, _ := repos.IdentityProvider.GetByID(ctx, pid)
		if got == nil {
			t.Fatalf("live org: provider must resolve")
		}
	})
	t.Run("identity_provider/deactivated_org_rejected", func(t *testing.T) {
		orgID := newActiveOrg(t)
		pid := seedProvider(t, orgID)
		deactivate(t, orgID)
		if got, _ := repos.IdentityProvider.GetByID(ctx, pid); got != nil {
			t.Fatalf("deactivated org: provider MUST NOT resolve")
		}
	})
	t.Run("identity_provider/deleted_org_rejected", func(t *testing.T) {
		orgID := newActiveOrg(t)
		pid := seedProvider(t, orgID)
		softDeleteOrg(t, orgID)
		if got, _ := repos.IdentityProvider.GetByID(ctx, pid); got != nil {
			t.Fatalf("deleted org: provider MUST NOT resolve")
		}
	})
	t.Run("identity_provider/soft_deleted_row_live_org_rejected", func(t *testing.T) {
		orgID := newActiveOrg(t)
		pid := seedProvider(t, orgID)
		if _, err := pool.Exec(ctx, "UPDATE identity_providers SET deleted_at = now() WHERE id = $1", pid); err != nil {
			t.Fatalf("soft-delete provider: %v", err)
		}
		if got, _ := repos.IdentityProvider.GetByID(ctx, pid); got != nil {
			t.Fatalf("soft-deleted provider under live org: MUST NOT resolve")
		}
	})

	// ── P3-13: the SOFT-DELETE boundary is repository-wide, not method- ─────
	// shaped. The org-delete cascade is the ONLY writer of deleted_at on
	// oauth_clients and identity_providers (both repos' own Delete methods
	// are HARD deletes), so a soft-deleted row IS a deleted org's tombstone.
	// These pins prove the admin-surface lookups (by-UUID get, listings, the
	// org+type lookup) can no longer see tombstones — previously a deleted
	// org's client stayed readable, updatable and secret-regenerable by UUID.

	// seedClientRow mirrors seedClient but returns the row UUID for by-ID reads.
	seedClientRow := func(t *testing.T, orgID uuid.UUID) (uuid.UUID, string) {
		t.Helper()
		id := uuid.New()
		clientID := "e2e-cli-" + uuid.NewString()
		oid := orgID
		if err := repos.Client.RegisterClient(ctx, &domain.Client{
			ID:                      id,
			OrganizationID:          &oid,
			ClientID:                clientID,
			Name:                    "e2e client",
			ClientSecretHash:        "placeholder-not-a-real-hash",
			RedirectURIs:            []string{"https://app.example.com/cb"},
			Scope:                   "openid",
			IsPublic:                false,
			TokenEndpointAuthMethod: "client_secret_basic",
		}); err != nil {
			t.Fatalf("seed client: %v", err)
		}
		return id, clientID
	}

	t.Run("oauth_client/by_id_live_org_resolves", func(t *testing.T) {
		id, _ := seedClientRow(t, newActiveOrg(t))
		if got, _ := repos.Client.GetClientByID(ctx, id); got == nil {
			t.Fatalf("live org: client must resolve by UUID")
		}
	})
	t.Run("oauth_client/by_id_deleted_org_tombstone_rejected", func(t *testing.T) {
		orgID := newActiveOrg(t)
		id, _ := seedClientRow(t, orgID)
		softDeleteOrg(t, orgID) // cascade soft-deletes the client row
		if got, _ := repos.Client.GetClientByID(ctx, id); got != nil {
			t.Fatalf("deleted org: client MUST NOT resolve by UUID (admin read/update/secret-regen path)")
		}
	})
	t.Run("oauth_client/by_id_soft_deleted_row_live_org_rejected", func(t *testing.T) {
		orgID := newActiveOrg(t)
		id, _ := seedClientRow(t, orgID)
		if _, err := pool.Exec(ctx, "UPDATE oauth_clients SET deleted_at = now() WHERE id = $1", id); err != nil {
			t.Fatalf("soft-delete client row: %v", err)
		}
		if got, _ := repos.Client.GetClientByID(ctx, id); got != nil {
			t.Fatalf("soft-deleted client row: MUST NOT resolve by UUID")
		}
	})
	t.Run("oauth_client/list_excludes_tombstones", func(t *testing.T) {
		orgID := newActiveOrg(t)
		liveID, _ := seedClientRow(t, orgID)
		deadID, _ := seedClientRow(t, orgID)
		if _, err := pool.Exec(ctx, "UPDATE oauth_clients SET deleted_at = now() WHERE id = $1", deadID); err != nil {
			t.Fatalf("soft-delete client row: %v", err)
		}
		page := repository.Pagination{Page: 1, PageSize: 50}
		clients, total, err := repos.Client.List(ctx, page, &orgID)
		if err != nil {
			t.Fatalf("list clients: %v", err)
		}
		if total != 1 || len(clients) != 1 || clients[0].ID != liveID {
			t.Fatalf("list must exclude tombstones: total=%d len=%d", total, len(clients))
		}
	})

	t.Run("identity_provider/by_org_type_live_resolves", func(t *testing.T) {
		orgID := newActiveOrg(t)
		seedProvider(t, orgID)
		if got, _ := repos.IdentityProvider.GetByOrgAndType(ctx, orgID, domain.IdentityProviderType("oidc")); got == nil {
			t.Fatalf("live provider: must resolve by org+type")
		}
	})
	t.Run("identity_provider/by_org_type_soft_deleted_rejected", func(t *testing.T) {
		orgID := newActiveOrg(t)
		pid := seedProvider(t, orgID)
		if _, err := pool.Exec(ctx, "UPDATE identity_providers SET deleted_at = now() WHERE id = $1", pid); err != nil {
			t.Fatalf("soft-delete provider: %v", err)
		}
		if got, _ := repos.IdentityProvider.GetByOrgAndType(ctx, orgID, domain.IdentityProviderType("oidc")); got != nil {
			t.Fatalf("soft-deleted provider: MUST NOT resolve by org+type")
		}
	})
	t.Run("identity_provider/list_excludes_tombstones", func(t *testing.T) {
		orgID := newActiveOrg(t)
		livePID := seedProvider(t, orgID)
		// Second provider needs a distinct priority (unique org+type+priority)
		// and is seeded ALREADY soft-deleted.
		deadPID, _ := uuid.NewV7()
		if _, err := pool.Exec(ctx,
			`INSERT INTO identity_providers (id, organization_id, type, name, slug, priority, deleted_at)
			 VALUES ($1, $2, 'oidc', 'e2e-dead-provider', $3, 2, now())`,
			deadPID, orgID, "e2e-idp-dead-"+uuid.NewString()[:8]); err != nil {
			t.Fatalf("seed dead provider: %v", err)
		}
		rows, err := repos.IdentityProvider.ListByOrganization(ctx, orgID)
		if err != nil {
			t.Fatalf("list providers: %v", err)
		}
		if len(rows) != 1 || rows[0].ID != livePID {
			t.Fatalf("provider list must exclude tombstones: len=%d", len(rows))
		}
		_ = deadPID
	})

	// ── P3-14: the WRITE side of the boundary — tombstones are INERT ────────
	// (immutable, not just invisible), and the site-admin nil-org delete
	// works instead of panicking.

	rowState := func(t *testing.T, id uuid.UUID) (exists bool, tombstoned bool) {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM oauth_clients WHERE id = $1", id).Scan(&n); err != nil {
			t.Fatalf("count client row: %v", err)
		}
		if n == 0 {
			return false, false
		}
		var deletedAt *time.Time
		if err := pool.QueryRow(ctx, "SELECT deleted_at FROM oauth_clients WHERE id = $1", id).Scan(&deletedAt); err != nil {
			t.Fatalf("read client row: %v", err)
		}
		return true, deletedAt != nil
	}

	t.Run("oauth_client/site_admin_nil_org_delete_works", func(t *testing.T) {
		orgID := newActiveOrg(t)
		id, _ := seedClientRow(t, orgID)
		// P3-14 PART A: this exact call shape (nil orgID, the mounted
		// site-admin route's semantic) panicked before the fix.
		if err := repos.Client.Delete(ctx, id, nil); err != nil {
			t.Fatalf("site-admin delete (nil orgID): %v", err)
		}
		if exists, _ := rowState(t, id); exists {
			t.Fatalf("live client must be hard-deleted by the site-admin route")
		}
	})
	t.Run("oauth_client/tombstone_hard_delete_refused", func(t *testing.T) {
		orgID := newActiveOrg(t)
		id, _ := seedClientRow(t, orgID)
		softDeleteOrg(t, orgID)               // cascade tombstones the client
		_ = repos.Client.Delete(ctx, id, nil) // idempotent-delete semantic: no error either way
		exists, tombstoned := rowState(t, id)
		if !exists || !tombstoned {
			t.Fatalf("tombstone must SURVIVE a hard-delete attempt (exists=%v tombstoned=%v) — org Undelete could no longer restore it (P3-14 PART B)", exists, tombstoned)
		}
	})
	t.Run("oauth_client/tombstone_update_refused", func(t *testing.T) {
		orgID := newActiveOrg(t)
		id, _ := seedClientRow(t, orgID)
		softDeleteOrg(t, orgID)
		var before string
		if err := pool.QueryRow(ctx, "SELECT name FROM oauth_clients WHERE id = $1", id).Scan(&before); err != nil {
			t.Fatalf("read tombstone: %v", err)
		}
		oid := orgID
		_ = repos.Client.Update(ctx, &domain.Client{
			ID:                      id,
			OrganizationID:          &oid,
			ClientID:                "e2e-mutated",
			Name:                    "MUTATED",
			ClientSecretHash:        "mutated-hash",
			RedirectURIs:            []string{"https://evil.example.com/cb"},
			Scope:                   "openid",
			TokenEndpointAuthMethod: "client_secret_basic",
		})
		var after string
		if err := pool.QueryRow(ctx, "SELECT name FROM oauth_clients WHERE id = $1", id).Scan(&after); err != nil {
			t.Fatalf("re-read tombstone: %v", err)
		}
		if after != before {
			t.Fatalf("tombstone was UPDATED (%q -> %q) — writes must not touch a deleted org's rows (P3-14 PART B)", before, after)
		}
	})
	t.Run("identity_provider/tombstone_delete_refused", func(t *testing.T) {
		orgID := newActiveOrg(t)
		pid := seedProvider(t, orgID)
		softDeleteOrg(t, orgID) // cascade tombstones the provider
		if err := repos.IdentityProvider.Delete(ctx, pid, orgID); err == nil {
			t.Fatalf("tombstoned provider delete must report not-found (rows affected 0)")
		}
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM identity_providers WHERE id = $1", pid).Scan(&n); err != nil {
			t.Fatalf("count provider row: %v", err)
		}
		if n != 1 {
			t.Fatalf("tombstoned provider must SURVIVE a delete attempt, rows=%d", n)
		}
	})
}
