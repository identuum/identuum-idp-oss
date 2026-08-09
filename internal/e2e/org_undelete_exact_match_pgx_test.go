//go:build integration

// org_undelete_exact_match_pgx_test.go — P2-14: org Undelete must reverse
// ONLY the org's OWN cascade, never a child that was deleted independently.
//
// Delete stamps ONE Go time.Now() (Torg) onto the org AND every child it
// cascades (users / service_accounts / identity_providers / oauth_clients)
// in one tx, so org.deleted_at == every cascade-child's deleted_at EXACTLY.
// Undelete restores children on an EXACT match of that instant — the precise
// inverse of the cascade. A child soft-deleted INDEPENDENTLY (a DIFFERENT
// deleted_at, whether 1s or 1h from Torg) is NOT part of the cascade and MUST
// stay deleted.
//
// The prior code matched children with `deleted_at BETWEEN Torg-2s AND
// Torg+2s`. That ±2s window over-restored: an independent delete landing
// inside the window was wrongly resurrected (the P2-14 data-integrity bug).
//
// TEETH: revert Undelete's child UPDATEs to the BETWEEN window and
// TestOrgUndelete_ExactMatch_OverRestoreDead fails — user X (deleted at
// Torg-1s, inside the old window) comes back to life.
//
// Requires IDENTUUM_IDP_TEST_DATABASE_URL (see oss_e2e_test.go).

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// undeleteFixture is the seeded world: one org with a cascade child in EACH
// of the four soft-deletable tables, plus two independently-deleted users
// (X inside the old ±2s window, Z one hour out).
type undeleteFixture struct {
	orgID uuid.UUID
	// cascade children — deleted by Delete(org), must be restored by Undelete.
	userCascadeID uuid.UUID
	saID          uuid.UUID
	idpID         uuid.UUID
	clientID      uuid.UUID
	// independent children — deleted BEFORE Delete(org), must STAY deleted.
	userXID uuid.UUID // deleted at Torg-1s (inside old window) — the teeth
	userZID uuid.UUID // deleted at Torg-1h (far outside)
	txDel   time.Time // X's independent deleted_at
	tzDel   time.Time // Z's independent deleted_at
}

func seedUndeleteFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repos *postgres.Repositories) undeleteFixture {
	t.Helper()
	sfx := uuid.NewString()[:8]

	orgID, _ := uuid.NewV7()
	org := &domain.Organization{
		ID:        orgID,
		Name:      "e2e-undel-org-" + sfx,
		Domain:    "e2e-undel-" + sfx + ".example.invalid",
		OrgSlug:   "e2e-undel-" + sfx,
		Active:    true,
		MFAPolicy: "optional",
	}
	createdOrg, err := repos.Organization.Create(ctx, org)
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	orgID = createdOrg.ID // Create may assign its own ID; use the persisted one.
	// Hard-delete the org in cleanup: every child table FKs organizations with
	// ON DELETE CASCADE, so this tears the whole world down in one shot.
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", orgID)
	})

	newUser := func(tag string) uuid.UUID {
		uid, _ := uuid.NewV7()
		u := &domain.User{
			ID:             uid,
			OrganizationID: orgID,
			Email:          tag + "-" + uuid.NewString() + "@example.invalid",
			Role:           domain.RoleOrgUser,
			PasswordHash:   "init-" + uuid.NewString() + "-not-printed",
			AuthSource:     domain.AuthSourceLocal,
		}
		if _, err := repos.User.Create(ctx, u); err != nil {
			t.Fatalf("seed user %s: %v", tag, err)
		}
		return uid
	}

	f := undeleteFixture{orgID: orgID}
	f.userCascadeID = newUser("cascade")
	f.userXID = newUser("independent-x")
	f.userZID = newUser("independent-z")

	// One cascade child in each of the other three tables. Minimal NOT-NULL
	// columns only; oauth_clients keeps the default client_secret_basic auth
	// method with both jwks columns NULL to satisfy its CASE key-source CHECK.
	f.saID, _ = uuid.NewV7()
	if _, err := pool.Exec(ctx,
		`INSERT INTO service_accounts (id, organization_id, name) VALUES ($1, $2, $3)`,
		f.saID, orgID, "sa-"+sfx); err != nil {
		t.Fatalf("seed service_account: %v", err)
	}
	f.idpID, _ = uuid.NewV7()
	if _, err := pool.Exec(ctx,
		`INSERT INTO identity_providers (id, organization_id, type, name, slug) VALUES ($1, $2, $3, $4, $5)`,
		f.idpID, orgID, "oidc", "idp-"+sfx, "idp-"+sfx); err != nil {
		t.Fatalf("seed identity_provider: %v", err)
	}
	f.clientID, _ = uuid.NewV7()
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_clients (id, client_id, client_secret_hash, name, redirect_uris, scope, organization_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		f.clientID, "client-"+sfx, "hash-not-printed", "client-"+sfx,
		[]string{"https://" + sfx + ".example.invalid/cb"}, "openid", orgID); err != nil {
		t.Fatalf("seed oauth_client: %v", err)
	}

	return f
}

// independentDelete soft-deletes a single user at an explicit instant WITHOUT
// going through the org cascade — this is the "some other operation deleted
// this child on its own" case Undelete must never touch.
func independentDelete(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, at time.Time) {
	t.Helper()
	ct, err := pool.Exec(ctx, `UPDATE users SET deleted_at = $1 WHERE id = $2`, at, userID)
	if err != nil {
		t.Fatalf("independent delete user %s: %v", userID, err)
	}
	if ct.RowsAffected() != 1 {
		t.Fatalf("independent delete user %s: affected %d rows, want 1", userID, ct.RowsAffected())
	}
}

func userDeletedAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) *time.Time {
	return deletedAt(t, ctx, pool, "users", id)
}

func deletedAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string, id uuid.UUID) *time.Time {
	t.Helper()
	var d *time.Time
	// Table names are compile-time constants from this test, never user input.
	if err := pool.QueryRow(ctx, "SELECT deleted_at FROM "+table+" WHERE id = $1", id).Scan(&d); err != nil {
		t.Fatalf("read %s.deleted_at (%s): %v", table, id, err)
	}
	return d
}

// TestOrgUndelete_ExactMatch_OverRestoreDead is the P2-14 teeth. An
// independent delete of user X lands at Torg-1s — inside the OLD ±2s window
// but at a DIFFERENT instant than the cascade. After Undelete, X MUST stay
// deleted while the org's own cascade (a child in every table) is restored.
//
// Revert Undelete to `deleted_at BETWEEN Torg-2s AND Torg+2s` and this test
// fails: X's Torg-1s falls in the window and X is wrongly resurrected.
func TestOrgUndelete_ExactMatch_OverRestoreDead(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx := context.Background()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())

	f := seedUndeleteFixture(t, ctx, pool, repos)

	// Independently delete X at ~Torg-1s and Z at ~Torg-1h, BEFORE Delete(org).
	// Because they already carry a deleted_at, Delete's cascade
	// (WHERE deleted_at IS NULL) skips them — they are not part of the cascade.
	f.txDel = time.Now().Add(-1 * time.Second).UTC()
	f.tzDel = time.Now().Add(-1 * time.Hour).UTC()
	independentDelete(t, ctx, pool, f.userXID, f.txDel)
	independentDelete(t, ctx, pool, f.userZID, f.tzDel)

	// Cascade-delete the org: stamps Torg on the org + every still-live child.
	if err := repos.Organization.Delete(ctx, f.orgID); err != nil {
		t.Fatalf("Delete org: %v", err)
	}

	// INVARIANT PIN: org.deleted_at == each cascaded child's deleted_at across
	// all four tables. This is the property that makes exact-match the precise
	// inverse of the cascade.
	torg := deletedAt(t, ctx, pool, "organizations", f.orgID)
	if torg == nil {
		t.Fatal("org.deleted_at is nil after Delete")
	}
	for _, c := range []struct {
		table string
		id    uuid.UUID
	}{
		{"users", f.userCascadeID},
		{"service_accounts", f.saID},
		{"identity_providers", f.idpID},
		{"oauth_clients", f.clientID},
	} {
		got := deletedAt(t, ctx, pool, c.table, c.id)
		if got == nil || !got.Equal(*torg) {
			t.Fatalf("invariant pin: %s cascade child deleted_at=%v, want == org.deleted_at=%v", c.table, got, *torg)
		}
	}
	// The independent deletes must carry a DIFFERENT instant than the cascade,
	// else the scenario is vacuous.
	if xd := userDeletedAt(t, ctx, pool, f.userXID); xd == nil || xd.Equal(*torg) {
		t.Fatalf("setup: user X deleted_at=%v must differ from Torg=%v", xd, *torg)
	}
	// X must be inside the OLD ±2s window so BETWEEN would have grabbed it —
	// that is what makes this a real regression test for the window bug.
	if d := torg.Sub(f.txDel); d < 0 || d > 2*time.Second {
		t.Fatalf("setup: X at Torg-%v is not inside the old ±2s window; test would not exercise the bug", d)
	}

	// Undelete: restore ONLY the org's own cascade.
	if err := repos.Organization.Undelete(ctx, f.orgID); err != nil {
		t.Fatalf("Undelete org: %v", err)
	}

	// TEETH: X (independent, Torg-1s) STAYS deleted.
	if xd := userDeletedAt(t, ctx, pool, f.userXID); xd == nil {
		t.Fatal("OVER-RESTORE: independently-deleted user X (Torg-1s) was wrongly restored by Undelete")
	}
	// Z (independent, Torg-1h) STAYS deleted.
	if zd := userDeletedAt(t, ctx, pool, f.userZID); zd == nil {
		t.Fatal("FAR-INDEPENDENT: independently-deleted user Z (Torg-1h) was wrongly restored by Undelete")
	}

	// NO UNDER-RESTORE: every cascade child (all four tables) + the org itself
	// is restored (deleted_at cleared).
	if od := deletedAt(t, ctx, pool, "organizations", f.orgID); od != nil {
		t.Fatalf("org itself not restored: deleted_at=%v", *od)
	}
	for _, c := range []struct {
		table string
		id    uuid.UUID
	}{
		{"users", f.userCascadeID},
		{"service_accounts", f.saID},
		{"identity_providers", f.idpID},
		{"oauth_clients", f.clientID},
	} {
		if got := deletedAt(t, ctx, pool, c.table, c.id); got != nil {
			t.Fatalf("UNDER-RESTORE: %s cascade child not restored: deleted_at=%v", c.table, *got)
		}
	}
}
