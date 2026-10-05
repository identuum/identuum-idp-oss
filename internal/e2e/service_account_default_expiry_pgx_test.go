//go:build integration

// service_account_default_expiry_pgx_test.go — OSS-SA-EXPIRY against the real
// pgx repositories: a service account created without expires_at takes the
// organization's service_account_expiry_days as it is stored (rulings b, c),
// and an account that exists keeps its NULL expires_at when the organization's
// value changes later (ruling d). No migration rewrites existing rows.
//
// Requires IDENTUUM_IDP_TEST_DATABASE_URL (see oss_e2e_test.go).

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestSADefaultExpiry_StoredOrgValueAndExistingRowsUnchanged(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx := context.Background()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()

	bundleSvc, repos := bundleHarnessPgx(t, ctx, pool)
	orgID := seedBundleOrg(t, ctx, pool, repos)
	admin := bundleOrgAdmin(t, ctx, pool, orgID)
	saSvc := service.NewServiceAccountService(nil, repos.ServiceAccount).WithOrganizationExpiry(repos.Organization)

	setN := func(n int) {
		t.Helper()
		if _, err := repos.Organization.Update(ctx, orgID, repository.UpdateOrganizationOptions{ServiceAccountExpiryDays: &n}); err != nil {
			t.Fatalf("set service_account_expiry_days=%d: %v", n, err)
		}
	}

	// N = 0: no default expiry, on both create paths.
	setN(0)
	plain, err := saSvc.CreateForActor(ctx, admin, orgID, service.ServiceAccountAdminInput{Name: "plain-no-expiry"})
	if err != nil {
		t.Fatalf("create N=0: %v", err)
	}
	bundled, err := bundleSvc.CreateServiceAccountWithClientForActor(ctx, admin, orgID, service.BundleInput{SAName: "bundled-no-expiry"})
	if err != nil {
		t.Fatalf("bundle N=0: %v", err)
	}
	for _, id := range []string{plain.ID.String(), bundled.ServiceAccount.ID.String()} {
		var expires *time.Time
		if err := pool.QueryRow(ctx, "SELECT expires_at FROM service_accounts WHERE id = $1", id).Scan(&expires); err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		if expires != nil {
			t.Fatalf("N = 0 account %s stored expires_at %v, want NULL", id, expires)
		}
	}

	// N = 30: new accounts default to creation + 30 days; the two NULL rows stay NULL.
	setN(30)
	before := time.Now()
	dated, err := saSvc.CreateForActor(ctx, admin, orgID, service.ServiceAccountAdminInput{Name: "plain-dated"})
	if err != nil {
		t.Fatalf("create N=30: %v", err)
	}
	after := time.Now()
	var stored *time.Time
	if err := pool.QueryRow(ctx, "SELECT expires_at FROM service_accounts WHERE id = $1", dated.ID).Scan(&stored); err != nil {
		t.Fatalf("read dated: %v", err)
	}
	lo, hi := before.Add(30*24*time.Hour-time.Second), after.Add(30*24*time.Hour+time.Second)
	if stored == nil || stored.Before(lo) || stored.After(hi) {
		t.Fatalf("N = 30 stored expires_at %v, want within [%v, %v]", stored, lo, hi)
	}
	bundledDated, err := bundleSvc.CreateServiceAccountWithClientForActor(ctx, admin, orgID, service.BundleInput{SAName: "bundled-dated"})
	if err != nil {
		t.Fatalf("bundle N=30: %v", err)
	}
	if bundledDated.ServiceAccount.ExpiresAt == nil {
		t.Fatal("bundle N = 30 returned no expires_at")
	}
	for _, id := range []string{plain.ID.String(), bundled.ServiceAccount.ID.String()} {
		var expires *time.Time
		if err := pool.QueryRow(ctx, "SELECT expires_at FROM service_accounts WHERE id = $1", id).Scan(&expires); err != nil {
			t.Fatalf("re-read %s: %v", id, err)
		}
		if expires != nil {
			t.Fatalf("existing account %s changed to expires_at %v after N changed; ruling d keeps it NULL", id, expires)
		}
	}
}
