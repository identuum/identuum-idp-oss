//go:build integration

// service_account_client_bundle_pgx_test.go — P2-16b: the SA+client bundle
// must be a SINGLE transaction. Happy path creates both rows bound
// together; a client-insert failure rolls the whole thing back so no orphan
// service account is left behind.
//
// TEETH: revert PgxServiceAccountClientBundleRepository.CreateWithClient to
// two independent commits (no tx) → the SA row survives the client-insert
// failure → TestBundleAtomic_ClientInsertFailureLeavesNoOrphanSA FAILS on
// the "service_accounts rows = 1" assertion.
//
// Requires IDENTUUM_IDP_TEST_DATABASE_URL (see oss_e2e_test.go).

package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
)

// bundleHarnessPgx wires the real bundle service over the real pgx repos +
// the atomic bundle repository, against a freshly-migrated DB.
func bundleHarnessPgx(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (*service.ServiceAccountClientBundleService, *postgres.Repositories) {
	t.Helper()
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	saSvc := service.NewServiceAccountService(nil, repos.ServiceAccount)
	clientSvc := service.NewClientService(nil, repos.Client).WithServiceAccountBindingValidator(saSvc)
	bundleRepo := postgres.NewPgxServiceAccountClientBundleRepository(pool)
	bundleSvc := service.NewServiceAccountClientBundleService(nil, saSvc, clientSvc, bundleRepo)
	return bundleSvc, repos
}

func seedBundleOrg(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repos *postgres.Repositories) uuid.UUID {
	t.Helper()
	sfx := uuid.NewString()[:8]
	orgID, _ := uuid.NewV7()
	created, err := repos.Organization.Create(ctx, &domain.Organization{
		ID:        orgID,
		Name:      "e2e-bundle-org-" + sfx,
		Domain:    "e2e-bundle-" + sfx + ".example.invalid",
		OrgSlug:   "e2e-bundle-" + sfx,
		Active:    true,
		MFAPolicy: "optional",
	})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() {
		// ON DELETE CASCADE tears down service_accounts + oauth_clients.
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", created.ID)
	})
	return created.ID
}

func bundleOrgAdmin(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgAdmin}
}

func countRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string, orgID uuid.UUID) int {
	t.Helper()
	var n int
	// table is a compile-time constant from this test, never user input.
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE organization_id = $1", orgID).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestBundleAtomic_HappyPathCreatesBoundPair proves the bundle persists the
// SA + a confidential client bound to it and returns the one-time secret.
func TestBundleAtomic_HappyPathCreatesBoundPair(t *testing.T) {
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

	res, err := bundleSvc.CreateServiceAccountWithClientForActor(
		ctx, bundleOrgAdmin(orgID), orgID,
		service.BundleInput{SAName: "deploy-bot", SARole: domain.RoleOrgUser},
	)
	if err != nil {
		t.Fatalf("bundle create: %v", err)
	}
	if res.ClientSecret == "" {
		t.Errorf("one-time client secret empty")
	}
	if res.Client.ServiceAccountID == nil || *res.Client.ServiceAccountID != res.ServiceAccount.ID {
		t.Fatalf("client not bound to SA: %+v", res.Client)
	}

	// Both rows present.
	if n := countRows(t, ctx, pool, "service_accounts", orgID); n != 1 {
		t.Errorf("service_accounts rows = %d, want 1", n)
	}
	if n := countRows(t, ctx, pool, "oauth_clients", orgID); n != 1 {
		t.Errorf("oauth_clients rows = %d, want 1", n)
	}
	// The persisted binding matches the created SA.
	var boundSA *uuid.UUID
	if err := pool.QueryRow(ctx, "SELECT service_account_id FROM oauth_clients WHERE id = $1", res.Client.ID).Scan(&boundSA); err != nil {
		t.Fatalf("read client binding: %v", err)
	}
	if boundSA == nil || *boundSA != res.ServiceAccount.ID {
		t.Errorf("persisted oauth_clients.service_account_id = %v, want %v", boundSA, res.ServiceAccount.ID)
	}
}

// TestBundleAtomic_ClientInsertFailureLeavesNoOrphanSA is the P2-16b teeth.
// A client name longer than oauth_clients.name (VARCHAR(255)) makes the
// CLIENT insert fail INSIDE the transaction — AFTER the SA insert. With the
// single-tx implementation the whole thing rolls back, so service_accounts
// has ZERO rows for the org. Revert CreateWithClient to two separate commits
// and the SA row survives (rows = 1) → this test fails.
func TestBundleAtomic_ClientInsertFailureLeavesNoOrphanSA(t *testing.T) {
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

	// A 300-char client name overflows oauth_clients.name VARCHAR(255); the
	// SA name stays short/valid, so the SA insert succeeds and the CLIENT
	// insert is what fails inside the tx.
	overlongClientName := strings.Repeat("x", 300)
	res, err := bundleSvc.CreateServiceAccountWithClientForActor(
		ctx, bundleOrgAdmin(orgID), orgID,
		service.BundleInput{
			SAName:     "ephemeral-bot",
			SARole:     domain.RoleOrgUser,
			ClientName: overlongClientName,
		},
	)
	if err == nil {
		t.Fatalf("expected the client insert to fail; got result %+v", res)
	}
	if res != nil {
		t.Errorf("expected nil result on failure, got %+v", res)
	}

	// THE POINT: the SA that was inserted before the failing client insert
	// must have rolled back — no orphan.
	if n := countRows(t, ctx, pool, "service_accounts", orgID); n != 0 {
		t.Fatalf("ORPHAN SA: service_accounts rows = %d after atomic client-insert failure, want 0", n)
	}
	if n := countRows(t, ctx, pool, "oauth_clients", orgID); n != 0 {
		t.Errorf("oauth_clients rows = %d, want 0", n)
	}
}
