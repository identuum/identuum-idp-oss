//go:build integration

package postgres_test

// The auth-time client-resolution boundary, asserted against the live SQL:
// a soft-deleted client is a tombstone, and deleting an organization ends
// its clients' ability to resolve — credential revocation at delete time.
// Same FAIL-not-skip posture as the model teeth in this package.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func seedScratchOrg(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
INSERT INTO organizations (id, name, domain, org_slug, active)
VALUES (gen_random_uuid(), 'Scratch Org',
        'scratch-' || substr(md5(random()::text), 1, 8) || '.test',
        'scratch-' || substr(md5(random()::text), 1, 8), true)
RETURNING id::text`).Scan(&id); err != nil {
		t.Fatalf("seed scratch org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE organization_id = $1::uuid`, id)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1::uuid`, id)
	})
	return id
}

func seedLiveClient(t *testing.T, pool *pgxpool.Pool, orgID string) (repo *postgres.PgxClientRepository, clientID string) {
	t.Helper()
	repo = postgres.NewPgxClientRepository(pool)
	org := uuid.MustParse(orgID)
	c := &domain.Client{
		ID:             uuid.New(),
		Name:           "auth boundary probe",
		OrganizationID: &org,
		RedirectURIs:   []string{"https://boundary.example/cb"},
		IsPublic:       true,
	}
	if err := repo.RegisterClient(context.Background(), c); err != nil {
		t.Fatalf("register probe client: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT client_id FROM oauth_clients WHERE id = $1`, c.ID).Scan(&clientID); err != nil {
		t.Fatalf("read back client_id: %v", err)
	}
	got, err := repo.GetClientByClientID(context.Background(), clientID)
	if err != nil || got == nil {
		t.Fatalf("PREMISE FAILED: a live client in a live org must resolve (got=%v err=%v)", got, err)
	}
	return repo, clientID
}

// RULE: SOFTDEL-RESOLVE-1
func TestSoftDeletedClientDoesNotResolve(t *testing.T) {
	pool := modelTeethPool(t)
	orgID := seedScratchOrg(t, pool)
	repo, clientID := seedLiveClient(t, pool, orgID)

	if _, err := pool.Exec(context.Background(),
		`UPDATE oauth_clients SET deleted_at = now() WHERE client_id = $1`, clientID); err != nil {
		t.Fatalf("soft-delete probe client: %v", err)
	}
	if got, err := repo.GetClientByClientID(context.Background(), clientID); err == nil && got != nil {
		t.Error("a soft-deleted client RESOLVED at auth time — the tombstone predicate is not holding")
	}
}

// RULE: ORG-DELETE-REVOKE-1
func TestOrgDeleteEndsClientResolution(t *testing.T) {
	pool := modelTeethPool(t)
	orgID := seedScratchOrg(t, pool)
	repo, clientID := seedLiveClient(t, pool, orgID)

	if _, err := pool.Exec(context.Background(),
		`UPDATE organizations SET deleted_at = now(), active = false WHERE id = $1::uuid`, orgID); err != nil {
		t.Fatalf("soft-delete probe org: %v", err)
	}
	if got, err := repo.GetClientByClientID(context.Background(), clientID); err == nil && got != nil {
		t.Error("a deleted organization's client still RESOLVED — tenant deletion must be an authentication boundary")
	}
}

// RULE: DOMAIN-UNIQUE-1
func TestDomainUniquenessCapsAtTheSchema(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgA := seedScratchOrg(t, pool)
	orgB := seedScratchOrg(t, pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM organization_domains WHERE domain LIKE 'uniq-probe-%'`)
	})

	// (a) A VERIFIED domain is unique across the whole deployment.
	if _, err := pool.Exec(ctx, `
INSERT INTO organization_domains (organization_id, domain, verified_at)
VALUES ($1::uuid, 'uniq-probe-verified.test', now())`, orgA); err != nil {
		t.Fatalf("seed verified domain: %v", err)
	}
	_, err := pool.Exec(ctx, `
INSERT INTO organization_domains (organization_id, domain, verified_at)
VALUES ($1::uuid, 'uniq-probe-verified.test', now())`, orgB)
	if err == nil {
		t.Fatal("a SECOND org verified the same domain; uq_org_domains_verified_domain is not holding")
	}
	if !strings.Contains(err.Error(), "uq_org_domains_verified_domain") {
		t.Errorf("duplicate verified domain refused, but not by the global index: %v", err)
	}

	// (b) At most one PRIMARY domain per organization.
	if _, err := pool.Exec(ctx, `
INSERT INTO organization_domains (organization_id, domain, is_primary)
VALUES ($1::uuid, 'uniq-probe-primary-one.test', true)`, orgA); err != nil {
		t.Fatalf("seed primary domain: %v", err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO organization_domains (organization_id, domain, is_primary)
VALUES ($1::uuid, 'uniq-probe-primary-two.test', true)`, orgA)
	if err == nil {
		t.Fatal("a SECOND primary domain row was accepted; uq_org_domains_one_primary_per_org is not holding")
	}
	if !strings.Contains(err.Error(), "uq_org_domains_one_primary_per_org") {
		t.Errorf("second primary refused, but not by the one-primary index: %v", err)
	}
}
