//go:build integration

package postgres_test

// Integration tooth for SA-UPDATE-EXPIRY-1 (THE-SILENT-EXPIRY).
//
// The service assigned ExpiresAt on the aggregate and the repository's UPDATE
// statement covered {name, description, role} only, so a PUT carrying only
// expires_at answered 200 and stored nothing — the account went on minting
// tokens past the expiry its operator had just set.
//
// WHY THIS IS A DB TEST. Every in-memory fake stores whatever struct it is
// handed, so a fake proves the service assigned the field and nothing about
// whether the column was written. Only the live statement can show that, and
// the appliance is where the two previous slices found what fakes could not.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func seedScratchServiceAccount(t *testing.T, pool *pgxpool.Pool, orgID string) *domain.ServiceAccount {
	t.Helper()
	repo := postgres.NewPgxServiceAccountRepository(pool)
	org := uuid.MustParse(orgID)
	created, err := repo.Create(context.Background(), &domain.ServiceAccount{
		OrganizationID: org,
		Name:           "expiry-probe-" + uuid.NewString()[:8],
		Description:    "THE-SILENT-EXPIRY probe",
		Role:           domain.RoleOrgUser,
		Active:         true,
	})
	if err != nil {
		t.Fatalf("seed service account: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM service_accounts WHERE id = $1`, created.ID)
	})
	return created
}

// RULE: SA-UPDATE-EXPIRY-1
func TestServiceAccountUpdate_ExpiryIsPersisted(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	repo := postgres.NewPgxServiceAccountRepository(pool)
	orgID := seedScratchOrg(t, pool)
	sa := seedScratchServiceAccount(t, pool, orgID)

	// PREMISE: the seeded row has no expiry, so the assertion below cannot
	// pass by accident.
	if sa.ExpiresAt != nil {
		t.Fatalf("PREMISE FAILED: the probe must start without an expiry (got %v)", sa.ExpiresAt)
	}

	want := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	sa.ExpiresAt = &want
	if _, err := repo.Update(ctx, sa); err != nil {
		t.Fatalf("update with an expiry: %v", err)
	}

	// Read it back through the repository AND straight from the column: the
	// statement must have written it, not the returned struct.
	got, err := repo.GetByID(ctx, sa.ID)
	if err != nil || got == nil {
		t.Fatalf("read back: got=%v err=%v", got, err)
	}
	if got.ExpiresAt == nil {
		t.Fatalf("the expiry was DROPPED: the update answered success and stored nothing")
	}
	if !got.ExpiresAt.UTC().Truncate(time.Second).Equal(want) {
		t.Fatalf("expiry = %v, want %v", got.ExpiresAt.UTC(), want)
	}
	var column *time.Time
	if err := pool.QueryRow(ctx, `SELECT expires_at FROM service_accounts WHERE id = $1`, sa.ID).Scan(&column); err != nil {
		t.Fatalf("read the column: %v", err)
	}
	if column == nil || !column.UTC().Truncate(time.Second).Equal(want) {
		t.Fatalf("column expires_at = %v, want %v", column, want)
	}

	// The neighbours of the same statement still travel: a rename lands, and
	// the expiry survives an update that does not mention it.
	got.Name = "expiry-probe-renamed-" + uuid.NewString()[:8]
	if _, err := repo.Update(ctx, got); err != nil {
		t.Fatalf("rename: %v", err)
	}
	after, err := repo.GetByID(ctx, sa.ID)
	if err != nil || after == nil {
		t.Fatalf("read back after rename: got=%v err=%v", after, err)
	}
	if after.Name != got.Name {
		t.Fatalf("name = %q, want %q", after.Name, got.Name)
	}
	if after.ExpiresAt == nil || !after.ExpiresAt.UTC().Truncate(time.Second).Equal(want) {
		t.Fatalf("the expiry must survive an unrelated update (got %v)", after.ExpiresAt)
	}

	// And an expiry can be moved again — the column is not write-once.
	later := time.Now().Add(240 * time.Hour).UTC().Truncate(time.Second)
	after.ExpiresAt = &later
	if _, err := repo.Update(ctx, after); err != nil {
		t.Fatalf("move the expiry: %v", err)
	}
	final, err := repo.GetByID(ctx, sa.ID)
	if err != nil || final == nil || final.ExpiresAt == nil {
		t.Fatalf("read back after moving the expiry: %v %v", final, err)
	}
	if !final.ExpiresAt.UTC().Truncate(time.Second).Equal(later) {
		t.Fatalf("moved expiry = %v, want %v", final.ExpiresAt.UTC(), later)
	}
}
