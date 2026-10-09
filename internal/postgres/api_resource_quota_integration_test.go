//go:build integration

package postgres_test

// OSS-SEAM-5 against the live SQL: the quota-bound create counts and inserts
// in one transaction, serialized per organization.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func quotaCount(t *testing.T, repo *postgres.PgxAPIResourceRepository, org uuid.UUID) int64 {
	t.Helper()
	n, err := repo.CountByOrg(context.Background(), org)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// Proof 1: two creates for the last slot, held at fixed points: the first
// counts under the organization's lock and waits; the second starts and is
// observed either waiting on that lock or having counted past it. Only then
// is the first released. Exactly one may succeed.
func TestAPIResourceQuota_LastSlotHasOneWinner(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	org := uuid.MustParse(seedScratchOrg(t, pool))
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM api_resources WHERE org_id = $1`, org) })

	first, second := postgres.NewPgxAPIResourceRepository(pool), postgres.NewPgxAPIResourceRepository(pool)
	counted1, counted2, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	postgres.SetQuotaCounted(first, func() { close(counted1); <-release })
	postgres.SetQuotaCounted(second, func() { close(counted2); <-release })

	results := make(chan error, 2)
	go func() {
		results <- first.CreateUnderCeiling(ctx, newProbeResource(org, "https://q1-"+uuid.NewString()+".example.test"), nil, 1)
	}()
	<-counted1
	go func() {
		results <- second.CreateUnderCeiling(ctx, newProbeResource(org, "https://q2-"+uuid.NewString()+".example.test"), nil, 1)
	}()
	// The second create either counts (no lock held it) or waits on the
	// advisory lock; the loop ends on whichever is observed first.
	deadline := time.Now().Add(30 * time.Second)
	for waiting := false; !waiting; {
		select {
		case <-counted2:
			waiting = true
			continue
		default:
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
			AND ((classid::bigint << 32) | objid::bigint) = hashtextextended('api_resources.quota:' || $1::text, 0)`, org).Scan(&n); err != nil {
			t.Fatalf("pg_locks: %v", err)
		}
		waiting = n > 0
		if !waiting && time.Now().After(deadline) {
			t.Fatal("the second create neither counted nor waited on the lock")
		}
	}
	close(release)
	var ok, exceeded int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			ok++
		case errors.Is(err, repository.ErrQuotaExceeded):
			exceeded++
		default:
			t.Fatalf("create: %v", err)
		}
	}
	if ok != 1 || exceeded != 1 || quotaCount(t, first, org) != 1 {
		t.Fatalf("%d created, %d refused, %d held; want 1, 1 and 1", ok, exceeded, quotaCount(t, first, org))
	}
}

// Proof 2: a create that fails after the count writes nothing, so the slot is
// free; a retry counts once.
func TestAPIResourceQuota_FailedCreateFreesTheSlot(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	org := uuid.MustParse(seedScratchOrg(t, pool))
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM api_resources WHERE org_id = $1`, org) })
	repo := postgres.NewPgxAPIResourceRepository(pool)

	if err := repo.CreateUnderCeiling(ctx, newProbeResource(org, "https://f1-"+uuid.NewString()+".example.test"), nil, 2); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// Two scopes with one name: the scope insert fails after the row insert.
	dup := []domain.APIScope{{Name: "read"}, {Name: "read"}}
	retry := newProbeResource(org, "https://f2-"+uuid.NewString()+".example.test")
	if err := repo.CreateUnderCeiling(ctx, retry, dup, 2); err == nil {
		t.Fatal("a create with a duplicated scope name succeeded")
	}
	if n := quotaCount(t, repo, org); n != 1 {
		t.Fatalf("after the failed create the organization holds %d; want 1", n)
	}
	if err := repo.CreateUnderCeiling(ctx, retry, []domain.APIScope{{Name: "read"}}, 2); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := quotaCount(t, repo, org); n != 2 {
		t.Fatalf("after the retry the organization holds %d; want 2", n)
	}
	if err := repo.CreateUnderCeiling(ctx, newProbeResource(org, "https://f3-"+uuid.NewString()+".example.test"), nil, 2); !errors.Is(err, repository.ErrQuotaExceeded) {
		t.Fatalf("a create at the ceiling: %v; want ErrQuotaExceeded", err)
	}
}
