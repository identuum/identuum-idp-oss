//go:build integration

package postgres_test

// Integration tooth for ORG-LIST-SYSORG-EXCLUDED-1: the pgx organization
// List NEVER returns the System organization, even under the most
// permissive lifecycle filter (IncludeInactive + IncludeDeleted). The
// exclusion is an unconditional `id != SystemOrgID` in the WHERE builder;
// THE-DEACTIVATED-ORG widened the reachable filter space, so this pins
// that the widening cannot surface the System org. FAIL-not-skip.

import (
	"context"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// RULE: ORG-LIST-SYSORG-EXCLUDED-1
func TestOrgList_SystemOrgExcludedEvenFullyWidened(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := postgres.NewPgxOrganizationRepository(pool)

	scratch := seedScratchOrg(t, pool)

	// Precondition, so the assertion has teeth: the System org row EXISTS.
	var sysRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE id = $1`,
		domain.SystemOrgID).Scan(&sysRows); err != nil || sysRows != 1 {
		t.Fatalf("System organization row must exist (rows=%d err=%v)", sysRows, err)
	}

	orgs, _, err := repo.List(ctx,
		repository.OrganizationFilter{IncludeInactive: true, IncludeDeleted: true},
		repository.NewPagination(1, 500), repository.NewOrganizationSort("created_at", false))
	if err != nil {
		t.Fatalf("List(fully widened): %v", err)
	}
	sawScratch := false
	for _, o := range orgs {
		if o.ID.String() == domain.SystemOrgID {
			t.Fatalf("the System organization LEAKED into the fully-widened list")
		}
		if o.ID.String() == scratch {
			sawScratch = true
		}
	}
	if !sawScratch {
		t.Fatalf("the widened list must still return ordinary orgs (scratch org absent — the assertion would be vacuous)")
	}
}
