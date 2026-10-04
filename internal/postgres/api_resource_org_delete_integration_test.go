//go:build integration

package postgres_test

// A deleted organization releases its API resources' audiences: the soft
// delete cascades to them (deleted_at, migration 0050), the global audience
// index counts only live resources, so another organization can take the
// audience, and no read returns the deleted resource. Restoring the
// organization restores a resource only while its audience is still free.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestAPIResourceAudience_ADeletedOrganizationReleasesIt(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgA := uuid.MustParse(seedScratchOrg(t, pool))
	orgB := uuid.MustParse(seedScratchOrg(t, pool))
	orgs := postgres.NewPgxOrganizationRepository(pool)
	resources := postgres.NewPgxAPIResourceRepository(pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_resources WHERE org_id = ANY($1)`, []uuid.UUID{orgA, orgB})
	})
	taken := "https://released-" + uuid.NewString() + ".example.test"
	kept := "https://kept-" + uuid.NewString() + ".example.test"

	first := newProbeResource(orgA, taken)
	if err := resources.Create(ctx, first, nil); err != nil {
		t.Fatalf("create in A: %v", err)
	}
	second := newProbeResource(orgA, kept)
	if err := resources.Create(ctx, second, nil); err != nil {
		t.Fatalf("create second in A: %v", err)
	}
	if err := orgs.Delete(ctx, orgA); err != nil {
		t.Fatalf("delete A: %v", err)
	}

	if got, err := resources.GetByID(ctx, first.ID, &orgA); err != nil || got != nil {
		t.Errorf("GetByID of a deleted organization's resource = %v, %v; want none", got, err)
	}
	reused := newProbeResource(orgB, taken)
	if err := resources.Create(ctx, reused, nil); err != nil {
		t.Fatalf("another organization taking a deleted organization's audience: %v", err)
	}
	if got, err := resources.GetByAudienceGlobal(ctx, taken); err != nil || got == nil || got.ID != reused.ID {
		t.Errorf("GetByAudienceGlobal = %v, %v; want the live resource", got, err)
	}

	if err := orgs.Undelete(ctx, orgA); err != nil {
		t.Fatalf("restore A: %v", err)
	}
	if got, err := resources.GetByID(ctx, second.ID, &orgA); err != nil || got == nil {
		t.Errorf("the restored organization's free-audience resource = %v, %v; want it back", got, err)
	}
	if got, err := resources.GetByID(ctx, first.ID, &orgA); err != nil || got != nil {
		t.Errorf("the restored organization's taken-audience resource = %v, %v; want it left deleted", got, err)
	}
	if err := resources.Create(ctx, newProbeResource(orgB, kept), nil); !errors.Is(err, domain.ErrAPIResourceAlreadyExists) {
		t.Errorf("the restored resource's audience: err=%v, want it held again", err)
	}
}
