//go:build integration

package postgres_test

// H7 against the live SQL: an API resource's audience is unique across the
// whole installation (two tenants can no longer hold the same one), the
// repository reports a taken audience as domain.ErrAPIResourceAlreadyExists,
// and the migration refuses to run over existing duplicates instead of
// choosing one silently.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/migrations"
)

func newProbeResource(org uuid.UUID, audience string) *domain.APIResource {
	now := time.Now().UTC()
	return &domain.APIResource{
		ID: uuid.New(), OrganizationID: org, Name: "probe", Audience: audience,
		Active: true, TokenTTLSecs: 60, ResourceSecretHash: "h", CreatedAt: now, UpdatedAt: now,
	}
}

func TestAPIResourceRepository_AudienceIsGloballyUnique(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgA := uuid.MustParse(seedScratchOrg(t, pool))
	orgB := uuid.MustParse(seedScratchOrg(t, pool))
	repo := postgres.NewPgxAPIResourceRepository(pool)
	audience := "https://audience-unique-" + uuid.NewString() + ".example.test"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_resources WHERE org_id = ANY($1)`, []uuid.UUID{orgA, orgB})
	})

	first := newProbeResource(orgA, audience)
	if err := repo.Create(ctx, first, nil); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// Another tenant cannot take it.
	if err := repo.Create(ctx, newProbeResource(orgB, audience), nil); !errors.Is(err, domain.ErrAPIResourceAlreadyExists) {
		t.Errorf("same audience in another organization: err=%v, want ErrAPIResourceAlreadyExists", err)
	}
	// Nor the same tenant twice.
	if err := repo.Create(ctx, newProbeResource(orgA, audience), nil); !errors.Is(err, domain.ErrAPIResourceAlreadyExists) {
		t.Errorf("same audience in the same organization: err=%v, want ErrAPIResourceAlreadyExists", err)
	}
	// Nor by renaming an existing resource onto it.
	other := newProbeResource(orgB, "https://audience-other-"+uuid.NewString()+".example.test")
	if err := repo.Create(ctx, other, nil); err != nil {
		t.Fatalf("other create: %v", err)
	}
	other.Audience = audience
	if err := repo.Update(ctx, other); !errors.Is(err, domain.ErrAPIResourceAlreadyExists) {
		t.Errorf("Update onto a taken audience: err=%v, want ErrAPIResourceAlreadyExists", err)
	}
	if err := repo.UpdateWithScopes(ctx, other, nil); !errors.Is(err, domain.ErrAPIResourceAlreadyExists) {
		t.Errorf("UpdateWithScopes onto a taken audience: err=%v, want ErrAPIResourceAlreadyExists", err)
	}
	// The global lookup now has one answer.
	got, err := repo.GetByAudienceGlobal(ctx, audience)
	if err != nil || got == nil || got.ID != first.ID {
		t.Errorf("GetByAudienceGlobal = %v, %v; want the first resource", got, err)
	}
}

// The migration stops over existing duplicates with a message naming the
// audience, rather than picking a survivor. Run in a rolled-back transaction:
// the index is dropped, a duplicate is planted, and the migration's pre-flight
// is executed.
func TestMigration0045_RefusesToRunOverDuplicateAudiences(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgA := seedScratchOrg(t, pool)
	orgB := seedScratchOrg(t, pool)

	data, err := migrations.EmbedFS.ReadFile("0045_api_resources_audience_global_unique.sql")
	if err != nil {
		t.Fatalf("read 0045: %v", err)
	}
	up, _, _ := strings.Cut(string(data), "-- +goose Down")
	start := strings.Index(up, "-- +goose StatementBegin")
	end := strings.Index(up, "-- +goose StatementEnd")
	if start < 0 || end < start {
		t.Fatal("0045 Up has no StatementBegin/StatementEnd block for its pre-flight")
	}
	preflight := up[start+len("-- +goose StatementBegin") : end]

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // always rolled back

	if _, err := tx.Exec(ctx, `DROP INDEX IF EXISTS uq_api_resources_audience`); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	dup := "https://dup-" + uuid.NewString() + ".example.test"
	for _, org := range []string{orgA, orgB} {
		if _, err := tx.Exec(ctx, `INSERT INTO api_resources (id, org_id, name, audience, resource_secret_hash) VALUES (gen_random_uuid(), $1::uuid, 'dup', $2, 'h')`, org, dup); err != nil {
			t.Fatalf("plant duplicate: %v", err)
		}
	}
	_, err = tx.Exec(ctx, preflight)
	if err == nil {
		t.Fatal("the pre-flight passed over a duplicated audience; it must refuse")
	}
	if !strings.Contains(err.Error(), dup) {
		t.Errorf("the refusal must name the audience; got: %v", err)
	}
}
