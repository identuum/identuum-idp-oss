//go:build integration

// api_resource_update_atomic_pgx_test.go — P2-16 (API-resource half):
// APIResourceService.Update must validate BEFORE any write and apply the
// field update + scope replacement in ONE transaction, so an invalid
// scope set or a scope-replacement failure never leaves a partial write.
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
)

func TestAPIResourceUpdate_ValidateBeforeWrite_Atomic(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx := context.Background()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())

	suffix := uuid.NewString()[:8]
	orgID, _ := uuid.NewV7()
	org, err := repos.Organization.Create(ctx, &domain.Organization{
		ID: orgID, Name: "e2e-apires-" + suffix, Domain: "e2e-apires-" + suffix + ".example.invalid",
		OrgSlug: "e2e-apires-" + suffix, Active: true, MFAPolicy: "optional",
	})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() { _ = repos.Organization.Delete(context.Background(), org.ID) })

	svc := service.NewAPIResourceService(nil, repos.APIResource)
	// THE-INVERTED-GUARD: the service is actor-scoped now — this suite acts
	// as the seeded org's own org_admin.
	actor := &domain.Principal{UserID: uuid.New(), OrganizationID: org.ID, Role: domain.RoleOrgAdmin}

	const origName = "orig-name"
	const origTTL = 3600
	origAudience := "https://api-" + suffix + ".example.invalid"
	created, _, err := svc.Create(ctx, actor, service.CreateAPIResourceOptions{
		OrganizationID: org.ID, Name: origName, Audience: origAudience, Active: true, TokenTTLSecs: origTTL,
		Scopes: []domain.APIScope{{Name: "read"}, {Name: "write"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	baseline := func() *domain.APIResource {
		got, gErr := svc.GetByID(ctx, actor, created.ID)
		if gErr != nil {
			t.Fatalf("get: %v", gErr)
		}
		return got
	}
	scopeNames := func(r *domain.APIResource) []string {
		out := make([]string, 0, len(r.Scopes))
		for _, s := range r.Scopes {
			out = append(out, s.Name)
		}
		return out
	}

	// 1. Invalid scopes (reserved prefix) → error AND the row is UNCHANGED
	// (validated before any write). TEETH target.
	t.Run("invalid_scopes_no_partial_write", func(t *testing.T) {
		newName := "should-not-persist-1"
		if _, uErr := svc.Update(ctx, actor, created.ID, service.UpdateAPIResourceOptions{
			Name:   &newName,
			Scopes: []domain.APIScope{{Name: "read"}, {Name: "system:admin"}}, // forbidden prefix
		}); uErr == nil {
			t.Fatal("expected error for a reserved scope prefix")
		}
		got := baseline()
		if got.Name != origName || got.TokenTTLSecs != origTTL || got.Audience != origAudience {
			t.Errorf("field mutated on invalid-scopes Update (partial write): name=%q ttl=%d aud=%q", got.Name, got.TokenTTLSecs, got.Audience)
		}
		names := scopeNames(got)
		if len(names) != 2 || strings.Contains(strings.Join(names, ","), "system:") {
			t.Errorf("scope set mutated on invalid-scopes Update: %v", names)
		}
	})

	// 2. Atomicity: a scope-replacement failure AFTER the field update
	// (duplicate names → UNIQUE(resource_id, name) violation) must roll BOTH
	// back — NEITHER the field change NOR the scope change persists. TEETH target.
	t.Run("atomic_rollback_on_scope_failure", func(t *testing.T) {
		newName := "should-not-persist-2"
		if _, uErr := svc.Update(ctx, actor, created.ID, service.UpdateAPIResourceOptions{
			Name:   &newName,
			Scopes: []domain.APIScope{{Name: "dup"}, {Name: "dup"}}, // valid per ValidateAPIScopes; UNIQUE violation in DB
		}); uErr == nil {
			t.Fatal("expected error from the duplicate-scope UNIQUE violation")
		}
		got := baseline()
		if got.Name != origName || got.TokenTTLSecs != origTTL {
			t.Errorf("field UPDATE not rolled back with the scope failure (partial write): name=%q ttl=%d", got.Name, got.TokenTTLSecs)
		}
		names := scopeNames(got)
		if len(names) != 2 {
			t.Errorf("scope set changed despite rollback: %v", names)
		}
		for _, n := range names {
			if n == "dup" {
				t.Errorf("dup scope persisted despite rollback: %v", names)
			}
		}
	})

	// 3. Happy path: a valid update persists BOTH the fields and the new scope set.
	t.Run("happy_path_updates_fields_and_scopes", func(t *testing.T) {
		newName := "renamed"
		newTTL := 7200
		if _, uErr := svc.Update(ctx, actor, created.ID, service.UpdateAPIResourceOptions{
			Name: &newName, TokenTTLSecs: &newTTL,
			Scopes: []domain.APIScope{{Name: "read"}, {Name: "admin"}},
		}); uErr != nil {
			t.Fatalf("update: %v", uErr)
		}
		got := baseline()
		if got.Name != newName || got.TokenTTLSecs != newTTL {
			t.Errorf("fields not updated: name=%q ttl=%d", got.Name, got.TokenTTLSecs)
		}
		set := map[string]bool{}
		for _, n := range scopeNames(got) {
			set[n] = true
		}
		if !set["read"] || !set["admin"] || set["write"] || len(set) != 2 {
			t.Errorf("scope set not replaced correctly: %v", scopeNames(got))
		}
	})
}
