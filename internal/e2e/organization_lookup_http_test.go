//go:build integration

// Package e2e — integration coverage for GET /api/v1/auth/organization-lookup
// against the live pgx repository factory. Pins the wire contract
// identuum-ui's idp-client.orgLookup helper consumes end-to-end.
//
// Test discipline mirrors the other e2e tests in this directory:
// randomized tenant org per run; t.Cleanup soft-deletes; assertions
// are structural only; provider config + secrets NEVER printed.
package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestE2E_OSS_OrganizationLookup_RoundTrip(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.Organization == nil {
		t.Fatal("repository factory returned nil Organization repo")
	}

	// Seed a randomized tenant org via the existing helper used by
	// other e2e tests. The helper soft-deletes on cleanup.
	org := seedTestOrganization(t, ctx, repos)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	handlers.RegisterOrganizationLookupRoute(r, handlers.OrganizationLookupHandlerDeps{
		OrganizationRepo:       repos.Organization,
		OrganizationDomainRepo: repos.OrganizationDomain,
		IdentityProviderRepo:   repos.IdentityProvider,
	})

	t.Run("by_slug_success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?slug="+org.OrgSlug, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status: want 200, got %d body=%q", w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("json parse: %v", err)
		}
		if body["slug"] != org.OrgSlug {
			t.Fatalf("slug: want %s, got %v", org.OrgSlug, body["slug"])
		}
		if body["name"] != org.Name {
			t.Fatalf("name: want %s, got %v", org.Name, body["name"])
		}
		if body["domain"] != org.Domain {
			t.Fatalf("domain: want %s, got %v", org.Domain, body["domain"])
		}
		if _, ok := body["identity_providers"].([]any); !ok {
			t.Fatal("identity_providers must be a (possibly empty) array")
		}
	})

	t.Run("by_domain_success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain="+org.Domain, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status: want 200, got %d", w.Code)
		}
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body["slug"] != org.OrgSlug {
			t.Fatalf("slug mismatch: want %s, got %v", org.OrgSlug, body["slug"])
		}
	})

	t.Run("unknown_domain_404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup?domain=does-not-exist.example.invalid", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("unknown domain: want 404, got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), `"organization_not_found"`) {
			t.Fatalf("body must use organization_not_found sentinel, got %q", w.Body.String())
		}
	})

	t.Run("missing_params_400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/organization-lookup", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("missing params: want 400, got %d", w.Code)
		}
	})
}
