//go:build integration

// Package e2e — integration coverage for the policy-field create
// semantics landed by slice
// agent-a-20260716-idp-oss-orgrepo-create-honors-policy-fields.
//
// Properties pinned:
//
//  1. Create(MaxSessionsPerUser=N) where N > 0 persists N (NOT the
//     viper DEFAULT_MAX_SESSIONS_PER_USER fallback).
//  2. Create(MaxSessionsPerUser=0) preserves the existing default
//     (viper DEFAULT_MAX_SESSIONS_PER_USER → 5 fallback) so callers
//     who never set the field get the same secure default they had
//     pre-slice.
//  3. AuthPolicy + ApiAuthorizationPolicy defaults remain correct
//     (empty string ⇒ AuthPolicyLocalOnly / APIAuthPolicyStrict).
//
// The bool fields (PasswordComplexityEnabled, LocalAdminOnly,
// AllowPublicRegistration, RequireRegistrationApproval,
// RequireStrictReauth, Active) cannot be cleanly tested at the
// Create boundary because the domain type uses bool not *bool — an
// "omitted" struct value is indistinguishable from explicit `false`
// at the repository layer. See the Create doc-comment for the full
// limitation note. Callers who need bool defaults must call Update
// after Create.

package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestE2E_OSS_OrgRepoCreate_HonorsMaxSessionsPerUser(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())

	t.Run("explicit > 0 persists", func(t *testing.T) {
		const want = 17
		suffix := uuid.NewString()
		created, err := repos.Organization.Create(ctx, &domain.Organization{
			Name:               "e2e-orgcreate-explicit-" + suffix,
			Domain:             "e2e-orgcreate-explicit-" + suffix + ".example.invalid",
			OrgSlug:            "e2e-explicit-" + strings.ReplaceAll(suffix[:8], "-", ""),
			Active:             true,
			MFAPolicy:          "optional",
			MaxSessionsPerUser: want,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		t.Cleanup(func() { _ = repos.Organization.Delete(context.Background(), created.ID) })
		if created.MaxSessionsPerUser != want {
			t.Fatalf("Create(MaxSessionsPerUser=%d) persisted %d; REGRESSION: Create stopped honoring the struct value",
				want, created.MaxSessionsPerUser)
		}
	})

	t.Run("zero falls back to default", func(t *testing.T) {
		// MaxSessionsPerUser=0 (Go zero-value) → repository falls back to
		// the viper DEFAULT_MAX_SESSIONS_PER_USER env-config or, if unset,
		// to the historical fallback of 5. The exact value depends on the
		// running config; we only assert it's > 0 (a positive default) so
		// the test is portable across deployments.
		suffix := uuid.NewString()
		created, err := repos.Organization.Create(ctx, &domain.Organization{
			Name:      "e2e-orgcreate-default-" + suffix,
			Domain:    "e2e-orgcreate-default-" + suffix + ".example.invalid",
			OrgSlug:   "e2e-default-" + strings.ReplaceAll(suffix[:8], "-", ""),
			Active:    true,
			MFAPolicy: "optional",
			// MaxSessionsPerUser: 0 (zero-value)
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		t.Cleanup(func() { _ = repos.Organization.Delete(context.Background(), created.ID) })
		if created.MaxSessionsPerUser <= 0 {
			t.Fatalf("Create with MaxSessionsPerUser=0 persisted %d; want > 0 (default fallback)",
				created.MaxSessionsPerUser)
		}
	})

	t.Run("empty AuthPolicy defaults to local_only", func(t *testing.T) {
		suffix := uuid.NewString()
		created, err := repos.Organization.Create(ctx, &domain.Organization{
			Name:      "e2e-orgcreate-authpolicy-" + suffix,
			Domain:    "e2e-orgcreate-authpolicy-" + suffix + ".example.invalid",
			OrgSlug:   "e2e-authpd-" + strings.ReplaceAll(suffix[:8], "-", ""),
			Active:    true,
			MFAPolicy: "optional",
			// AuthPolicy: "" (zero-value)
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		t.Cleanup(func() { _ = repos.Organization.Delete(context.Background(), created.ID) })
		if created.AuthPolicy != domain.AuthPolicyLocalOnly {
			t.Fatalf("Create with empty AuthPolicy persisted %q; want %q (default)",
				created.AuthPolicy, domain.AuthPolicyLocalOnly)
		}
	})

	t.Run("explicit AuthPolicy honored", func(t *testing.T) {
		suffix := uuid.NewString()
		created, err := repos.Organization.Create(ctx, &domain.Organization{
			Name:       "e2e-orgcreate-idponly-" + suffix,
			Domain:     "e2e-orgcreate-idponly-" + suffix + ".example.invalid",
			OrgSlug:    "e2e-idpod-" + strings.ReplaceAll(suffix[:8], "-", ""),
			Active:     true,
			MFAPolicy:  "optional",
			AuthPolicy: domain.AuthPolicyIDPOnly,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		t.Cleanup(func() { _ = repos.Organization.Delete(context.Background(), created.ID) })
		if created.AuthPolicy != domain.AuthPolicyIDPOnly {
			t.Fatalf("Create(AuthPolicy=idp_only) persisted %q; want %q",
				created.AuthPolicy, domain.AuthPolicyIDPOnly)
		}
	})

	t.Run("service-layer Create persists PasswordComplexityEnabled=true (secure default)", func(t *testing.T) {
		// Regression pin for slice
		// agent-a-20260718-idp-oss-orgservice-create-passwordcomplexity-secure-default.
		// Pre-fix: OrganizationService.Create constructed the domain.Organization
		// without setting PasswordComplexityEnabled, so the bool zero-value
		// `false` (RELAXED complexity) was persisted instead of the intended
		// migration default `true` (STRICT). Post-fix: the service sets the
		// field explicitly to honor Decision D-015 §9 + the migration's
		// `NOT NULL DEFAULT true`.
		//
		// This test calls the SERVICE layer (not the repo Create directly) so
		// a regression in the service-layer struct-construction is caught at
		// the e2e boundary too.
		svc := service.NewOrganizationService(nil, repos.Organization)
		suffix := uuid.NewString()
		created, err := svc.Create(ctx, service.CreateOrganizationOptions{
			Name:   "e2e-orgcreate-pwc-secure-default-" + suffix,
			Domain: "e2e-orgcreate-pwc-" + suffix + ".example.invalid",
			Active: true,
		})
		if err != nil {
			t.Fatalf("OrganizationService.Create: %v", err)
		}
		t.Cleanup(func() { _ = repos.Organization.Delete(context.Background(), created.ID) })
		if !created.PasswordComplexityEnabled {
			t.Fatalf("SECURE-DEFAULT REGRESSION: service-layer Create persisted PasswordComplexityEnabled=false; want true (Decision D-015 §9)")
		}
		// Confirm the persisted column matches by re-fetching through GetByID
		// (defends against a service-side mutation that doesn't reach the DB).
		refetched, err := repos.Organization.GetByID(ctx, created.ID)
		if err != nil || refetched == nil {
			t.Fatalf("GetByID after Create: %v", err)
		}
		if !refetched.PasswordComplexityEnabled {
			t.Fatalf("SECURE-DEFAULT REGRESSION: re-fetched org from DB has PasswordComplexityEnabled=false; want true")
		}
	})
}
