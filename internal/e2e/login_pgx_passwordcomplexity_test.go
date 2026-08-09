//go:build integration

// Package e2e — integration coverage for the per-org
// PasswordComplexityEnabled projection + enforcement landed by slice
// agent-a-20260715-idp-oss-password-complexity-perorg-enforcement
// (Decision D-015 §9).
//
// Properties pinned:
//
//  1. Projection round-trip — organizations.password_complexity_enabled
//     surfaces through PgxUserRepository.FindUsersByEmail into
//     domain.User.OrgPasswordComplexityEnabled.
//  2. Tenant enforcement — PasswordResetService.ResetPassword wired
//     against the real PgxUserRepository rejects a weak-but-long-
//     enough password when the org policy is strict (complexity=true)
//     and accepts the SAME password when the org policy is relaxed
//     (complexity=false).
//  3. Strict default — a too-short password is rejected regardless of
//     the org's complexity setting.

package e2e

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func seedComplexityOrg(t *testing.T, ctx context.Context, repos *postgres.Repositories, complexityEnabled bool) *domain.Organization {
	t.Helper()
	suffix := uuid.NewString()
	org := &domain.Organization{
		Name:      "e2e-pwcomplex-org-" + suffix,
		Domain:    "e2e-pwcomplex-" + suffix + ".example.invalid",
		OrgSlug:   "e2e-pwc-" + suffix[:8],
		Active:    true,
		MFAPolicy: "optional",
	}
	created, err := repos.Organization.Create(ctx, org)
	if err != nil {
		t.Fatalf("seedComplexityOrg Create: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.Organization.Delete(context.Background(), created.ID)
	})
	// PgxOrganizationRepository.Create reads the default from viper for
	// some columns; consume Update to set PasswordComplexityEnabled
	// deterministically.
	updated, err := repos.Organization.Update(ctx, created.ID, repository.UpdateOrganizationOptions{
		PasswordComplexityEnabled: &complexityEnabled,
	})
	if err != nil {
		t.Fatalf("seedComplexityOrg Update: %v", err)
	}
	return updated
}

func seedActiveUserWithResetToken(t *testing.T, ctx context.Context, repos *postgres.Repositories, orgID uuid.UUID) (*domain.User, string) {
	t.Helper()
	email := strings.ToLower("e2e-pwcomplex-" + uuid.NewString() + "@example.invalid")
	initialPassword := "Initial-Strong-Password-1!"
	user, err := repos.User.Create(ctx, &domain.User{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Email:          email,
		PasswordHash:   initialPassword,
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		t.Fatalf("seedActiveUser Create: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), user.ID, user.OrganizationID)
	})
	rawToken, err := crypto.GenerateRandomString(32)
	if err != nil {
		t.Fatalf("token generation: %v", err)
	}
	tokenHash := crypto.HashToken(rawToken)
	if err := repos.PasswordReset.Create(ctx, &domain.PasswordReset{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("password_reset Create: %v", err)
	}
	return user, rawToken
}

func TestE2E_OSS_PasswordComplexity_ProjectionAndEnforcement(t *testing.T) {
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
	if repos == nil || repos.User == nil || repos.PasswordReset == nil || repos.Organization == nil {
		t.Fatal("repository factory returned nil critical repo")
	}

	// ── Strict org (complexity=true).
	strictOrg := seedComplexityOrg(t, ctx, repos, true)
	strictUser, strictToken := seedActiveUserWithResetToken(t, ctx, repos, strictOrg.ID)

	// Projection round-trip pin: FindUsersByEmail surfaces the org
	// policy through the User row.
	usersFound, err := repos.User.FindUsersByEmail(ctx, strictUser.Email)
	if err != nil {
		t.Fatalf("FindUsersByEmail: %v", err)
	}
	if len(usersFound) != 1 {
		t.Fatalf("want 1 user, got %d", len(usersFound))
	}
	got := usersFound[0]
	if got.OrgPasswordComplexityEnabled == nil {
		t.Fatal("FindUsersByEmail: OrgPasswordComplexityEnabled is nil (REGRESSION: scanUserWithOrg omits o.password_complexity_enabled from SELECT or fails to populate user.OrgPasswordComplexityEnabled)")
	}
	if *got.OrgPasswordComplexityEnabled != true {
		t.Fatalf("OrgPasswordComplexityEnabled = %v, want true", *got.OrgPasswordComplexityEnabled)
	}

	// ── Relaxed org (complexity=false).
	relaxedOrg := seedComplexityOrg(t, ctx, repos, false)
	relaxedUser, relaxedToken := seedActiveUserWithResetToken(t, ctx, repos, relaxedOrg.ID)

	// Projection round-trip pin: relaxed.
	usersFound2, err := repos.User.FindUsersByEmail(ctx, relaxedUser.Email)
	if err != nil {
		t.Fatalf("FindUsersByEmail relaxed: %v", err)
	}
	if len(usersFound2) != 1 {
		t.Fatalf("want 1 user relaxed, got %d", len(usersFound2))
	}
	gotRelaxed := usersFound2[0]
	if gotRelaxed.OrgPasswordComplexityEnabled == nil {
		t.Fatal("OrgPasswordComplexityEnabled is nil for relaxed org (REGRESSION)")
	}
	if *gotRelaxed.OrgPasswordComplexityEnabled != false {
		t.Fatalf("OrgPasswordComplexityEnabled = %v, want false", *gotRelaxed.OrgPasswordComplexityEnabled)
	}

	// ── PasswordResetService enforcement against the real PGX repo.
	prSvc := service.NewPasswordResetService(service.PasswordResetServiceConfig{
		Users:             repos.User.(*postgres.PgxUserRepository),
		Resets:            repos.PasswordReset,
		MinPasswordLength: 8,
	})

	// Property 2a: strict org rejects weak-but-long-enough password.
	weak := "longenoughpw" // 12 chars, lowercase only — no digit/upper/special.
	err = prSvc.ResetPassword(ctx, service.ResetPasswordInput{Token: strictToken, NewPassword: weak})
	if !errors.Is(err, service.ErrPasswordResetWeakPassword) {
		t.Fatalf("strict org + weak password: want ErrPasswordResetWeakPassword, got %v", err)
	}

	// Property 2b: relaxed org accepts the SAME weak-but-long-enough password.
	err = prSvc.ResetPassword(ctx, service.ResetPasswordInput{Token: relaxedToken, NewPassword: weak})
	if err != nil {
		t.Fatalf("relaxed org + same weak password: want success, got %v", err)
	}

	// Property 3: too-short password rejected regardless of policy.
	// Re-mint a token for strictUser to test too-short separately.
	rawToken2, err := crypto.GenerateRandomString(32)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if err := repos.PasswordReset.Create(ctx, &domain.PasswordReset{
		UserID:    strictUser.ID,
		TokenHash: crypto.HashToken(rawToken2),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("password_reset Create token2: %v", err)
	}
	err = prSvc.ResetPassword(ctx, service.ResetPasswordInput{Token: rawToken2, NewPassword: "shrt"})
	if !errors.Is(err, service.ErrPasswordResetWeakPassword) {
		t.Fatalf("too-short rejected regardless: want ErrPasswordResetWeakPassword, got %v", err)
	}
}
