//go:build integration

// Package e2e — integration coverage for the per-org MaxSessionsPerUser
// eviction landed by slice
// agent-a-20260714-idp-oss-maxsessions-eviction-enforcement
// (Decision D-015 §4). The companion unit suite at
// internal/service/user_session_service_test.go covers the in-memory
// repository path; this file proves the SAME contract carries through
// the real PgxSessionRepository + organizations.max_sessions_per_user
// JOIN projection.
//
// Properties pinned:
//
//  1. Projection round-trip — organizations.max_sessions_per_user=1
//     is projected through PgxUserRepository.FindUsersByEmail into
//     domain.User.OrgMaxSessionsPerUser.
//  2. Non-admin enforcement — LocalLoginService.Login wired against
//     the production PGX repo evicts the older session when an
//     org_user logs in twice under cap=1; the newer session remains
//     active; the older session row's revoked_reason column carries
//     "max_sessions_exceeded".
//  3. Locked admin-local invariant (Decision D-004) — org_admin
//     logged in twice under the SAME cap=1 retains BOTH sessions.
//     Admins are control-plane infrastructure and MUST NOT be
//     collapsed under the cap.

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

// seedCappedOrganization creates a tenant org with the supplied
// MaxSessionsPerUser cap. t.Cleanup soft-deletes the org on test exit.
//
// As of slice agent-a-20260716-idp-oss-orgrepo-create-honors-policy-fields,
// PgxOrganizationRepository.Create honors org.MaxSessionsPerUser when > 0,
// so this helper no longer needs the prior Create+Update workaround.
func seedCappedOrganization(t *testing.T, ctx context.Context, repos *postgres.Repositories, cap int) *domain.Organization {
	t.Helper()
	suffix := uuid.NewString()
	org := &domain.Organization{
		Name:               "e2e-maxsessions-org-" + suffix,
		Domain:             "e2e-maxsessions-" + suffix + ".example.invalid",
		OrgSlug:            "e2e-maxsess-" + suffix[:8],
		Active:             true,
		MFAPolicy:          "optional",
		MaxSessionsPerUser: cap,
	}
	created, err := repos.Organization.Create(ctx, org)
	if err != nil {
		t.Fatalf("seedCappedOrganization: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.Organization.Delete(context.Background(), created.ID)
	})
	if created.MaxSessionsPerUser != cap {
		t.Fatalf("seedCappedOrganization: Create persisted MaxSessionsPerUser=%d, want %d (REGRESSION: Create stopped honoring the struct value)",
			created.MaxSessionsPerUser, cap)
	}
	return created
}

func TestE2E_OSS_MaxSessions_ProjectionAndEvictionForOrgUser(t *testing.T) {
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
	if repos == nil || repos.User == nil || repos.Session == nil || repos.Organization == nil {
		t.Fatal("repository factory returned nil User, Session, or Organization repo")
	}

	org := seedCappedOrganization(t, ctx, repos, 1)

	// ── Seed an org_user member.
	userEmail := strings.ToLower("e2e-maxsess-user-" + uuid.NewString() + "@example.invalid")
	userPlaintext := "u-" + uuid.NewString() + "-marker-not-printed"
	createdUser, err := repos.User.Create(ctx, &domain.User{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Email:          userEmail,
		PasswordHash:   userPlaintext, // Create argon2id-hashes any non-PHC string.
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		t.Fatalf("seed org_user Create: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), createdUser.ID, createdUser.OrganizationID)
	})

	// Property 1: projection round-trip.
	users, err := repos.User.FindUsersByEmail(ctx, userEmail)
	if err != nil {
		t.Fatalf("FindUsersByEmail (org_user): %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("FindUsersByEmail returned %d users; want 1", len(users))
	}
	got := users[0]
	if got.OrgMaxSessionsPerUser == nil {
		t.Fatal("FindUsersByEmail: OrgMaxSessionsPerUser is nil (REGRESSION: scanUserWithOrg omits o.max_sessions_per_user from SELECT or fails to populate user.OrgMaxSessionsPerUser)")
	}
	if *got.OrgMaxSessionsPerUser != 1 {
		t.Fatalf("FindUsersByEmail: OrgMaxSessionsPerUser = %d, want 1", *got.OrgMaxSessionsPerUser)
	}

	// Property 2: non-admin enforcement via real PGX repo.
	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	login := service.NewLocalLoginService(nil, repos.User, sessions, nil)

	// First login → mints session A.
	resultA, err := login.Login(ctx, service.LoginInput{Email: userEmail, Password: userPlaintext})
	if err != nil || resultA == nil || resultA.Session == nil {
		t.Fatalf("first login: %v / %+v", err, resultA)
	}
	sessionA := resultA.Session.ID

	// Second login → mints session B AND evicts session A under cap=1.
	resultB, err := login.Login(ctx, service.LoginInput{Email: userEmail, Password: userPlaintext})
	if err != nil || resultB == nil || resultB.Session == nil {
		t.Fatalf("second login: %v / %+v", err, resultB)
	}
	sessionB := resultB.Session.ID

	if sessionA == sessionB {
		t.Fatal("second login returned the SAME session row; expected a fresh insert")
	}

	// Verify only ONE active session remains.
	activeAfter, err := repos.Session.ListActiveByUserID(ctx, createdUser.ID)
	if err != nil {
		t.Fatalf("ListActiveByUserID: %v", err)
	}
	if len(activeAfter) != 1 {
		t.Fatalf("cap=1 + org_user MUST leave exactly 1 active session post-eviction; got %d", len(activeAfter))
	}
	if activeAfter[0].ID != sessionB {
		t.Errorf("expected sessionB to remain active; got %s", activeAfter[0].ID)
	}

	// Verify session A was revoked with the canonical reason.
	revokedSessionA, err := repos.Session.GetByID(ctx, sessionA)
	if err != nil {
		t.Fatalf("GetByID(sessionA): %v", err)
	}
	if revokedSessionA == nil {
		t.Fatal("sessionA row missing after eviction")
	}
	if revokedSessionA.RevokedAt == nil {
		t.Fatal("sessionA must be revoked (RevokedAt non-nil) after cap=1 eviction")
	}
	if revokedSessionA.RevokedReason == nil || *revokedSessionA.RevokedReason != "max_sessions_exceeded" {
		t.Errorf("sessionA RevokedReason: want 'max_sessions_exceeded', got %v", revokedSessionA.RevokedReason)
	}
}

func TestE2E_OSS_MaxSessions_OrgAdminExemptUnderCap1(t *testing.T) {
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
	org := seedCappedOrganization(t, ctx, repos, 1)

	// Seed an org_admin in the same capped org.
	adminEmail := strings.ToLower("e2e-maxsess-admin-" + uuid.NewString() + "@example.invalid")
	adminPlaintext := "a-" + uuid.NewString() + "-marker-not-printed"
	createdAdmin, err := repos.User.Create(ctx, &domain.User{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Email:          adminEmail,
		PasswordHash:   adminPlaintext,
		Role:           domain.RoleOrgAdmin,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		t.Fatalf("seed org_admin Create: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), createdAdmin.ID, createdAdmin.OrganizationID)
	})

	// Direct UserSessionService.CreateUserSession calls — bypasses
	// the MFA-enrollment gate on LocalLoginService.Login because
	// org_admin role forces ErrLoginMFAEnrollmentRequired. The
	// integration scope here is the eviction loop, not the login
	// pipeline. Pass the policy through directly.
	maxSessions := 1
	if createdAdmin.OrgMaxSessionsPerUser != nil {
		maxSessions = *createdAdmin.OrgMaxSessionsPerUser
	}
	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{DefaultTTL: time.Hour})

	issuedA, err := sessions.CreateUserSession(ctx, service.CreateUserSessionInput{
		UserID:             createdAdmin.ID,
		MaxSessionsPerUser: maxSessions,
		OrganizationID:     createdAdmin.OrganizationID,
		Role:               string(createdAdmin.Role),
	})
	if err != nil {
		t.Fatalf("first admin CreateUserSession: %v", err)
	}
	issuedB, err := sessions.CreateUserSession(ctx, service.CreateUserSessionInput{
		UserID:             createdAdmin.ID,
		MaxSessionsPerUser: maxSessions,
		OrganizationID:     createdAdmin.OrganizationID,
		Role:               string(createdAdmin.Role),
	})
	if err != nil {
		t.Fatalf("second admin CreateUserSession: %v", err)
	}

	// Admin-local invariant pin (Decision D-004): BOTH sessions MUST
	// remain active even at cap=1.
	activeAfter, err := repos.Session.ListActiveByUserID(ctx, createdAdmin.ID)
	if err != nil {
		t.Fatalf("ListActiveByUserID: %v", err)
	}
	if len(activeAfter) != 2 {
		t.Fatalf("ADMIN-LOCAL INVARIANT VIOLATED (Decision D-004): org_admin at cap=1 must retain BOTH sessions; got %d active", len(activeAfter))
	}
	gotA := repos.Session // re-declare to avoid unused-variable false positive
	_ = gotA
	// Sanity: session A AND session B IDs must both appear in the active set.
	idSet := map[uuid.UUID]bool{}
	for _, s := range activeAfter {
		idSet[s.ID] = true
	}
	if !idSet[issuedA.Session.ID] {
		t.Error("admin session A missing from active set post-second-login")
	}
	if !idSet[issuedB.Session.ID] {
		t.Error("admin session B missing from active set post-second-login")
	}
}
