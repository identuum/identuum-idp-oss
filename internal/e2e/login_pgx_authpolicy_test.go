//go:build integration

// Package e2e — integration coverage for the org auth_policy projection
// + enforcement pinned by slice agent-a-20260710-idp-oss-authpolicy-e2e-
// projection-pin. The companion unit suite at
// internal/service/local_login_service_test.go covers the in-memory
// repository path; this file proves the SAME contract carries through
// the real PgxUserRepository + organizations table JOIN.
//
// Pre-fix posture (before slice
// agent-a-20260709-idp-oss-authpolicy-local-login-enforcement): the
// helper domain.IsLocalCredentialFlowAllowed existed at
// internal/service/local_credential_flow.go:43 with 0 production
// callers. organizations.auth_policy persisted on writes but
// scanUserWithOrg never projected it, so the LocalLoginService.Login
// path never saw the org's auth_policy and idp_only orgs accepted
// local password logins regardless. This integration pin proves the
// 2026-06-24 wire-in:
//
//   1. organizations.auth_policy=idp_only round-trips through
//      PgxUserRepository.FindUsersByEmail into domain.User.OrgAuthPolicy
//      (the new field landed in the wire-in slice).
//   2. LocalLoginService.Login backed by the production PGX repo
//      denies an idp_only + RoleOrgUser login with the generic
//      ErrLoginInvalidCredentials sentinel (the SAME shape as
//      wrong-password — enumeration-safe).
//   3. The locked admin-local invariant holds end-to-end: an
//      idp_only + RoleOrgAdmin login does NOT collapse to
//      ErrLoginInvalidCredentials. Org_admin requires MFA via
//      service.IsMFARequiredForUser, so the admin path lands on
//      ErrLoginMFAEnrollmentRequired — proving the admin passed
//      through the auth_policy gate.
//
// Test discipline (per [[platform/conventions]] and the agent rules):
//   - randomized email + plaintext + org slug per run so the test is
//     isolated from any other operator's demo data and so the
//     plaintext is unique per invocation;
//   - the plaintext password is NEVER printed in any failure message,
//     log line, or assertion;
//   - t.Cleanup soft-deletes the seeded users + org even on failure;
//   - no DB URL appears in any error string (existing classifyOpenError
//     helper used for redaction).
//
// Run:
//
//	go test -tags integration -v ./internal/e2e/...

package e2e

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// seedIDPOnlyOrganization creates a tenant organization with
// AuthPolicy=idp_only and a randomized name/domain/slug so each
// integration-test run is isolated from the operator's demo data.
// The seeded row is soft-deleted on cleanup. The helper mirrors
// seedTestOrganization in login_pgx_password_hash_test.go but lets the
// caller pin the auth_policy value the test needs.
func seedIDPOnlyOrganization(t *testing.T, ctx context.Context, repos *postgres.Repositories) *domain.Organization {
	t.Helper()
	suffix := uuid.NewString()
	org := &domain.Organization{
		Name:       "e2e-authpolicy-org-" + suffix,
		Domain:     "e2e-authpolicy-" + suffix + ".example.invalid",
		OrgSlug:    "e2e-authpolicy-" + suffix[:8],
		Active:     true,
		MFAPolicy:  "optional",
		AuthPolicy: domain.AuthPolicyIDPOnly,
	}
	created, err := repos.Organization.Create(ctx, org)
	if err != nil {
		t.Fatalf("seedIDPOnlyOrganization: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.Organization.Delete(context.Background(), created.ID)
	})
	return created
}

// TestE2E_OSS_AuthPolicyProjection_IDPOnlyDeniesOrgUser is the end-to-
// end regression pin for the slice
// agent-a-20260709-idp-oss-authpolicy-local-login-enforcement that
// landed earlier the same day.
//
// It exercises THREE properties through the real PGX repo:
//
//  1. Projection round-trip — organizations.auth_policy=idp_only is
//     persisted on Create and surfaces on PgxUserRepository
//     .FindUsersByEmail as a non-nil OrgAuthPolicy with value
//     "idp_only" (the new field added in the wire-in slice).
//
//  2. Non-admin enforcement — LocalLoginService.Login wired with the
//     production PGX repo denies an idp_only + RoleOrgUser login
//     with the generic ErrLoginInvalidCredentials sentinel. No
//     LoginResult. No session. The wire shape is BYTE-IDENTICAL to
//     the wrong-password path — pinned by the assertion that the
//     same email + a wrong password also returns
//     ErrLoginInvalidCredentials (enumeration safety).
//
//  3. Admin-local invariant — an idp_only + RoleOrgAdmin login with
//     the correct password does NOT collapse to
//     ErrLoginInvalidCredentials. Because the org's
//     mfa_policy="optional" but the admin's role itself forces MFA
//     via service.IsMFARequiredForUser, the admin lands on
//     ErrLoginMFAEnrollmentRequired — which proves the auth_policy
//     gate was PASSED (the admin reached the MFA gate that runs
//     AFTER auth_policy).
func TestE2E_OSS_AuthPolicyProjection_IDPOnlyDeniesOrgUser(t *testing.T) {
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

	org := seedIDPOnlyOrganization(t, ctx, repos)

	// ── Sub-step A: seed a normal org_user under the idp_only org.

	userEmail := strings.ToLower("e2e-authpolicy-user-" + uuid.NewString() + "@example.invalid")
	userPlaintext := "u-" + uuid.NewString() + "-marker-not-printed"
	userID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed: uuid generation failed: %v", err)
	}
	createdUser, err := repos.User.Create(ctx, &domain.User{
		ID:             userID,
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

	// ── Property 1: projection round-trip for org_user.

	users, err := repos.User.FindUsersByEmail(ctx, userEmail)
	if err != nil {
		t.Fatalf("FindUsersByEmail (org_user): %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("FindUsersByEmail (org_user): want exactly 1 user, got %d", len(users))
	}
	got := users[0]
	if got.ID != userID {
		t.Fatal("FindUsersByEmail (org_user): returned ID does not match seeded ID")
	}
	if got.OrgAuthPolicy == nil {
		t.Fatal("FindUsersByEmail (org_user): OrgAuthPolicy is nil (REGRESSION: scanUserWithOrg omits o.auth_policy from SELECT or fails to populate user.OrgAuthPolicy)")
	}
	if *got.OrgAuthPolicy != domain.AuthPolicyIDPOnly {
		// Print the EXPECTED + GOT values structurally — the field is
		// a public org policy enum, not a credential.
		t.Fatalf("FindUsersByEmail (org_user): OrgAuthPolicy = %q, want %q", *got.OrgAuthPolicy, domain.AuthPolicyIDPOnly)
	}

	// ── Property 2: non-admin enforcement through the real repo.

	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	// mfa = nil — the seeded org_user has MFAEnabled=false; the
	// LocalLoginService MFA branch never fires. Even if it did,
	// auth_policy enforcement runs BEFORE the MFA gate so the policy
	// denial would still surface here.
	login := service.NewLocalLoginService(nil, repos.User, sessions, nil)

	t.Run("idp_only + org_user correct password denied as generic invalid_credentials", func(t *testing.T) {
		result, err := login.Login(ctx, service.LoginInput{
			Email:    userEmail,
			Password: userPlaintext, // correct password — reaches the auth_policy gate.
		})
		if !errors.Is(err, service.ErrLoginInvalidCredentials) {
			t.Fatalf("idp_only + org_user correct password: want ErrLoginInvalidCredentials (generic), got %v", err)
		}
		if result != nil {
			t.Fatalf("policy-denied login MUST NOT return a LoginResult, got %+v", result)
		}
	})

	t.Run("idp_only + org_user wrong password also collapses to invalid_credentials (enumeration safety)", func(t *testing.T) {
		_, err := login.Login(ctx, service.LoginInput{
			Email:    userEmail,
			Password: "intentionally-wrong-not-the-seeded-value",
		})
		if !errors.Is(err, service.ErrLoginInvalidCredentials) {
			t.Fatalf("idp_only + org_user wrong password: want ErrLoginInvalidCredentials, got %v", err)
		}
	})

	// ── Sub-step B: seed an org_admin in the SAME idp_only org.

	adminEmail := strings.ToLower("e2e-authpolicy-admin-" + uuid.NewString() + "@example.invalid")
	adminPlaintext := "a-" + uuid.NewString() + "-marker-not-printed"
	adminID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed admin: uuid generation failed: %v", err)
	}
	createdAdmin, err := repos.User.Create(ctx, &domain.User{
		ID:             adminID,
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

	// ── Property 1 (admin): projection round-trip for org_admin.

	adminUsers, err := repos.User.FindUsersByEmail(ctx, adminEmail)
	if err != nil {
		t.Fatalf("FindUsersByEmail (org_admin): %v", err)
	}
	if len(adminUsers) != 1 {
		t.Fatalf("FindUsersByEmail (org_admin): want exactly 1 user, got %d", len(adminUsers))
	}
	gotAdmin := adminUsers[0]
	if gotAdmin.OrgAuthPolicy == nil {
		t.Fatal("FindUsersByEmail (org_admin): OrgAuthPolicy is nil (REGRESSION: projection broken)")
	}
	if *gotAdmin.OrgAuthPolicy != domain.AuthPolicyIDPOnly {
		t.Fatalf("FindUsersByEmail (org_admin): OrgAuthPolicy = %q, want %q", *gotAdmin.OrgAuthPolicy, domain.AuthPolicyIDPOnly)
	}
	if gotAdmin.Role != domain.RoleOrgAdmin {
		t.Fatalf("FindUsersByEmail (org_admin): Role = %q, want %q", gotAdmin.Role, domain.RoleOrgAdmin)
	}

	// ── Property 3: locked admin-local invariant end-to-end.
	//
	// org_admin with correct password MUST NOT collapse to
	// ErrLoginInvalidCredentials — that would mean the auth_policy
	// gate denied an admin, which would violate Decision D-004.
	// Because service.IsMFARequiredForUser returns true for
	// RoleOrgAdmin (regardless of mfa_policy), the admin lands on
	// ErrLoginMFAEnrollmentRequired — which proves the admin path
	// reached the MFA gate that runs AFTER the auth_policy gate.

	t.Run("idp_only + org_admin correct password passes auth_policy gate (admin-local invariant)", func(t *testing.T) {
		result, err := login.Login(ctx, service.LoginInput{
			Email:    adminEmail,
			Password: adminPlaintext,
		})
		if errors.Is(err, service.ErrLoginInvalidCredentials) {
			t.Fatal("ADMIN-LOCAL INVARIANT VIOLATED: idp_only + org_admin must NOT collapse to invalid_credentials (Decision D-004)")
		}
		if !errors.Is(err, service.ErrLoginMFAEnrollmentRequired) {
			t.Fatalf("expected MFA-enrollment gate (admin passed auth_policy), got err=%v", err)
		}
		// Partial-result contract: User is populated so the HTTP
		// layer can mint a pending-MFA session_id; Session +
		// RefreshToken remain unset because no session is created on
		// this path.
		if result == nil || result.User == nil {
			t.Fatal("expected partial LoginResult with User populated past auth_policy gate")
		}
		if result.User.ID != adminID {
			t.Fatal("partial result user_id mismatch — admin path returned the wrong row")
		}
		if result.Session != nil {
			t.Fatal("admin-on-MFA-gate path MUST NOT create a Session")
		}
		if result.RefreshToken != "" {
			t.Fatal("admin-on-MFA-gate path MUST NOT issue a RefreshToken")
		}
	})
}
