//go:build integration

// Package e2e — integration coverage for the local-login pgx round-trip
// that previously silently failed because PgxUserRepository.FindUsersByEmail
// omitted u.password_hash from its SELECT projection.
//
// Pre-fix symptom (pinned by reproduction below if the regression ever
// returns): a user seeded with a known argon2id-hashed password is
// returned by FindUsersByEmail, but with PasswordHash == "" — which
// makes crypto.CompareHashAndPassword reject every login attempt as
// invalid_credentials.
//
// Test discipline (per [[platform/conventions]] and the agent rules):
//   - randomized email + plaintext per run so the test is isolated from
//     the operator's demo data;
//   - the plaintext, the resulting hash, and the issued refresh token
//     are NEVER printed in any failure message, log line, or assertion;
//   - t.Cleanup soft-deletes the seeded user even on failure, so the
//     demo DB stays clean.
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

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// TestE2E_OSS_FindUsersByEmail_PasswordHashRoundTrip is the regression
// pin for the FindUsersByEmail password_hash projection. It seeds a
// fresh, isolated user, calls the production pgx FindUsersByEmail, and
// verifies that:
//
//   - exactly one user is returned;
//   - PasswordHash is non-empty;
//   - PasswordHash has the $argon2id$ PHC prefix;
//   - crypto.CompareHashAndPassword accepts the known plaintext against
//     the returned hash (i.e. recovery's argon2id write and login's
//     argon2id verify are end-to-end compatible through pgx).
//
// On failure the test never echoes the plaintext, the hash, or any
// other credential-bearing value.
func TestE2E_OSS_FindUsersByEmail_PasswordHashRoundTrip(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.User == nil {
		t.Fatal("repository factory returned nil User repo")
	}

	// Randomized email + plaintext per run so this test never collides
	// with the operator's demo data and so the plaintext is unique per
	// invocation (any leak in a log would be obvious AND limited).
	email := strings.ToLower("e2e-login-rt-" + uuid.NewString() + "@example.invalid")
	plaintext := "rt-" + uuid.NewString() + "-marker-not-printed"

	seededID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed: uuid generation failed: %v", err)
	}

	org := seedTestOrganization(t, ctx, repos)

	created, err := repos.User.Create(ctx, &domain.User{
		ID:             seededID,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   plaintext, // Create argon2id-hashes any non-PHC string
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	t.Cleanup(func() {
		// Soft-delete the seeded user; never let an integration test
		// pollute the demo DB. Errors are ignored — the cleanup is
		// best-effort.
		_ = repos.User.Delete(context.Background(), created.ID, created.OrganizationID)
	})

	users, err := repos.User.FindUsersByEmail(ctx, email)
	if err != nil {
		t.Fatalf("FindUsersByEmail: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("FindUsersByEmail: want exactly 1 user, got %d", len(users))
	}
	got := users[0]

	if got.ID != seededID {
		t.Fatalf("FindUsersByEmail: returned ID does not match seeded ID")
	}
	if got.PasswordHash == "" {
		t.Fatal("FindUsersByEmail: PasswordHash must be non-empty (REGRESSION: SELECT omits u.password_hash)")
	}
	if !strings.HasPrefix(got.PasswordHash, "$argon2id$") {
		// Do NOT print the actual hash value here. The prefix check is
		// safe to assert structurally.
		t.Fatal("FindUsersByEmail: returned PasswordHash does not have $argon2id$ prefix")
	}

	if err := crypto.CompareHashAndPassword([]byte(got.PasswordHash), []byte(plaintext)); err != nil {
		// Map the error to a category string so the plaintext is never
		// part of the assertion message.
		t.Fatalf("CompareHashAndPassword: known-good plaintext rejected (error category: %s)", classifyCompareError(err))
	}

	// Negative case: a clearly-wrong password must NOT verify against
	// the same hash.
	if err := crypto.CompareHashAndPassword([]byte(got.PasswordHash), []byte("intentionally-wrong-not-the-seeded-value")); err == nil {
		t.Fatal("CompareHashAndPassword: wrong password unexpectedly accepted")
	}
}

// TestE2E_OSS_LocalLoginService_RoundTrip exercises the full
// LocalLoginService.Login state machine through the production
// PgxUserRepository.FindUsersByEmail. It pins three properties:
//
//  1. A correct plaintext password completes login (no
//     ErrLoginInvalidCredentials).
//  2. A wrong password collapses to ErrLoginInvalidCredentials.
//  3. The success path returns a LoginResult whose User matches the
//     seeded row. The refresh token is verified non-empty by length
//     only — it is NEVER printed.
//
// MFA is disabled on the seeded row, so the MFA branch is bypassed.
// This is the same posture as the local-demo site_admin row after
// `make oss-recover-site-admin`.
func TestE2E_OSS_LocalLoginService_RoundTrip(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.User == nil || repos.Session == nil {
		t.Fatal("repository factory returned nil User or Session repo")
	}

	email := strings.ToLower("e2e-login-svc-" + uuid.NewString() + "@example.invalid")
	plaintext := "svc-" + uuid.NewString() + "-marker-not-printed"

	seededID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed: uuid generation failed: %v", err)
	}

	org := seedTestOrganization(t, ctx, repos)

	created, err := repos.User.Create(ctx, &domain.User{
		ID:             seededID,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   plaintext,
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), created.ID, created.OrganizationID)
	})

	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	// MFA verifier intentionally nil — the seeded user has
	// MFAEnabled=false, so the LocalLoginService MFA branch never
	// fires. This mirrors the local-demo site_admin posture.
	login := service.NewLocalLoginService(nil, repos.User, sessions, nil)

	t.Run("correct password reaches success path", func(t *testing.T) {
		result, err := login.Login(ctx, service.LoginInput{
			Email:      email,
			Password:   plaintext,
			RememberMe: false,
		})
		if err != nil {
			// Pin the regression: pre-fix this returned
			// ErrLoginInvalidCredentials because user.PasswordHash
			// was empty.
			if errors.Is(err, service.ErrLoginInvalidCredentials) {
				t.Fatal("Login: correct password rejected with ErrLoginInvalidCredentials (REGRESSION: FindUsersByEmail omits password_hash)")
			}
			t.Fatalf("Login: unexpected error: %v", err)
		}
		if result == nil || result.User == nil || result.Session == nil {
			t.Fatal("Login: success returned nil result, user, or session")
		}
		if result.User.ID != seededID {
			t.Fatal("Login: success returned a user whose ID does not match the seeded row")
		}
		if len(result.RefreshToken) == 0 {
			t.Fatal("Login: success returned empty refresh token")
		}
		// The refresh token is a high-entropy secret. Do NOT print it.
		// A length sanity check is sufficient structural evidence.
		if len(result.RefreshToken) < 32 {
			t.Fatalf("Login: refresh token suspiciously short (len=%d)", len(result.RefreshToken))
		}
	})

	t.Run("wrong password returns invalid_credentials", func(t *testing.T) {
		_, err := login.Login(ctx, service.LoginInput{
			Email:      email,
			Password:   "intentionally-wrong-not-the-seeded-value",
			RememberMe: false,
		})
		if !errors.Is(err, service.ErrLoginInvalidCredentials) {
			t.Fatalf("Login: wrong password: want ErrLoginInvalidCredentials, got %v", err)
		}
	})
}

// seedTestOrganization creates a tenant organization with a randomized
// name/domain/slug so each integration-test run is isolated from the
// operator's demo data. Required because the OSS users table carries
// `CHECK (role = 'site_admin' OR organization_id IS NOT NULL)` —
// non-site_admin users must be bound to a real org. The seeded row is
// soft-deleted on cleanup.
func seedTestOrganization(t *testing.T, ctx context.Context, repos *postgres.Repositories) *domain.Organization {
	t.Helper()
	suffix := uuid.NewString()
	org := &domain.Organization{
		Name:      "e2e-test-org-" + suffix,
		Domain:    "e2e-" + suffix + ".example.invalid",
		OrgSlug:   "e2e-org-" + suffix[:8],
		Active:    true,
		MFAPolicy: "optional",
	}
	created, err := repos.Organization.Create(ctx, org)
	if err != nil {
		t.Fatalf("seedTestOrganization: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.Organization.Delete(context.Background(), created.ID)
	})
	return created
}

// classifyCompareError converts a crypto.CompareHashAndPassword error
// into a short category string. The original error message would not
// contain a credential, but using a category keeps the test output
// uniform with classifyOpenError / classifyMigrationError above.
func classifyCompareError(err error) string {
	if err == nil {
		return "<nil>"
	}
	switch {
	case errors.Is(err, crypto.ErrMismatchedHashAndPassword):
		return "mismatched"
	case errors.Is(err, crypto.ErrUnsupportedHashFormat):
		return "unsupported-format"
	case errors.Is(err, crypto.ErrInvalidHashFormat):
		return "invalid-format"
	default:
		return "other"
	}
}
