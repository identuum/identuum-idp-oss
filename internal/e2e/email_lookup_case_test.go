//go:build integration

// Package e2e — OSS-0914-STAGE-3 item 1 (follow-up of owner decision
// EMAIL-SCOPE (a), 2026-10-13): every sign-in and reset lookup by address
// finds the account whatever case and surrounding spaces were typed. Writers
// store addresses trimmed and lowercased since 0056; the lookups match on
// lower(email), so an older account whose address was stored in mixed case
// before 0056 is found too (0056 guarantees one live account per lower(email)).
//
// Addresses are fixtures under example.invalid; passwords and tokens are
// never printed.
package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// RULE: EMAIL-LOOKUP-CASE-1
func TestE2E_OSS_EmailLookupCase(t *testing.T) {
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
	org := seedTestOrganization(t, ctx, repos)

	seed := func(email, password string) *domain.User {
		t.Helper()
		u, err := repos.User.Create(ctx, &domain.User{ID: uuid.New(), OrganizationID: org.ID, Email: email,
			PasswordHash: password, Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true})
		if err != nil {
			t.Fatalf("seed user: %v", err)
		}
		return u
	}

	// A current account: stored lowercased by the writer.
	suffix := uuid.NewString()[:8]
	current := "lookup-" + suffix + "@example.invalid"
	currentPassword := "lk-" + uuid.NewString()
	cur := seed(current, currentPassword)
	typed := "  " + strings.ToUpper(current[:1]) + current[1:strings.Index(current, "@")] + "@Example.INVALID  "

	// An older account: its address was stored in mixed case before 0056.
	legacyStored := "Legacy-" + suffix + "@Example.Invalid"
	legacyPassword := "lg-" + uuid.NewString()
	leg := seed(strings.ToLower(legacyStored), legacyPassword)
	if _, err := pool.Exec(ctx, `UPDATE users SET email = $1 WHERE id = $2`, legacyStored, leg.ID); err != nil {
		t.Fatalf("store the older mixed-case address: %v", err)
	}
	legacyTyped := strings.ToLower(legacyStored)

	webauthn, err := service.NewWebAuthnService(service.WebAuthnServiceConfig{
		BaseURL:     "https://idp.example.invalid",
		UserRepo:    repos.User,
		CredRepo:    repos.WebAuthnCredential,
		SessionRepo: repository.NewInMemoryWebAuthnSessionRepository(),
	})
	if err != nil {
		t.Fatalf("webauthn service: %v", err)
	}
	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	login := service.NewLocalLoginService(nil, repos.User, sessions, nil)

	t.Run("passkey_typed_case_and_spaces", func(t *testing.T) {
		u, err := webauthn.FindUserByEmail(ctx, typed)
		if err != nil || u == nil || u.ID != cur.ID {
			t.Fatalf("passkey lookup of the typed address: want the account, got user=%v err=%v", u != nil, err)
		}
	})
	t.Run("passkey_older_mixed_case_row", func(t *testing.T) {
		u, err := webauthn.FindUserByEmail(ctx, legacyTyped)
		if err != nil || u == nil || u.ID != leg.ID {
			t.Fatalf("passkey lookup of an older mixed-case account: want the account, got user=%v err=%v", u != nil, err)
		}
	})
	t.Run("login_typed_case_and_spaces", func(t *testing.T) {
		res, err := login.Login(ctx, service.LoginInput{Email: typed, Password: currentPassword})
		if err != nil || res == nil || res.User == nil || res.User.ID != cur.ID {
			t.Fatalf("login with the typed address: want success, got err=%v", err)
		}
	})
	t.Run("login_older_mixed_case_row", func(t *testing.T) {
		res, err := login.Login(ctx, service.LoginInput{Email: legacyTyped, Password: legacyPassword})
		if err != nil || res == nil || res.User == nil || res.User.ID != leg.ID {
			t.Fatalf("login of an older mixed-case account: want success, got err=%v", err)
		}
	})
	t.Run("reset_lookup_older_mixed_case_row", func(t *testing.T) {
		// Password reset and verification re-send look up the address the
		// same way after lowercasing what was typed.
		users, err := repos.User.FindUsersByEmail(ctx, legacyTyped)
		if err != nil || len(users) != 1 || users[0].ID != leg.ID {
			t.Fatalf("reset lookup of an older mixed-case account: want 1 account, got %d err=%v", len(users), err)
		}
	})
	t.Run("federated_lookup_older_mixed_case_row", func(t *testing.T) {
		// The first sign-in through an organization's identity provider
		// looks up the normalized address inside the organization.
		u, err := repos.User.GetByEmailAndOrgID(ctx, org.ID, legacyTyped)
		if err != nil || u == nil || u.ID != leg.ID {
			t.Fatalf("in-organization lookup of an older mixed-case account: want the account, got user=%v err=%v", u != nil, err)
		}
	})
}
