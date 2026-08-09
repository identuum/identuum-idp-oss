//go:build integration

// Package e2e — integration coverage for the OSS account-sessions
// list + revoke flow against the live pgx repository.
//
// Test discipline:
//   - randomized email + per-run UUID isolation;
//   - session tokens NEVER printed in any assertion message
//     (the test does not call CreateUserSession; it inserts a
//     raw row via the repo to avoid touching the rotation
//     pipeline and to make ownership semantics explicit);
//   - t.Cleanup soft-deletes the seeded user.
//
// Run:
//
//	go test -tags integration -v ./internal/e2e/...

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// TestE2E_OSS_SessionsRevokeRoundTrip exercises the pgx
// SessionRepository's full ListByUserID → Revoke → re-list cycle
// alongside the OSS UserSessionService.RevokeSession surface that
// the new HTTP handler calls into. After RevokeSession the
// repo's ListByUserID(false) must drop the row.
func TestE2E_OSS_SessionsRevokeRoundTrip(t *testing.T) {
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
	if repos == nil || repos.Session == nil {
		t.Fatal("repository factory returned nil Session repo")
	}

	org := seedTestOrganization(t, ctx, repos)
	email := strings.ToLower("e2e-sess-" + uuid.NewString() + "@example.invalid")
	plaintext := "sess-" + uuid.NewString() + "-not-printed"
	userID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed: uuid: %v", err)
	}
	createdUser, err := repos.User.Create(ctx, &domain.User{
		ID:             userID,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   plaintext,
		Role:           domain.RoleOrgUser,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), createdUser.ID, createdUser.OrganizationID)
	})

	// Insert TWO session rows via the repo. We compute random
	// selectors + validator hashes to satisfy the schema's
	// uniqueness constraint without using the rotation pipeline.
	sessions := make([]*domain.Session, 0, 2)
	for i := 0; i < 2; i++ {
		sessID, err := uuid.NewV7()
		if err != nil {
			t.Fatalf("uuid: %v", err)
		}
		selector := uuid.New()
		hashBytes := sha256.Sum256([]byte("validator-" + sessID.String()))
		validatorHash := hex.EncodeToString(hashBytes[:])
		ip := "10.0.0.10"
		ua := "test-agent/1.0"
		now := time.Now().UTC()
		s := &domain.Session{
			ID:                 sessID,
			UserID:             createdUser.ID,
			TokenSelector:      &selector,
			TokenValidatorHash: &validatorHash,
			CreatedAt:          now,
			ExpiresAt:          now.Add(time.Hour),
			IsValid:            true,
			IPAddress:          &ip,
			UserAgent:          &ua,
		}
		created, err := repos.Session.Create(ctx, s)
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		sessions = append(sessions, created)
	}
	t.Cleanup(func() {
		for _, s := range sessions {
			_ = repos.Session.Revoke(context.Background(), s.ID, createdUser.OrganizationID, "test_cleanup")
		}
	})

	// ListByUserID(includeInvalid=false) must see both rows.
	out, err := repos.Session.ListByUserID(ctx, createdUser.ID, false)
	if err != nil {
		t.Fatalf("ListByUserID: %v", err)
	}
	if len(out) < 2 {
		t.Fatalf("ListByUserID: expected at least 2 rows, got %d", len(out))
	}

	// Use the OSS UserSessionService.RevokeSession surface — same
	// path the new HTTP handler calls into.
	userSessionSvc := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	if err := userSessionSvc.RevokeSession(ctx, sessions[0].ID, "user_requested"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	// After revoke, ListByUserID(includeInvalid=false) must drop
	// the revoked row. Some implementations require a re-query;
	// the OSS pgx implementation filters via revoked_at IS NULL.
	out, err = repos.Session.ListByUserID(ctx, createdUser.ID, false)
	if err != nil {
		t.Fatalf("ListByUserID after revoke: %v", err)
	}
	for _, s := range out {
		if s.ID == sessions[0].ID {
			t.Error("revoked session must NOT appear in ListByUserID(false)")
		}
	}
}
