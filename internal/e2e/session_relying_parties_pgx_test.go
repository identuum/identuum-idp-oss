//go:build integration

package e2e

// session_relying_parties (migration 0047) against the live pgx repository: a
// (session, client) pair is recorded once however often the token endpoint
// records it, each session lists only its own relying parties, and the rows go
// with their session.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestE2E_OSS_SessionRelyingPartiesRecordOncePerPairAndGoWithTheSession(t *testing.T) {
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
	user, err := repos.User.Create(ctx, &domain.User{
		ID: uuid.New(), OrganizationID: org.ID, Email: strings.ToLower("e2e-rp-" + uuid.NewString() + "@example.invalid"),
		PasswordHash: "rp-" + uuid.NewString() + "-not-printed", Role: domain.RoleOrgUser,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _ = repos.User.Delete(context.Background(), user.ID, user.OrganizationID) })

	newSession := func() *domain.Session {
		t.Helper()
		id, _ := uuid.NewV7()
		selector := uuid.New()
		sum := sha256.Sum256([]byte("validator-" + id.String()))
		hash := hex.EncodeToString(sum[:])
		now := time.Now().UTC()
		s, err := repos.Session.Create(ctx, &domain.Session{
			ID: id, UserID: user.ID, TokenSelector: &selector, TokenValidatorHash: &hash,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour), IsValid: true,
		})
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		return s
	}
	first, second := newSession(), newSession()
	rp := repos.SessionRelyingParty

	for _, clientID := range []string{"app-b", "app-a", "app-a"} {
		if err := rp.Record(ctx, first.ID, clientID); err != nil {
			t.Fatalf("Record(%s): %v", clientID, err)
		}
	}
	got, err := rp.ClientIDs(ctx, first.ID)
	if err != nil {
		t.Fatalf("ClientIDs: %v", err)
	}
	if len(got) != 2 || !slices.Contains(got, "app-a") || !slices.Contains(got, "app-b") {
		t.Errorf("ClientIDs = %v; want app-a and app-b once each", got)
	}
	if other, _ := rp.ClientIDs(ctx, second.ID); len(other) != 0 {
		t.Errorf("another session lists %v; want none", other)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, first.ID); err != nil {
		t.Fatalf("delete session: %v", err)
	}
	if after, _ := rp.ClientIDs(ctx, first.ID); len(after) != 0 {
		t.Errorf("after the session is deleted ClientIDs = %v; want none (ON DELETE CASCADE)", after)
	}
}
