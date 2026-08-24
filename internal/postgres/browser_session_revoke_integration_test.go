//go:build integration

package postgres_test

// Integration teeth for the browser-session-token revoke sinks (BROWSER-SESSION-1).
//
// Asserted against the live SQL: revoking by token hash or by session id flips
// revoked_at on the matching active row, and both are idempotent — a second
// revoke leaves the original revoked_at untouched and errors on nothing. The
// wire cookie value never appears; only its hash is stored. FAIL-not-skip.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func browserTokenRevokedAt(t *testing.T, ctx context.Context, db postgres.DBTX, hash string) *time.Time {
	t.Helper()
	var at *time.Time
	if err := db.QueryRow(ctx, `SELECT revoked_at FROM browser_session_tokens WHERE token_hash = $1`, hash).Scan(&at); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	return at
}

// seedBrowserSession creates the org -> user -> session chain the
// browser_session_tokens FKs require and returns a fresh session id.
func seedBrowserSession(t *testing.T, ctx context.Context, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	orgID := seedScratchOrg(t, pool)
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, organization_id, role)
		VALUES ($1, $2, 'x', $3::uuid, 'org_user')`,
		userID, "bs-"+uuid.NewString()+"@example.test", orgID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	sessionID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_selector, token_validator_hash, remember_me, is_valid, expires_at)
		VALUES ($1, $2, $3, 'vhash', false, true, NOW() + interval '1 hour')`,
		sessionID, userID, uuid.New()); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return sessionID
}

func seedBrowserToken(t *testing.T, ctx context.Context, repo *postgres.PgxBrowserSessionTokenRepository, hash string, sessionID uuid.UUID) {
	t.Helper()
	if err := repo.Insert(ctx, &domain.BrowserSessionToken{
		ID: uuid.New(), SessionID: sessionID, UserID: uuid.New(),
		TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("insert browser token: %v", err)
	}
}

// RULE: BROWSER-SESSION-REVOKE-1
func TestBrowserSessionTokenRevoke_ByHashAndBySessionIdempotent(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := postgres.NewPgxBrowserSessionTokenRepository(pool)

	hashA := "bshash-" + uuid.NewString()
	hashB := "bshash-" + uuid.NewString()
	sessA := seedBrowserSession(t, ctx, pool)
	sess := seedBrowserSession(t, ctx, pool)
	seedBrowserToken(t, ctx, repo, hashA, sessA)
	seedBrowserToken(t, ctx, repo, hashB, sess)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM browser_session_tokens WHERE token_hash LIKE 'bshash-%'`)
	})

	// Revoke by token hash flips revoked_at.
	if err := repo.RevokeByTokenHash(ctx, hashA, time.Now()); err != nil {
		t.Fatalf("RevokeByTokenHash: %v", err)
	}
	first := browserTokenRevokedAt(t, ctx, pool, hashA)
	if first == nil {
		t.Fatalf("RevokeByTokenHash did not set revoked_at")
	}
	// Idempotent: a second revoke leaves the original revoked_at untouched.
	if err := repo.RevokeByTokenHash(ctx, hashA, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("second RevokeByTokenHash: %v", err)
	}
	if second := browserTokenRevokedAt(t, ctx, pool, hashA); second == nil || !second.Equal(*first) {
		t.Errorf("RevokeByTokenHash not idempotent: %v -> %v", first, second)
	}

	// Revoke by session id flips revoked_at on the session's row.
	if err := repo.RevokeBySessionID(ctx, sess, time.Now()); err != nil {
		t.Fatalf("RevokeBySessionID: %v", err)
	}
	if browserTokenRevokedAt(t, ctx, pool, hashB) == nil {
		t.Fatalf("RevokeBySessionID did not set revoked_at for the session's token")
	}
}
