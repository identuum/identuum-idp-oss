//go:build integration

package postgres_test

// Integration teeth for the session-revocation sinks (SESSION-SINK-SCOPE-1).
//
// Asserted against the live SQL: Revoke flips revoked_at on ONLY the one
// targeted session id (a sibling session and another user's session stay
// active) and is idempotent (a repeat is ErrSessionNotFound and the original
// revoked_at does not move); RevokeByUserID flips revoked_at on ONLY that
// user's active sessions (another user's session stays active) and is a nil
// no-op on repeat. FAIL-not-skip.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func seedSessionUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, organization_id, role)
		VALUES ($1, $2, 'x', $3::uuid, 'org_user')`,
		id, "sr-"+uuid.NewString()+"@example.test", orgID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedActiveSession(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_selector, token_validator_hash, remember_me, is_valid, expires_at)
		VALUES ($1, $2, $3, 'vhash', false, true, NOW() + interval '1 hour')`,
		id, userID, uuid.New()); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return id
}

func sessionRowRevokedAt(t *testing.T, ctx context.Context, db postgres.DBTX, id uuid.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	if err := db.QueryRow(ctx, `SELECT revoked_at FROM sessions WHERE id = $1`, id).Scan(&at); err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	return at
}

// RULE: SESSION-SINK-SCOPE-1
func TestSessionRevokeSinks_ScopedToPredicate(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := postgres.NewPgxSessionRepository(pool)

	orgID := seedScratchOrg(t, pool)
	userA := seedSessionUser(t, ctx, pool, orgID)
	userB := seedSessionUser(t, ctx, pool, orgID)
	a1 := seedActiveSession(t, ctx, pool, userA)
	a2 := seedActiveSession(t, ctx, pool, userA)
	b1 := seedActiveSession(t, ctx, pool, userB)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM sessions WHERE id = ANY($1)`, []uuid.UUID{a1, a2, b1})
	})

	// Revoke by id flips revoked_at on ONLY that session.
	if err := repo.Revoke(ctx, a1, uuid.Nil, "self"); err != nil {
		t.Fatalf("Revoke(a1): %v", err)
	}
	ra1 := sessionRowRevokedAt(t, ctx, pool, a1)
	if ra1 == nil {
		t.Fatalf("Revoke(a1) did not set revoked_at")
	}
	if sessionRowRevokedAt(t, ctx, pool, a2) != nil {
		t.Errorf("Revoke(a1) must not touch the sibling session a2")
	}
	if sessionRowRevokedAt(t, ctx, pool, b1) != nil {
		t.Errorf("Revoke(a1) must not touch another user's session b1")
	}

	// Idempotent: a repeat Revoke leaves the original revoked_at untouched.
	if err := repo.Revoke(ctx, a1, uuid.Nil, "self-again"); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Errorf("a repeat Revoke of an already-revoked session must be ErrSessionNotFound, got %v", err)
	}
	if ra1b := sessionRowRevokedAt(t, ctx, pool, a1); ra1b == nil || !ra1b.Equal(*ra1) {
		t.Errorf("a repeat Revoke must leave revoked_at unchanged: %v -> %v", ra1, ra1b)
	}

	// RevokeByUserID flips revoked_at on the user's remaining active session
	// (a2) and never on another user's session (b1).
	if err := repo.RevokeByUserID(ctx, userA, "self-all"); err != nil {
		t.Fatalf("RevokeByUserID(userA): %v", err)
	}
	if sessionRowRevokedAt(t, ctx, pool, a2) == nil {
		t.Errorf("RevokeByUserID(userA) must revoke the user's active session a2")
	}
	if sessionRowRevokedAt(t, ctx, pool, b1) != nil {
		t.Errorf("RevokeByUserID(userA) must not touch another user's session b1")
	}

	// Idempotent: a repeat call errors on nothing and leaves b1 untouched.
	if err := repo.RevokeByUserID(ctx, userA, "self-all"); err != nil {
		t.Errorf("a repeat RevokeByUserID must be a nil no-op, got %v", err)
	}
	if sessionRowRevokedAt(t, ctx, pool, b1) != nil {
		t.Errorf("RevokeByUserID must never touch another user's session b1")
	}
}
