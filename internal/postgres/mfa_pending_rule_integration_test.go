//go:build integration

package postgres_test

// Integration teeth for the pending-MFA-login sinks (MFA-PENDING-1).
//
// Asserted against the live SQL: MarkConsumed is atomic single-use (only a live,
// unconsumed, unexpired handle consumes; a second consume is a no-op), and
// RecordFailedVerifyAttempt bumps the counter and invalidates the handle in ONE
// statement exactly at the max-attempts threshold. FAIL-not-skip.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func seedMFAPending(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID uuid.UUID, expiresAt time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO mfa_pending_login_sessions (id, user_id, kind, remember_me, expires_at)
		VALUES ($1, $2, 'verify', false, $3)`,
		id, userID, expiresAt); err != nil {
		t.Fatalf("seed mfa pending: %v", err)
	}
	return id
}

func mfaPendingConsumedAt(t *testing.T, ctx context.Context, db postgres.DBTX, id uuid.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	if err := db.QueryRow(ctx, `SELECT consumed_at FROM mfa_pending_login_sessions WHERE id = $1`, id).Scan(&at); err != nil {
		t.Fatalf("read consumed_at: %v", err)
	}
	return at
}

// RULE: MFA-PENDING-CONSUME-1
func TestMFAPending_MarkConsumedSingleUse(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := postgres.NewPgxMFAPendingLoginSessionRepository(pool)

	orgID := seedScratchOrg(t, pool)
	userID := seedSessionUser(t, ctx, pool, orgID)
	now := time.Now()
	live := seedMFAPending(t, ctx, pool, userID, now.Add(time.Hour))
	expired := seedMFAPending(t, ctx, pool, userID, now.Add(-time.Minute))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mfa_pending_login_sessions WHERE id = ANY($1)`, []uuid.UUID{live, expired})
	})

	// A live handle consumes exactly once.
	ok, err := repo.MarkConsumed(ctx, live, now)
	if err != nil || !ok {
		t.Fatalf("MarkConsumed(live) = (%v, %v), want (true, nil)", ok, err)
	}
	if mfaPendingConsumedAt(t, ctx, pool, live) == nil {
		t.Fatalf("MarkConsumed must set consumed_at")
	}
	// A second consume of the same handle is a no-op (single-use).
	if ok, err := repo.MarkConsumed(ctx, live, now); err != nil || ok {
		t.Errorf("a second MarkConsumed must be (false, nil), got (%v, %v)", ok, err)
	}
	// An expired handle never consumes.
	if ok, err := repo.MarkConsumed(ctx, expired, now); err != nil || ok {
		t.Errorf("MarkConsumed(expired) must be (false, nil), got (%v, %v)", ok, err)
	}
}

// RULE: MFA-PENDING-ATTEMPTS-1
func TestMFAPending_RecordFailedVerifyAttemptBounds(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := postgres.NewPgxMFAPendingLoginSessionRepository(pool)

	orgID := seedScratchOrg(t, pool)
	userID := seedSessionUser(t, ctx, pool, orgID)
	now := time.Now()
	id := seedMFAPending(t, ctx, pool, userID, now.Add(time.Hour))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mfa_pending_login_sessions WHERE id = $1`, id)
	})

	const maxAttempts = 3
	// Attempts below the threshold do NOT invalidate.
	for i := 1; i < maxAttempts; i++ {
		inv, err := repo.RecordFailedVerifyAttempt(ctx, id, maxAttempts, now)
		if err != nil || inv {
			t.Fatalf("attempt %d: RecordFailedVerifyAttempt = (%v, %v), want (false, nil) below threshold", i, inv, err)
		}
	}
	// The attempt that reaches the threshold invalidates the handle in the same statement.
	if inv, err := repo.RecordFailedVerifyAttempt(ctx, id, maxAttempts, now); err != nil || !inv {
		t.Fatalf("the max-attempt failure must invalidate (true), got (%v, %v)", inv, err)
	}
	if mfaPendingConsumedAt(t, ctx, pool, id) == nil {
		t.Errorf("reaching max attempts must set consumed_at")
	}
	// A non-positive threshold fails closed.
	if _, err := repo.RecordFailedVerifyAttempt(ctx, id, 0, now); err == nil {
		t.Errorf("maxAttempts < 1 must be an error (fail closed)")
	}
}
