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

// The per-user wrong-code total spans handles: it sums failed_attempts over
// the user's verify handles inside the window, whatever their state, and the
// maintenance sweep keeps an expired verify handle that recorded wrong codes
// for repository.MFAFailedAttemptRetention so the sum does not shrink early.
func TestMFAPending_CountRecentFailedVerifyAttemptsAndRetention(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := postgres.NewPgxMFAPendingLoginSessionRepository(pool)

	orgID := seedScratchOrg(t, pool)
	userID := seedSessionUser(t, ctx, pool, orgID)
	otherID := seedSessionUser(t, ctx, pool, orgID)

	seed := func(user uuid.UUID, kind string, failed int, age, ttl time.Duration) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := pool.Exec(ctx, `
			INSERT INTO mfa_pending_login_sessions (id, user_id, kind, remember_me, failed_attempts, created_at, expires_at)
			VALUES ($1, $2, $3, false, $4, NOW() - make_interval(secs => $5), NOW() - make_interval(secs => $5) + make_interval(secs => $6))`,
			id, user, kind, failed, age.Seconds(), ttl.Seconds()); err != nil {
			t.Fatalf("seed mfa pending: %v", err)
		}
		return id
	}
	exists := func(id uuid.UUID) bool {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM mfa_pending_login_sessions WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n == 1
	}

	recentExpired := seed(userID, "verify", 3, 10*time.Minute, 5*time.Minute) // expired, inside the window
	recentLive := seed(userID, "verify", 2, time.Minute, 5*time.Minute)
	old := seed(userID, "verify", 4, 2*time.Hour, 5*time.Minute)       // outside any window
	clean := seed(userID, "verify", 0, 30*time.Minute, 5*time.Minute)  // expired, no wrong codes
	enroll := seed(userID, "enroll", 4, 10*time.Minute, 5*time.Minute) // not a verify handle
	someoneElse := seed(otherID, "verify", 4, time.Minute, 5*time.Minute)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mfa_pending_login_sessions WHERE id = ANY($1)`,
			[]uuid.UUID{recentExpired, recentLive, old, clean, enroll, someoneElse})
	})

	since := time.Now().Add(-15 * time.Minute)
	n, oldest, err := repo.CountRecentFailedVerifyAttempts(ctx, userID, since)
	if err != nil || n != 5 {
		t.Errorf("CountRecentFailedVerifyAttempts = (%d, %v), want (5, nil): 3 expired + 2 live verify wrong codes, nothing from the old, enroll or another user's handle", n, err)
	}
	// FUNC-M3: the oldest counted handle is the one created 10 minutes ago.
	if age := time.Since(oldest); age < 9*time.Minute || age > 11*time.Minute {
		t.Errorf("oldest counted handle is %s old, want about 10m (the expired verify handle with wrong codes)", age)
	}
	if n, oldest, err := repo.CountRecentFailedVerifyAttempts(ctx, uuid.New(), since); err != nil || n != 0 || !oldest.IsZero() {
		t.Errorf("a user with no handles = (%d, %s, %v), want (0, zero, nil)", n, oldest, err)
	}

	if _, err := repo.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if !exists(recentExpired) {
		t.Error("an expired verify handle with wrong codes inside the retention must survive the sweep")
	}
	if exists(old) {
		t.Error("an expired verify handle past the retention must be swept")
	}
	if exists(clean) {
		t.Error("an expired verify handle with no wrong codes must be swept")
	}
	if exists(enroll) {
		t.Error("an expired enroll handle (it holds the candidate secret) must be swept")
	}
	if n, _, err := repo.CountRecentFailedVerifyAttempts(ctx, userID, since); err != nil || n != 5 {
		t.Errorf("after the sweep = (%d, %v), want (5, nil): the sweep must not shrink the window", n, err)
	}
	// FUNC-M3: the operator's MFA reset deletes the user's pending rows, and
	// with them the misses the bound counts; another user's stay.
	if _, err := repo.DeleteForUser(ctx, userID); err != nil {
		t.Fatalf("DeleteForUser: %v", err)
	}
	if n, _, err := repo.CountRecentFailedVerifyAttempts(ctx, userID, since); err != nil || n != 0 {
		t.Errorf("after DeleteForUser = (%d, %v), want (0, nil)", n, err)
	}
	if !exists(someoneElse) {
		t.Error("DeleteForUser removed another user's handle")
	}
}
