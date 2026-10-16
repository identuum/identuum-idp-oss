//go:build integration

package postgres_test

// F4 (OSS-PRE-RELEASE-REVIEW-2026-10-10, OSS-REVIEW-FIXES-1): against the
// live SQL, CountRecentFailedVerifyAttempts ages a handle's wrong codes by
// the latest moment they can have been made — LEAST(expires_at, consumed_at)
// — never by the handle's creation. The clock is fixed a year ahead, so the
// rows' created_at (the database's NOW()) lies far before every window under
// test: the creation-based count answers 0 for all of them. FAIL-not-skip.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestMFAPending_CountRecentFailedVerifyAttemptsAgesByAttemptTime(t *testing.T) {
	pool := keyEncPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	repo := postgres.NewPgxMFAPendingLoginSessionRepository(pool)
	orgID := seedScratchOrg(t, pool)
	userID := seedSessionUser(t, ctx, pool, orgID)

	t0 := time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second)
	create := func() uuid.UUID {
		t.Helper()
		row, err := repo.Create(ctx, &domain.MFAPendingLoginSession{ID: uuid.New(), UserID: userID, Kind: domain.MFAPendingKindVerify, ExpiresAt: t0.Add(5 * time.Minute)})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		return row.ID
	}
	miss := func(id uuid.UUID, at time.Time, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := repo.RecordFailedVerifyAttempt(ctx, id, 5, at); err != nil {
				t.Fatalf("record miss: %v", err)
			}
		}
	}
	count := func(since time.Time) (int, time.Time) {
		t.Helper()
		n, oldest, err := repo.CountRecentFailedVerifyAttempts(ctx, userID, since)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		return n, oldest
	}

	// Five misses at t0+4m invalidate the handle at t0+4m: its attempt time
	// is exact.
	invalidated := create()
	miss(invalidated, t0.Add(4*time.Minute), 5)
	// Two misses at t0+4m on a handle that stays live until t0+5m: its misses
	// can only have been made by t0+5m.
	live := create()
	miss(live, t0.Add(4*time.Minute), 2)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mfa_pending_login_sessions WHERE id = ANY($1)`, []uuid.UUID{invalidated, live})
	})

	window := 15 * time.Minute
	if n, oldest := count(t0.Add(15*time.Minute + time.Second).Add(-window)); n != 7 || !oldest.Equal(t0.Add(4*time.Minute)) {
		t.Errorf("at t0+15m+1s: (%d, %s); want (7, t0+4m): every miss made at t0+4m is inside the window, and the oldest aged-out moment is the invalidated handle's", n, oldest)
	}
	if n, oldest := count(t0.Add(19*time.Minute + time.Second).Add(-window)); n != 2 || !oldest.Equal(t0.Add(5*time.Minute)) {
		t.Errorf("at t0+19m+1s: (%d, %s); want (2, t0+5m): the invalidated handle's misses are over fifteen minutes old, the live handle's count until its expiry is", n, oldest)
	}
	if n, oldest := count(t0.Add(20*time.Minute + time.Second).Add(-window)); n != 0 || !oldest.IsZero() {
		t.Errorf("at t0+20m+1s: (%d, %s); want (0, zero): every miss is over fifteen minutes old by any reading", n, oldest)
	}
}
