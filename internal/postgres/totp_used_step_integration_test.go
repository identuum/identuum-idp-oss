//go:build integration

package postgres_test

// Integration teeth for the TOTP single-use store (totp_used_steps,
// migration 0040; THE-CODE-THAT-WORKS-TWICE). Asserted against the live
// SQL: Claim creates a (user, step) row exactly once — the second claim of
// the same pair is (false, nil), a different step is a first use again —
// and the sweep removes only rows whose expiry has passed. FAIL-not-skip.
// The unit rule TOTP-SINGLE-USE-1 lives in internal/service; this file
// proves the store the rule relies on.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestTOTPUsedStep_ClaimIsSingleUseAndSweepKeepsLiveRows(t *testing.T) {
	pool := keyEncPool(t)
	// Keep the pool open until the row, user and organization cleanups finish.
	t.Cleanup(pool.Close)
	ctx := context.Background()
	repo := postgres.NewPgxTOTPUsedStepRepository(pool)

	orgID := seedScratchOrg(t, pool)
	userID := seedSessionUser(t, ctx, pool, orgID)
	other := uuid.New()
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM totp_used_steps WHERE user_id IN ($1, $2)`, userID, other); err != nil {
			t.Errorf("clean up owned TOTP steps: %v", err)
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Errorf("clean up seeded user: %v", err)
		}
	})

	now := time.Now().UTC()
	step := now.Unix() / 30
	expires := now.Add(2 * time.Minute)

	first, err := repo.Claim(ctx, userID, step, expires)
	if err != nil || !first {
		t.Fatalf("Claim(first) = (%v, %v), want (true, nil)", first, err)
	}
	again, err := repo.Claim(ctx, userID, step, expires)
	if err != nil || again {
		t.Fatalf("Claim(same pair again) = (%v, %v), want (false, nil): the same step was accepted twice", again, err)
	}
	next, err := repo.Claim(ctx, userID, step+1, expires)
	if err != nil || !next {
		t.Fatalf("Claim(next step) = (%v, %v), want (true, nil)", next, err)
	}
	if ok, err := repo.Claim(ctx, other, step, expires); err != nil || !ok {
		t.Fatalf("Claim(another user, same step) = (%v, %v), want (true, nil)", ok, err)
	}

	assertOwnedRows := func(phase string, want int) {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM totp_used_steps WHERE user_id IN ($1, $2)`, userID, other).Scan(&count); err != nil {
			t.Fatalf("%s: count owned TOTP steps: %v", phase, err)
		}
		if count != want {
			t.Fatalf("%s: owned TOTP steps = %d, want %d", phase, count, want)
		}
	}
	otherClaims := []struct {
		userID uuid.UUID
		step   int64
	}{{userID, step + 1}, {other, step}}

	// The sweep is global, but this test owns only these three rows. Other
	// fixtures' expired rows may legitimately contribute to its delete count.
	assertOwnedRows("before sweep", 3)
	if _, err := repo.DeleteExpiredBefore(ctx, now); err != nil {
		t.Fatalf("DeleteExpiredBefore(now): %v", err)
	}
	assertOwnedRows("before expiry", 3)
	if again, err := repo.Claim(ctx, userID, step, expires); err != nil || again {
		t.Fatalf("after an early sweep the used step was resurrected: (%v, %v)", again, err)
	}
	for _, claim := range otherClaims {
		if again, err := repo.Claim(ctx, claim.userID, claim.step, expires); err != nil || again {
			t.Fatalf("after an early sweep another owned step was resurrected: (%v, %v)", again, err)
		}
	}
	if _, err := repo.DeleteExpiredBefore(ctx, expires.Add(time.Second)); err != nil {
		t.Fatalf("DeleteExpiredBefore(past expiry): %v", err)
	}
	assertOwnedRows("after expiry", 0)
	if first, err := repo.Claim(ctx, userID, step, expires); err != nil || !first {
		t.Fatalf("after its expiry a step is claimable again (the code itself can no longer match): (%v, %v)", first, err)
	}
	for _, claim := range otherClaims {
		if first, err := repo.Claim(ctx, claim.userID, claim.step, expires); err != nil || !first {
			t.Fatalf("after expiry another owned step is not claimable again: (%v, %v)", first, err)
		}
	}
	assertOwnedRows("after reclaim", 3)
}
