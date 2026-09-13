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
	defer pool.Close()
	ctx := context.Background()
	repo := postgres.NewPgxTOTPUsedStepRepository(pool)

	orgID := seedScratchOrg(t, pool)
	userID := seedSessionUser(t, ctx, pool, orgID)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM totp_used_steps WHERE user_id = $1`, userID)
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
	other := uuid.New()
	if ok, err := repo.Claim(ctx, other, step, expires); err != nil || !ok {
		t.Fatalf("Claim(another user, same step) = (%v, %v), want (true, nil)", ok, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM totp_used_steps WHERE user_id = $1`, other)
	})

	// A sweep before the expiry keeps every row; one after it removes them.
	if n, err := repo.DeleteExpiredBefore(ctx, now); err != nil || n != 0 {
		t.Fatalf("DeleteExpiredBefore(now) = (%d, %v), want (0, nil): live rows were swept", n, err)
	}
	if again, err := repo.Claim(ctx, userID, step, expires); err != nil || again {
		t.Fatalf("after an early sweep the used step was resurrected: (%v, %v)", again, err)
	}
	if n, err := repo.DeleteExpiredBefore(ctx, expires.Add(time.Second)); err != nil || n != 3 {
		t.Fatalf("DeleteExpiredBefore(past expiry) = (%d, %v), want (3, nil)", n, err)
	}
	if first, err := repo.Claim(ctx, userID, step, expires); err != nil || !first {
		t.Fatalf("after its expiry a step is claimable again (the code itself can no longer match): (%v, %v)", first, err)
	}
}
