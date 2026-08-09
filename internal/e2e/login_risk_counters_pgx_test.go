//go:build integration

// login_risk_counters_pgx_test.go — P2-10: prove the two split counters at
// the SQL level. CountAccountFailuresSince keys on the (email AND ip) pair
// (kills V1); CountDistinctAccountsFromIPSince is COUNT(DISTINCT email_hash)
// per IP (kills V2). Rows persist in the shared DB, so all hashes carry a
// per-run suffix for isolation.
//
// Requires IDENTUUM_IDP_TEST_DATABASE_URL (see oss_e2e_test.go).

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestLoginRiskCounters_AccountAndDistinctIP(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx := context.Background()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()
	repo := postgres.NewPgxLoginAttemptRepository(pool)

	sfx := uuid.NewString()[:8]
	const purpose = "password"
	since := time.Now().Add(-time.Hour).UTC()

	victim := "victim-" + sfx
	attackerIP := "attacker-ip-" + sfx
	victimIP := "victim-ip-" + sfx

	seed := func(emailHash, ipHash string, success bool) {
		t.Helper()
		id, _ := uuid.NewV7()
		if err := repo.Insert(ctx, &domain.LoginAttempt{
			ID: id, EmailHash: emailHash, IPHash: ipHash, Purpose: purpose,
			Success: success, CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// --- V1 (account counter = email AND ip) ---
	for i := 0; i < 5; i++ {
		seed(victim, attackerIP, false) // attacker hammers the victim from ONE IP
	}
	// (victim, attackerIP): the attacker's own pair sees all 5.
	if n, err := repo.CountAccountFailuresSince(ctx, victim, attackerIP, purpose, since); err != nil || n != 5 {
		t.Fatalf("account (victim, attackerIP) = %d, err=%v; want 5", n, err)
	}
	// (victim, victimIP): the victim from their OWN IP sees ZERO — V1 dead.
	if n, err := repo.CountAccountFailuresSince(ctx, victim, victimIP, purpose, since); err != nil || n != 0 {
		t.Fatalf("account (victim, victimIP) = %d, err=%v; want 0 (V1: OR keyspace would return 5)", n, err)
	}

	// --- V2 (IP counter = COUNT(DISTINCT email_hash)) ---
	ipX := "ipx-" + sfx
	seed("u1-"+sfx, ipX, false)
	seed("u2-"+sfx, ipX, false)
	seed("u3-"+sfx, ipX, false)
	seed("u3-"+sfx, ipX, false) // a 4th RAW failure but a 3rd DISTINCT account
	if n, err := repo.CountDistinctAccountsFromIPSince(ctx, ipX, purpose, since); err != nil || n != 3 {
		t.Fatalf("distinct-accounts(ipX) = %d, err=%v; want 3 (V2: COUNT(*) would return 4)", n, err)
	}

	// Success rows and out-of-window rows must not be counted.
	seed("u4-"+sfx, ipX, true) // success → excluded
	old, _ := uuid.NewV7()
	if err := repo.Insert(ctx, &domain.LoginAttempt{
		ID: old, EmailHash: "u5-" + sfx, IPHash: ipX, Purpose: purpose, Success: false,
		CreatedAt: time.Now().Add(-2 * time.Hour).UTC(),
	}); err != nil {
		t.Fatalf("seed old: %v", err)
	}
	if n, err := repo.CountDistinctAccountsFromIPSince(ctx, ipX, purpose, since); err != nil || n != 3 {
		t.Fatalf("distinct-accounts(ipX) after success+old = %d, err=%v; want 3", n, err)
	}
}
