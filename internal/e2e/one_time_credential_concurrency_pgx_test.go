//go:build integration

// Package e2e — P0-9 / P0-10 / P0-11 regression: three one-time credentials
// (password-reset token, org-activation token, MFA recovery code) must be
// SINGLE-USE under REAL concurrency. Each fix is a single atomic conditional
// claim (UPDATE ... WHERE <still-unused> RETURNING / RowsAffected) whose result
// is the proof; a concurrent loser matches zero rows and is rejected. A
// SEQUENTIAL replay passes against the pre-fix read-then-mark code — only firing
// N simultaneous redemptions of the SAME credential exercises the atomic gate.
//
// Run:
//
//	go test -tags integration -v ./internal/e2e/...
//
// Safety: no raw token/code/hash or DB URL is echoed; each subtest hard-deletes
// its seed org (FK cascade reaps children).
package e2e

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// countWinners fires n attempts on a shared barrier and tallies how many
// reported success — the atomic single-use proof.
func countWinners(n int, attempt func() bool) (winners, losers int) {
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		mu    sync.Mutex
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok := attempt()
			mu.Lock()
			if ok {
				winners++
			} else {
				losers++
			}
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	return
}

func otcSeedOrg(t *testing.T, ctx context.Context, repos *postgres.Repositories, pool *pgxpool.Pool, active bool) uuid.UUID {
	t.Helper()
	suffix := uuid.NewString()
	org, err := repos.Organization.Create(ctx, &domain.Organization{
		Name:      "e2e-otc-" + suffix,
		Domain:    "e2e-otc-" + suffix + ".example.invalid",
		OrgSlug:   "e2e-otc-" + suffix[:8],
		Active:    active,
		MFAPolicy: "optional",
	})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", org.ID)
	})
	return org.ID
}

func otcSeedUser(t *testing.T, ctx context.Context, repos *postgres.Repositories, orgID uuid.UUID) *domain.User {
	t.Helper()
	uid, _ := uuid.NewV7()
	u, err := repos.User.Create(ctx, &domain.User{
		ID:             uid,
		OrganizationID: orgID,
		Email:          "otc-" + uuid.NewString() + "@example.invalid",
		PasswordHash:   "init-" + uuid.NewString() + "-not-printed",
		Role:           domain.RoleOrgAdmin,
		AuthSource:     domain.AuthSourceLocal,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

func TestE2E_OSS_OneTimeCredential_ConcurrentSingleUse(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())

	// ── P0-9: password-reset token ──────────────────────────────────────────
	t.Run("password_reset", func(t *testing.T) {
		orgID := otcSeedOrg(t, ctx, repos, pool, true)
		user := otcSeedUser(t, ctx, repos, orgID)
		tokenHash := "e2e-reset-" + uuid.NewString()
		if err := repos.PasswordReset.Create(ctx, &domain.PasswordReset{
			UserID: user.ID, TokenHash: tokenHash,
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed reset token: %v", err)
		}
		newHash, err := crypto.GenerateHash([]byte("Longenough-pw-1!"))
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		const n = 16
		winners, losers := countWinners(n, func() bool {
			_, ok, cErr := repos.PasswordReset.ClaimPasswordReset(ctx, tokenHash, newHash)
			return cErr == nil && ok
		})
		if winners != 1 {
			t.Fatalf("password reset: want exactly 1 winner, got winners=%d losers=%d of n=%d", winners, losers, n)
		}
	})

	// P0-9 rollback: a failed password write (user soft-deleted) must roll back
	// the claim so the reset link SURVIVES (used_at stays NULL).
	t.Run("password_reset_failed_write_rolls_back", func(t *testing.T) {
		orgID := otcSeedOrg(t, ctx, repos, pool, true)
		user := otcSeedUser(t, ctx, repos, orgID)
		tokenHash := "e2e-reset-rb-" + uuid.NewString()
		if err := repos.PasswordReset.Create(ctx, &domain.PasswordReset{
			UserID: user.ID, TokenHash: tokenHash,
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed reset token: %v", err)
		}
		if err := repos.User.Delete(ctx, user.ID, user.OrganizationID); err != nil {
			t.Fatalf("soft-delete user: %v", err)
		}
		newHash, _ := crypto.GenerateHash([]byte("Longenough-pw-1!"))
		if _, ok, _ := repos.PasswordReset.ClaimPasswordReset(ctx, tokenHash, newHash); ok {
			t.Fatalf("claim must fail when the user's password write affects zero rows")
		}
		row, err := repos.PasswordReset.GetByTokenHash(ctx, tokenHash)
		if err != nil || row == nil {
			t.Fatalf("token row must still exist: err=%v", err)
		}
		if row.UsedAt != nil {
			t.Fatalf("failed write must roll back the claim — the reset link must survive (used_at still NULL)")
		}
	})

	// ── P0-10: org-activation token ─────────────────────────────────────────
	t.Run("org_activation", func(t *testing.T) {
		orgID := otcSeedOrg(t, ctx, repos, pool, false) // inactive org awaiting activation
		user := otcSeedUser(t, ctx, repos, orgID)
		activationHash := crypto.HashToken("raw-activation-" + uuid.NewString())
		exp := time.Now().Add(time.Hour)
		if _, err := repos.User.Update(ctx, user.ID, user.OrganizationID, repository.UpdateUserOptions{
			ActivationTokenHash:      &activationHash,
			ActivationTokenExpiresAt: &exp,
		}); err != nil {
			t.Fatalf("seed activation token: %v", err)
		}
		newHash, _ := crypto.GenerateHash([]byte("Longenough-pw-1!"))
		pgxUsers := repos.User.(*postgres.PgxUserRepository)
		const n = 16
		winners, losers := countWinners(n, func() bool {
			_, ok, cErr := pgxUsers.ConsumeActivationToken(ctx, activationHash, newHash)
			return cErr == nil && ok
		})
		if winners != 1 {
			t.Fatalf("org activation: want exactly 1 winner, got winners=%d losers=%d of n=%d", winners, losers, n)
		}
	})

	// ── P0-11: MFA recovery code ────────────────────────────────────────────
	t.Run("mfa_recovery_code", func(t *testing.T) {
		orgID := otcSeedOrg(t, ctx, repos, pool, true)
		user := otcSeedUser(t, ctx, repos, orgID)
		codeHash := crypto.HashSecret("recovery-code-" + uuid.NewString())
		if _, err := repos.User.Update(ctx, user.ID, user.OrganizationID, repository.UpdateUserOptions{
			MFARecoveryCodes: []string{codeHash, crypto.HashSecret("other-" + uuid.NewString())},
		}); err != nil {
			t.Fatalf("seed recovery codes: %v", err)
		}
		const n = 16
		winners, losers := countWinners(n, func() bool {
			_, ok, cErr := repos.User.ConsumeRecoveryCode(ctx, user.ID, codeHash)
			return cErr == nil && ok
		})
		if winners != 1 {
			t.Fatalf("mfa recovery code: want exactly 1 winner, got winners=%d losers=%d of n=%d", winners, losers, n)
		}
	})
}
