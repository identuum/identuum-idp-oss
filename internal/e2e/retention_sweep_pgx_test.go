//go:build integration

// retention_sweep_pgx_test.go — P2-12: the periodic cleanup driver must
// prune expired rows from password_resets, email_verifications,
// organization_claims, and mfa_pending_login_sessions (previously never
// swept). For each table: seed one EXPIRED and one LIVE row, run one
// cleanup Tick, and assert the expired row is GONE and the live row
// REMAINS. For mfa_pending the swept row carries the candidate encrypted
// TOTP seed + recovery-code hashes — its removal is the point.
//
// Requires IDENTUUM_IDP_TEST_DATABASE_URL (see oss_e2e_test.go).

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// countBy returns the number of rows matching the single-arg query.
func countBy(t *testing.T, pool *pgxpool.Pool, sql string, arg any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, arg).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", sql, err)
	}
	return n
}

func TestRetentionSweep_PrunesExpiredKeepsLive(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx := context.Background()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())

	// Seed one org + one user (the FK anchors). Child rows cascade on delete.
	suffix := uuid.NewString()[:8]
	orgID, _ := uuid.NewV7()
	org, err := repos.Organization.Create(ctx, &domain.Organization{
		ID: orgID, Name: "e2e-ret-" + suffix, Domain: "e2e-ret-" + suffix + ".example.invalid",
		OrgSlug: "e2e-ret-" + suffix, Active: true, MFAPolicy: "optional",
	})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() { _ = repos.Organization.Delete(context.Background(), org.ID) })

	uid, _ := uuid.NewV7()
	user, err := repos.User.Create(ctx, &domain.User{
		ID: uid, OrganizationID: org.ID, Email: "ret-" + uuid.NewString() + "@example.invalid",
		Role: domain.RoleOrgAdmin, PasswordHash: "init-not-printed", AuthSource: domain.AuthSourceLocal,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _ = repos.User.Delete(context.Background(), user.ID, user.OrganizationID) })

	// Times: expired is 1h in the past; live is 1h in the future — a margin
	// far larger than any host/DB clock skew (the sweep uses DB NOW()).
	now := time.Now()
	pastCreated := now.Add(-2 * time.Hour)
	pastExp := now.Add(-1 * time.Hour)
	liveExp := now.Add(1 * time.Hour)

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed exec %q: %v", sql, err)
		}
	}

	// Distinct keys per row.
	prExpired, prLive := "pr-exp-"+suffix, "pr-live-"+suffix
	evExpired, evLive := "ev-exp-"+suffix, "ev-live-"+suffix
	clExpiredID, _ := uuid.NewV7()
	clLiveID, _ := uuid.NewV7()
	mfaExpiredID, _ := uuid.NewV7()
	mfaLiveID, _ := uuid.NewV7()

	// password_resets.
	exec(`INSERT INTO password_resets (token_hash, user_id, expires_at, created_at) VALUES ($1,$2,$3,$4)`, prExpired, user.ID, pastExp, pastCreated)
	exec(`INSERT INTO password_resets (token_hash, user_id, expires_at, created_at) VALUES ($1,$2,$3,$4)`, prLive, user.ID, liveExp, now)
	// email_verifications.
	exec(`INSERT INTO email_verifications (token_hash, user_id, expires_at, created_at) VALUES ($1,$2,$3,$4)`, evExpired, user.ID, pastExp, pastCreated)
	exec(`INSERT INTO email_verifications (token_hash, user_id, expires_at, created_at) VALUES ($1,$2,$3,$4)`, evLive, user.ID, liveExp, now)
	// organization_claims (chk: expires_at > created_at).
	exec(`INSERT INTO organization_claims (id, organization_id, token_hash, expires_at, created_at, email_bound) VALUES ($1,$2,$3,$4,$5,false)`, clExpiredID, org.ID, "cl-exp-"+suffix, pastExp, pastCreated)
	exec(`INSERT INTO organization_claims (id, organization_id, token_hash, expires_at, created_at, email_bound) VALUES ($1,$2,$3,$4,$5,false)`, clLiveID, org.ID, "cl-live-"+suffix, liveExp, now)
	// mfa_pending_login_sessions — the swept row carries the sensitive
	// candidate seed + recovery-code hashes.
	exec(`INSERT INTO mfa_pending_login_sessions (id, user_id, kind, secret, recovery_codes, expires_at, created_at) VALUES ($1,$2,'enroll',$3,$4::jsonb,$5,$6)`,
		mfaExpiredID, user.ID, "candidate-encrypted-seed", `["recovery-hash-1","recovery-hash-2"]`, pastExp, pastCreated)
	exec(`INSERT INTO mfa_pending_login_sessions (id, user_id, kind, secret, recovery_codes, expires_at, created_at) VALUES ($1,$2,'enroll',$3,$4::jsonb,$5,$6)`,
		mfaLiveID, user.ID, "live-candidate-seed", `["live-hash"]`, liveExp, now)

	// Build the driver EXACTLY as runtime wires it, and Tick once.
	report := lifecycle.NewStartupReport()
	cleanup := service.NewTokenRevocationCleanup(report,
		service.NewTokenRevocationService(report, repos.TokenRevocation), time.Hour, service.NoopCleanupLogger{}).
		WithPasswordResetSweeper(repos.PasswordReset).
		WithEmailVerificationSweeper(repos.EmailVerification).
		WithClaimSweeper(repos.Claim).
		WithMFAPendingSweeper(repos.MFAPendingLoginSession)
	cleanup.Tick(ctx)

	// Per table: expired GONE, live REMAINS.
	checks := []struct {
		table      string
		sql        string
		expiredKey any
		liveKey    any
	}{
		{"password_resets", `SELECT count(*) FROM password_resets WHERE token_hash = $1`, prExpired, prLive},
		{"email_verifications", `SELECT count(*) FROM email_verifications WHERE token_hash = $1`, evExpired, evLive},
		{"organization_claims", `SELECT count(*) FROM organization_claims WHERE id = $1`, clExpiredID, clLiveID},
		{"mfa_pending_login_sessions", `SELECT count(*) FROM mfa_pending_login_sessions WHERE id = $1`, mfaExpiredID, mfaLiveID},
	}
	for _, c := range checks {
		if countBy(t, pool, c.sql, c.expiredKey) != 0 {
			t.Errorf("%s: EXPIRED row was NOT swept (still present) — retention leak", c.table)
		}
		if countBy(t, pool, c.sql, c.liveKey) != 1 {
			t.Errorf("%s: LIVE row was wrongly deleted — sweep removed an unexpired row", c.table)
		}
	}

	// mfa_pending: the sensitive fields of the expired row must be gone.
	if countBy(t, pool, `SELECT count(*) FROM mfa_pending_login_sessions WHERE id = $1 AND secret IS NOT NULL`, mfaExpiredID) != 0 {
		t.Error("mfa_pending_login_sessions: expired candidate encrypted seed + recovery hashes still retained after sweep")
	}
}
