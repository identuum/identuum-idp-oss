//go:build integration

// Integration boundary test for the password-reset expiry instant, standing on a
// deadline POSTGRES computes (THE-PROBE-AND-THE-SEAMLESS-CALLERS, 2026-08-04).
//
// WHY THIS ONE, AND WHY IN THIS REPO. The frozen-database-clock technique was
// proven on identuum-ag-ce. A technique proven in exactly one place is a
// technique proven for exactly one shape, so this applies it in a different
// repository, on a different schema, and on a statement that differs in three
// ways from the ag-ce one: the comparison is spelled NOW() rather than now(),
// the statement runs INSIDE A TRANSACTION the repository opens itself, and the
// same frozen clock is also WRITTEN (`SET used_at = NOW()`).
//
//	UPDATE password_resets SET used_at = NOW()
//	 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
//
// `NOW()` is an unquoted identifier, so Postgres folds it to `now()` and it
// resolves through search_path exactly like the lowercase form — this test is
// what establishes that rather than assuming it. The transaction inherits the
// session's search_path, so pinning the connection is enough.
//
// `expires_at > NOW()` is STRICT: a reset token AT its expiry instant is already
// unusable, and one MICROSECOND earlier it claims. Microsecond, not nanosecond —
// timestamptz truncates below that.
package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

var pwResetFrozenEpoch = time.Date(2031, 3, 1, 12, 0, 0, 0, time.UTC)

// freezePwResetClock pins one connection and shadows now() on it.
//
// The schema name carries the case label. A single shared name with CREATE OR
// REPLACE is a PER-DATABASE object: a second freeze rewrites the first case's
// clock, and because both cases refuse at the same strict boundary the wrong
// clock still produces the right answer. That defect shipped in the ag-ce
// version of this helper and is not repeated here.
func freezePwResetClock(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label string, at time.Time) *pgxpool.Conn {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire connection: %v", err)
	}
	schema := "frozenpwr_" + label
	t.Cleanup(func() {
		// Un-shadow BEFORE dropping, then release, so the connection returns to
		// the pool with a clean search_path instead of a dangling one.
		_, _ = conn.Exec(context.Background(), `RESET search_path`)
		_, _ = conn.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		conn.Release()
	})
	for _, s := range []string{
		`CREATE SCHEMA IF NOT EXISTS ` + schema,
		`CREATE OR REPLACE FUNCTION ` + schema + `.now() RETURNS timestamptz
		   LANGUAGE sql STABLE AS $fn$ SELECT TIMESTAMPTZ '` + at.UTC().Format("2006-01-02 15:04:05.999999-07") + `' $fn$`,
		`SET search_path TO ` + schema + `, public, pg_catalog`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("freeze db clock (%s): %v", s, err)
		}
	}
	assertPwResetFrozen(t, ctx, conn, at)
	return conn
}

// assertPwResetFrozen re-reads BOTH spellings on this connection. The uppercase
// one is the point: the statement under test writes NOW(), not now().
func assertPwResetFrozen(t *testing.T, ctx context.Context, conn *pgxpool.Conn, want time.Time) {
	t.Helper()
	var lower, upper time.Time
	if err := conn.QueryRow(ctx, `SELECT now(), NOW()`).Scan(&lower, &upper); err != nil {
		t.Fatalf("read frozen now(): %v", err)
	}
	if !lower.UTC().Equal(want.UTC()) || !upper.UTC().Equal(want.UTC()) {
		t.Fatalf("frozen now()=%v NOW()=%v, want %v — the shadow did not take for both spellings",
			lower.UTC(), upper.UTC(), want.UTC())
	}
}

// seedPwReset inserts a user and a reset token whose expires_at is a LITERAL.
func seedPwReset(t *testing.T, ctx context.Context, conn *pgxpool.Conn, expiresAt time.Time) string {
	t.Helper()
	userID := uuid.New()
	// Email and token_hash carry a fresh id: both are unique and this table is
	// not truncated between runs, so fixed values pass once and fail on re-run.
	email := "pwr-frozen-" + userID.String()[:8] + "@example.test"
	// chk_users_org_id_not_null is (role = 'site_admin' OR organization_id IS NOT
	// NULL). site_admin is not an option — idx_single_site_admin permits exactly
	// one in the database — so the user gets its own organization. Every id here
	// is fresh because organizations.domain and org_slug are unique and this
	// table is not truncated between runs.
	orgID := uuid.New()
	suffix := orgID.String()[:8]
	if _, err := conn.Exec(ctx, `
		INSERT INTO organizations (id, name, domain, org_slug, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5)`,
		orgID, "PwReset Frozen "+suffix, "pwr-"+suffix+".example.test", "pwr-"+suffix,
		pwResetFrozenEpoch.Add(-time.Hour)); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, organization_id, created_at, updated_at)
		VALUES ($1, $2, 'x', $3, $4, $4)`, userID, email, orgID, pwResetFrozenEpoch.Add(-time.Hour)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	hash := "pwr-hash-" + userID.String()
	if _, err := conn.Exec(ctx, `
		INSERT INTO password_resets (token_hash, user_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4)`, hash, userID, expiresAt, pwResetFrozenEpoch.Add(-time.Hour)); err != nil {
		t.Fatalf("seed password_reset: %v", err)
	}
	return hash
}

// TestIntegration_FrozenDBClock_PasswordResetAtExpiry stands on a deadline that
// exists only inside Postgres, in a second repository and a second SQL shape.
func TestIntegration_FrozenDBClock_PasswordResetAtExpiry(t *testing.T) {
	dbURL := setupStateTestDBURL(t)
	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("new pool (URL redacted): %v", err)
	}
	// t.Cleanup, NOT defer. Deferred calls in the test body run BEFORE cleanup
	// callbacks, so `defer pool.Close()` blocks forever waiting on connections
	// this test only releases in its own t.Cleanup. Registering the close first
	// makes LIFO ordering release the pinned connections before the pool shuts.
	t.Cleanup(pool.Close)

	// EXACTLY at expires_at the token is already unusable: `expires_at > NOW()`
	// is false when they are equal.
	connAt := freezePwResetClock(t, ctx, pool, "at", pwResetFrozenEpoch)
	hashAt := seedPwReset(t, ctx, connAt, pwResetFrozenEpoch)
	repoAt := postgres.NewPgxPasswordResetRepository(connAt)
	assertPwResetFrozen(t, ctx, connAt, pwResetFrozenEpoch)
	if _, ok, err := repoAt.ClaimPasswordReset(ctx, hashAt, "new-hash"); err != nil {
		t.Fatalf("at expires_at exactly: err = %v", err)
	} else if ok {
		t.Errorf("at expires_at exactly: the reset CLAIMED; `expires_at > NOW()` is STRICT and must refuse")
	}

	// One MICROSECOND earlier the same token claims.
	connBefore := freezePwResetClock(t, ctx, pool, "before", pwResetFrozenEpoch.Add(-time.Microsecond))
	hashBefore := seedPwReset(t, ctx, connBefore, pwResetFrozenEpoch)
	repoBefore := postgres.NewPgxPasswordResetRepository(connBefore)
	// Both freezes are live on separate schemas; re-verify each before use so a
	// rewritten clock cannot pass unnoticed.
	assertPwResetFrozen(t, ctx, connAt, pwResetFrozenEpoch)
	assertPwResetFrozen(t, ctx, connBefore, pwResetFrozenEpoch.Add(-time.Microsecond))
	if _, ok, err := repoBefore.ClaimPasswordReset(ctx, hashBefore, "new-hash"); err != nil {
		t.Fatalf("a microsecond before expires_at: err = %v", err)
	} else if !ok {
		t.Errorf("a microsecond before expires_at: the reset was refused, want claimed")
	}
}
