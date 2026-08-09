//go:build integration

// Package e2e — P0-13 integration coverage: the MFA verification path
// bounds wrong-guess attempts with a DURABLE, SHARED per-handle counter.
//
// Before P0-13, POST /api/v1/auth/login/mfa had no brute-force
// protection: a wrong TOTP/recovery code returned before the pending
// handle was consumed, so an attacker holding a valid verify handle
// could guess six-digit codes without limit for the handle's whole
// ~5-minute lifetime. The fix increments mfa_pending_login_sessions
// .failed_attempts atomically on each failed verify and invalidates the
// handle at the threshold — in Postgres, so the bound holds across
// replicas and restarts.
//
// This test proves the SHARED + DURABLE property that only a real DB can
// show: two SEPARATE service instances (each its own repository, both on
// one Postgres — the multi-replica shape) accumulate failures onto the
// SAME row. If the counter were process-local (an in-memory map), each
// instance's count would be independent and the handle would survive; it
// does not — the guess made through instance B, on top of two through
// instance A, is what tips the shared counter to the threshold and kills
// the handle. A direct SQL read confirms failed_attempts + consumed_at
// are persisted.
//
// Test discipline: randomized email; the seeded TOTP secret + codes are
// never echoed in any assertion message; user + org soft-deleted on
// cleanup.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestE2E_OSS_MFAVerify_BruteForceBoundIsSharedAndDurable(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.User == nil || repos.MFAPendingLoginSession == nil {
		t.Fatal("repository factory returned nil required repo")
	}

	// Seed an org + an already-MFA-enrolled user (verify-kind targets).
	org := seedTestOrganization(t, ctx, repos)
	email := strings.ToLower("e2e-mfa-bf-" + uuid.NewString() + "@example.invalid")
	// A standard RFC 6238 test secret (valid base32, 80 bits). Not printed.
	const totpSecret = "JBSWY3DPEHPK3PXP"
	enabled := true
	seededID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed uuid: %v", err)
	}
	created, err := repos.User.Create(ctx, &domain.User{
		ID:             seededID,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   "bf-" + uuid.NewString() + "-marker-not-printed",
		Role:           domain.RoleOrgAdmin,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
		MFAEnabled:     enabled,
		MFASecret:      strPtr(totpSecret),
	})
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), created.ID, created.OrganizationID)
	})

	// TWO independent service instances, each with its OWN pending
	// repository, both backed by the same pool — the multi-replica shape.
	// maxVerifyAttempts=3 keeps the boundary crisp.
	const maxAttempts = 3
	newSvc := func() *service.MFAEnrollmentService {
		return service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{
			Pending: postgres.NewPgxMFAPendingLoginSessionRepository(pool),
			Users:   repos.User,
			Issuer:  "Identuum",
			Cipher:  e2eMFAIdentityCipher{},
		}, service.MFAEnrollmentServiceOptions{MaxVerifyAttempts: maxAttempts})
	}
	svcA := newSvc()
	svcB := newSvc()

	// One verify-kind pending handle, created via svcA (lands in shared DB).
	row, err := svcA.CreatePending(ctx, created, domain.MFAPendingKindVerify, false)
	if err != nil {
		t.Fatalf("CreatePending verify: %v", err)
	}
	t.Cleanup(func() {
		_, _ = repos.MFAPendingLoginSession.MarkConsumed(context.Background(), row.ID, time.Now())
	})

	// The guess must be rejected across the WHOLE accepted window, not just the
	// centre step. The verifier scans delta := -Window .. +Window and the default
	// window is 1, so THREE codes are valid at any instant. This guard compared
	// ONE step, which left the other two able to be "wrong".
	wrong := wrongCodeForWindowE2E(t, totpSecret, time.Now())
	correct := computeTOTPCodeForTest(t, totpSecret, uint64(time.Now().Unix())/uint64(service.TOTPPeriodSeconds))

	// Two wrong guesses through instance A.
	for i := 1; i <= 2; i++ {
		if _, err := svcA.VerifyAndConsume(ctx, row.ID, wrong); !errors.Is(err, service.ErrMFAEnrollmentInvalid) {
			t.Fatalf("svcA attempt %d: want ErrMFAEnrollmentInvalid, got %v", i, err)
		}
	}
	// Counter is shared/durable: read it straight from the row.
	failed, consumed := readPendingCounter(t, ctx, pool, row.ID)
	if failed != 2 || consumed {
		t.Fatalf("after 2 failures via svcA: want failed_attempts=2 consumed=false, got failed=%d consumed=%v", failed, consumed)
	}

	// The THIRD wrong guess goes through instance B. If the counter were
	// process-local this would be B's first failure (count 1 < 3) and the
	// handle would survive. Because the counter lives in the shared row, this
	// tips it to the threshold and kills the handle.
	if _, err := svcB.VerifyAndConsume(ctx, row.ID, wrong); !errors.Is(err, service.ErrMFAEnrollmentInvalid) {
		t.Fatalf("svcB threshold attempt: want ErrMFAEnrollmentInvalid, got %v", err)
	}
	failed, consumed = readPendingCounter(t, ctx, pool, row.ID)
	if failed != 3 || !consumed {
		t.Fatalf("after the cross-instance 3rd failure: want failed_attempts=3 consumed=true, got failed=%d consumed=%v", failed, consumed)
	}

	// The handle is dead: even the CORRECT code now fails (re-auth forced),
	// via either instance.
	if _, err := svcB.VerifyAndConsume(ctx, row.ID, correct); !errors.Is(err, service.ErrMFAEnrollmentAlreadyConsumed) {
		t.Fatalf("correct code after lockout (svcB): want ErrMFAEnrollmentAlreadyConsumed, got %v", err)
	}
	if _, err := svcA.VerifyAndConsume(ctx, row.ID, correct); !errors.Is(err, service.ErrMFAEnrollmentAlreadyConsumed) {
		t.Fatalf("correct code after lockout (svcA): want ErrMFAEnrollmentAlreadyConsumed, got %v", err)
	}
}

// readPendingCounter reads failed_attempts + whether consumed_at is set
// directly from the row — the durable, shared source of truth.
func readPendingCounter(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) (failed int, consumed bool) {
	t.Helper()
	if err := pool.QueryRow(ctx,
		`SELECT failed_attempts, consumed_at IS NOT NULL FROM mfa_pending_login_sessions WHERE id = $1`,
		id,
	).Scan(&failed, &consumed); err != nil {
		t.Fatalf("read pending counter: %v", err)
	}
	return failed, consumed
}

func strPtr(s string) *string { return &s }

// wrongCodeForWindowE2E returns a six-digit code the verifier will NOT accept
// for secret at now, excluding EVERY step in the accepted window.
//
// The window comes from service.TOTPWindowSteps and the period from
// service.TOTPPeriodSeconds — the verifier's own constants, exported for exactly
// this. There is no mirrored number left to forget.
func wrongCodeForWindowE2E(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	// The window and period come from the SERVICE's own exported constants, not
	// from numbers retyped here. Widening the verifier now widens this guard.
	stepNow := now.Unix() / int64(service.TOTPPeriodSeconds)
	valid := make(map[string]bool, 2*service.TOTPWindowSteps+1)
	for delta := int64(-service.TOTPWindowSteps); delta <= service.TOTPWindowSteps; delta++ {
		valid[computeTOTPCodeForTest(t, secret, uint64(stepNow+delta))] = true
	}
	for i := 0; i < 1000; i++ {
		candidate := fmt.Sprintf("%06d", i)
		if !valid[candidate] {
			return candidate
		}
	}
	t.Fatalf("no rejectable code in 1000 candidates")
	return ""
}
