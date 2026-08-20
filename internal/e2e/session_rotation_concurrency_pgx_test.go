//go:build integration

// Package e2e — P0-12 integration coverage for browser-session
// refresh-token rotation against the live pgx repository.
//
// Two defects were fixed and are proven here end-to-end:
//
//   - P0-12a ROTATION RACE: rotation validated the current validator,
//     generated a successor, and then did an UNCONDITIONAL update.
//     Two concurrent refreshes both validated the same token and both
//     wrote, last-write-wins; the loser held a validator the DB no
//     longer knew, so its next use tripped reuse detection and revoked
//     the whole family — a benign double-click logged the user out
//     everywhere. The fix routes rotation through a COMPARE-AND-SET
//     (repo.RotateToken) guarded on the exact validator hash we read:
//     exactly one concurrent sibling wins, the losers match ZERO rows
//     and are rejected with invalid_grant WITHOUT family revocation.
//
//   - P0-12b EXPIRY NEVER PERSISTED: the service extended
//     session.ExpiresAt in memory but the UPDATE omitted expires_at,
//     so an actively-used session still idled out at its original
//     deadline. The CAS now writes expires_at in the SAME statement.
//
// CAS-loser policy proven here: a CAS loss is BENIGN concurrency
// (invalid_grant, NO family revocation); a genuine replay of a
// consumed predecessor still fails the READ-TIME validator compare and
// IS treated as theft (ErrUserSessionReuse + family revocation).
//
// Test discipline: randomized email + per-run UUID isolation; raw
// refresh tokens are NEVER printed in any assertion message;
// t.Cleanup soft-deletes the seeded user + org.
//
// Run:
//
//	go test -tags integration -run SessionRotation -v ./internal/e2e/...
package e2e

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// rotationTestFixture seeds an active org + active user and returns a
// UserSessionService wired to the live pgx SessionRepository plus a
// freshly-minted session (its raw refresh token). Everything is
// cleaned up via t.Cleanup.
type rotationTestFixture struct {
	svc     *service.UserSessionService
	repos   *postgres.Repositories
	pool    *pgxpool.Pool // for direct DB-state manipulation in tests (e.g. aging prev_rotated_at)
	userID  uuid.UUID
	orgID   uuid.UUID
	session *domain.Session
	token0  string // raw refresh token for the freshly-minted session
	exp0    time.Time
}

func newRotationTestFixture(t *testing.T, ctx context.Context) *rotationTestFixture {
	t.Helper()

	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.Session == nil {
		t.Fatal("repository factory returned nil Session repo")
	}

	org := seedTestOrganization(t, ctx, repos)
	email := strings.ToLower("e2e-rot-" + uuid.NewString() + "@example.invalid")
	userID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed: uuid: %v", err)
	}
	createdUser, err := repos.User.Create(ctx, &domain.User{
		ID:             userID,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   "not-a-real-hash-" + uuid.NewString(),
		Role:           domain.RoleOrgUser,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), createdUser.ID, createdUser.OrganizationID)
	})

	// Default options: 12h TTL, 30d absolute lifetime — a session
	// created now and rotated seconds later stays well inside both.
	svc := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})

	issued, err := svc.CreateUserSession(ctx, service.CreateUserSessionInput{
		UserID: createdUser.ID,
	})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	if issued == nil || issued.Session == nil || strings.TrimSpace(issued.RefreshToken) == "" {
		t.Fatal("CreateUserSession returned an empty issued session")
	}

	// Read the persisted expires_at back so the P0-12b assertion is a
	// clean DB-value-vs-DB-value comparison (avoids Go-vs-pg precision
	// noise).
	persisted, err := repos.Session.GetByID(ctx, issued.Session.ID)
	if err != nil {
		t.Fatalf("GetByID after create: %v", err)
	}

	return &rotationTestFixture{
		svc:     svc,
		repos:   repos,
		pool:    pool,
		userID:  createdUser.ID,
		orgID:   createdUser.OrganizationID,
		session: issued.Session,
		token0:  issued.RefreshToken,
		exp0:    persisted.ExpiresAt.UTC(),
	}
}

// TestE2E_OSS_SessionRotation_ConcurrentStorm fires N simultaneous
// rotations of the SAME session with the SAME (current) refresh token.
// P0-12a: exactly one goroutine actually performs the database CAS —
// every other racer either loses that CAS outright (its own read still
// saw the pre-rotation hash; rejected with ErrUserSessionInvalidGrant)
// or reads AFTER the winner already committed and is accepted as a
// benign racer within the grace window (P0-12b — see
// sessionRotationGraceWindow). NONE of the n racers may trip family
// revocation: reuse must be exactly zero. The winner (and any benign
// racer) succeeds; the session stays valid and the user stays logged
// in. P0-12b (original): the winner's expires_at is persisted and has
// moved forward.
func TestE2E_OSS_SessionRotation_ConcurrentStorm(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fx := newRotationTestFixture(t, ctx)

	const n = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
		invalid int
		reuse   int
		other   int
	)
	release := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release // barrier: all goroutines fire together
			res, err := fx.svc.RotateRefreshToken(ctx, fx.token0)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && res != nil:
				winners++
			case errors.Is(err, service.ErrUserSessionReuse):
				reuse++
			case errors.Is(err, service.ErrUserSessionInvalidGrant):
				invalid++
			default:
				other++
			}
		}()
	}

	// Sleep before releasing so every rotation computes its new
	// expires_at from a wall clock strictly later than create time —
	// gives the P0-12b assertion real separation (~1.5s) instead of a
	// sub-millisecond delta that a reverted fix could still satisfy.
	time.Sleep(1500 * time.Millisecond)
	close(release)
	wg.Wait()

	// The core invariant this test exists to prove (P0-12b): NO racer is
	// EVER misclassified as theft, regardless of read/commit timing.
	if reuse != 0 {
		t.Errorf("CAS losers must NOT trigger reuse/family-revocation; got reuse=%d", reuse)
	}
	if other != 0 {
		t.Errorf("unexpected non-invalid_grant/non-success loser errors: other=%d", other)
	}
	// At least the true CAS winner must succeed; a benign racer (read
	// after the winner committed, within grace) ALSO succeeds without
	// rotating again, so winners can be >1 depending on scheduling —
	// unlike pre-P0-12b, this is not a bug, it's the fix. Every racer
	// that isn't a winner must be a legitimate CAS-loser (its own read
	// preceded the winner's commit, so it fairly lost the compare-and-set).
	if winners < 1 {
		t.Errorf("expected at least 1 successful rotation (the CAS winner), got %d (invalid=%d reuse=%d other=%d)",
			winners, invalid, reuse, other)
	}
	if winners+invalid != n {
		t.Errorf("every racer must be either a success or a CAS-loser; winners=%d invalid=%d reuse=%d other=%d (want sum=%d)",
			winners, invalid, reuse, other, n)
	}

	// User stays logged in: the session is NOT revoked and still lists
	// as active. (A single stray reuse would have revoked the family.)
	after, err := fx.repos.Session.GetByID(ctx, fx.session.ID)
	if err != nil {
		t.Fatalf("GetByID after storm: %v", err)
	}
	if !after.IsValid || after.RevokedAt != nil {
		t.Errorf("session must remain valid after benign concurrent rotation; is_valid=%v revoked_at=%v",
			after.IsValid, after.RevokedAt != nil)
	}
	active, err := fx.repos.Session.ListActiveByUserID(ctx, fx.userID)
	if err != nil {
		t.Fatalf("ListActiveByUserID after storm: %v", err)
	}
	found := false
	for _, s := range active {
		if s.ID == fx.session.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("rotated session must still appear in ListActiveByUserID (user stays logged in)")
	}

	// P0-12b: expires_at was persisted by the CAS and moved forward.
	if !after.ExpiresAt.UTC().After(fx.exp0) {
		t.Errorf("expires_at must advance on rotation (P0-12b); before=%s after=%s",
			fx.exp0.Format(time.RFC3339Nano), after.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}
	if delta := after.ExpiresAt.UTC().Sub(fx.exp0); delta < time.Second {
		t.Errorf("expires_at advance too small to be a real persist (P0-12b teeth); delta=%s", delta)
	}
}

// TestE2E_OSS_SessionRotation_ReplayIsTheft proves the other side of
// the CAS-loser policy: a genuine replay of a CONSUMED predecessor
// OLD ENOUGH that P0-12b's grace window has elapsed (not a concurrent
// double-click, not an immediate benign racer) fails the read-time
// validator compare and IS treated as theft — ErrUserSessionReuse
// plus family revocation. This is what the benign-loser AND the
// benign-racer-grace-window policies must NOT weaken: the security
// property is that a stale validator presented after grace still
// revokes the family, exactly as before P0-12b.
// RULE: SESSION-REPLAY-THEFT-1
func TestE2E_OSS_SessionRotation_ReplayIsTheft(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fx := newRotationTestFixture(t, ctx)

	// P2-21: rotate IMMEDIATELY after creation — no sleep. created_at and the
	// rotation's last_used_at now BOTH come from the DB clock (now() in SQL), so
	// last_used_at = now() >= created_at holds by construction and
	// chk_last_used_after_created cannot trip on container/host skew. The prior
	// ~1.5s sleep here was a workaround for exactly that skew and is removed;
	// this immediate rotation IS the skew regression test.
	issued1, err := fx.svc.RotateRefreshToken(ctx, fx.token0)
	if err != nil {
		t.Fatalf("first rotation must succeed: %v", err)
	}
	if issued1 == nil || strings.TrimSpace(issued1.RefreshToken) == "" {
		t.Fatal("first rotation returned empty token")
	}

	// P0-12b / TIMING-MARGIN-1: age the predecessor OUT of the grace window
	// before replaying — anchored to a SINGLE clock, with NO wall-clock sleep.
	// The service classifies a predecessor replay as benign-vs-reuse by
	// s.now() MINUS session.prev_rotated_at, where s.now() is the backend/host
	// clock (time.Now, in-process here). But RotateToken stamps prev_rotated_at
	// from the DB clock (now()). The original time.Sleep(11s) therefore
	// straddled two clocks: a few seconds of host-vs-VM drift could leave
	// s.now()-prev_rotated_at below the 10s sessionRotationGraceWindow and
	// misclassify this replay as a benign racer — the test would fail on clock
	// skew alone, not on any product regression (that is exactly the
	// TIMING-MARGIN-1 flake). Backdating prev_rotated_at with a BACKEND-clock
	// timestamp well past grace makes the subtraction host-minus-host: no VM
	// offset can change the verdict, and the real-time wait is gone. Only
	// prev_rotated_at moves; prev_validator_hash stays set, so
	// chk_sessions_prev_validator_paired holds. The grace window is 10s; -30s
	// is a generous margin whose size is irrelevant to drift-immunity because
	// both operands now come from the same clock. This immediate,
	// single-clock aging IS the skew regression test.
	agedPrevRotatedAt := time.Now().UTC().Add(-30 * time.Second)
	if _, err := fx.pool.Exec(ctx,
		`UPDATE sessions SET prev_rotated_at = $1 WHERE id = $2`,
		agedPrevRotatedAt, fx.session.ID); err != nil {
		t.Fatalf("age prev_rotated_at past the grace window: %v", err)
	}

	// Replay the consumed predecessor (token0), now well past grace. Same
	// stable selector, stale validator, too old to be a benign racer →
	// refresh-token reuse.
	_, err = fx.svc.RotateRefreshToken(ctx, fx.token0)
	if !errors.Is(err, service.ErrUserSessionReuse) {
		t.Fatalf("replay of a consumed token past the grace window must be treated as reuse; got %v", err)
	}

	// Family revocation: no active sessions remain for the user.
	active, err := fx.repos.Session.ListActiveByUserID(ctx, fx.userID)
	if err != nil {
		t.Fatalf("ListActiveByUserID after reuse: %v", err)
	}
	if len(active) != 0 {
		t.Errorf("reuse must revoke the whole session family; still active=%d", len(active))
	}

	// The session row itself must be revoked (defense-in-depth read).
	after, err := fx.repos.Session.GetByID(ctx, fx.session.ID)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return // acceptable: revoked rows filtered from GetByID
		}
		t.Fatalf("GetByID after reuse: %v", err)
	}
	if after.IsValid && after.RevokedAt == nil {
		t.Error("session must be revoked after refresh-token reuse")
	}
}

// TestE2E_OSS_SessionRotation_ReplayWithinGraceIsBenign proves the
// deliberate P0-12b tradeoff on its accepting side: presenting the
// immediately-preceding (just-superseded) validator WITHIN the grace
// window is accepted as a benign racer — no error, no rotation, no
// family revocation — mirroring what a losing goroutine in
// TestE2E_OSS_SessionRotation_ConcurrentStorm experiences, but
// reproduced deterministically via sequential calls instead of relying
// on real concurrency timing.
func TestE2E_OSS_SessionRotation_ReplayWithinGraceIsBenign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fx := newRotationTestFixture(t, ctx)

	issued1, err := fx.svc.RotateRefreshToken(ctx, fx.token0)
	if err != nil {
		t.Fatalf("first rotation must succeed: %v", err)
	}
	if issued1 == nil || strings.TrimSpace(issued1.RefreshToken) == "" {
		t.Fatal("first rotation returned empty token")
	}

	// Immediately (well within the 10s grace window) present the
	// just-superseded predecessor (token0) again — the same shape as a
	// losing concurrent racer's read, reproduced sequentially and
	// deterministically instead of via goroutine timing.
	issued2, err := fx.svc.RotateRefreshToken(ctx, fx.token0)
	if err != nil {
		t.Fatalf("replay within the grace window must be accepted as a benign racer, not rejected: %v", err)
	}
	if issued2 == nil || strings.TrimSpace(issued2.RefreshToken) == "" {
		t.Fatal("benign-racer acceptance must still return a usable refresh token")
	}

	// No revocation: the family must remain fully intact.
	active, err := fx.repos.Session.ListActiveByUserID(ctx, fx.userID)
	if err != nil {
		t.Fatalf("ListActiveByUserID after benign racer: %v", err)
	}
	found := false
	for _, s := range active {
		if s.ID == fx.session.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("benign racer within grace must NOT revoke the family; session missing from ListActiveByUserID")
	}

	after, err := fx.repos.Session.GetByID(ctx, fx.session.ID)
	if err != nil {
		t.Fatalf("GetByID after benign racer: %v", err)
	}
	if !after.IsValid || after.RevokedAt != nil {
		t.Errorf("benign racer within grace must NOT revoke the session; is_valid=%v revoked_at=%v",
			after.IsValid, after.RevokedAt != nil)
	}
}
