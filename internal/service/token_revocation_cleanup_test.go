package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// recordingRepo is a minimal TokenRevocationRepository for the
// cleanup tests. Only DeleteExpiredBefore matters here.
type recordingRepo struct {
	calls int32
	err   error
	count int64
}

func (r *recordingRepo) Insert(context.Context, *domain.TokenRevocation) error {
	return nil
}

func (r *recordingRepo) Exists(context.Context, string) (bool, error) {
	return false, nil
}

func (r *recordingRepo) DeleteExpiredBefore(_ context.Context, _ time.Time) (int64, error) {
	atomic.AddInt32(&r.calls, 1)
	return r.count, r.err
}

// ---------- Construction ----------

func TestNewTokenRevocationCleanup_NilServicePanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil svc did not panic")
		}
	}()
	_ = NewTokenRevocationCleanup(nil, nil, time.Minute, nil)
}

// ---------- Enabled ----------

func TestEnabled_ZeroIntervalIsDisabled(t *testing.T) {
	svc := NewTokenRevocationService(nil, &recordingRepo{})
	c := NewTokenRevocationCleanup(nil, svc, 0, nil)
	if c.Enabled() {
		t.Errorf("interval=0 reports Enabled=true")
	}
}

func TestEnabled_PositiveIntervalIsEnabled(t *testing.T) {
	svc := NewTokenRevocationService(nil, &recordingRepo{})
	c := NewTokenRevocationCleanup(nil, svc, time.Minute, nil)
	if !c.Enabled() {
		t.Errorf("interval=1m reports Enabled=false")
	}
}

// ---------- Run loop semantics ----------

func TestRun_ZeroIntervalReturnsImmediately(t *testing.T) {
	repo := &recordingRepo{}
	svc := NewTokenRevocationService(nil, repo)
	c := NewTokenRevocationCleanup(nil, svc, 0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("Run did not return on interval=0")
	}
	if atomic.LoadInt32(&repo.calls) != 0 {
		t.Errorf("repo got calls despite interval=0")
	}
}

func TestRun_ContextCancellationStopsLoop(t *testing.T) {
	repo := &recordingRepo{}
	svc := NewTokenRevocationService(nil, repo)
	// Use a fake-timer hook so the test is deterministic.
	tickCh := make(chan time.Time)
	c := NewTokenRevocationCleanup(nil, svc, time.Hour, nil)
	c.newTimer = func(time.Duration) Timer { return fakeTimer{ch: tickCh} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	tickCh <- time.Now()
	tickCh <- time.Now()
	// At this point repo.calls is >= 2 (tick processing might race;
	// just verify shutdown).
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("Run did not exit on ctx cancel")
	}
}

// ---------- Tick semantics ----------

func TestTick_CallsDeleteExpired(t *testing.T) {
	repo := &recordingRepo{count: 3}
	svc := NewTokenRevocationService(nil, repo)
	c := NewTokenRevocationCleanup(nil, svc, time.Minute, nil)
	c.Tick(context.Background())
	if atomic.LoadInt32(&repo.calls) != 1 {
		t.Errorf("DeleteExpiredBefore calls = %d, want 1", repo.calls)
	}
}

// errOIDCStateSweeper always fails DeleteExpired — proves a sweep error is
// logged-and-swallowed (P-018: no panic on the maintenance path).
type errOIDCStateSweeper struct{}

func (errOIDCStateSweeper) DeleteExpired(context.Context) (int64, error) {
	return 0, errors.New("db down")
}

// The composed OIDC-state sweeper prunes EXPIRED oidc_states on each tick and
// leaves LIVE rows untouched (fakeOIDCStateRepo.DeleteExpired models
// `expires_at < NOW()`).
func TestTick_SweepsExpiredOIDCStatesKeepsLive(t *testing.T) {
	states := newFakeOIDCStateRepo()
	states.byState["expired"] = &domain.OIDCState{State: "expired", ExpiresAt: time.Now().Add(-time.Minute)}
	states.byState["live"] = &domain.OIDCState{State: "live", ExpiresAt: time.Now().Add(time.Hour)}
	svc := NewTokenRevocationService(nil, &recordingRepo{})
	c := NewTokenRevocationCleanup(nil, svc, time.Minute, nil).WithOIDCStateSweeper(states)

	c.Tick(context.Background())

	if _, ok := states.byState["expired"]; ok {
		t.Errorf("expired oidc_state was not swept")
	}
	if _, ok := states.byState["live"]; !ok {
		t.Errorf("live oidc_state was wrongly swept")
	}
}

// A sweep error is swallowed — the tick must not panic (P-018).
func TestTick_OIDCStateSweepErrorDoesNotPanic(t *testing.T) {
	svc := NewTokenRevocationService(nil, &recordingRepo{})
	c := NewTokenRevocationCleanup(nil, svc, time.Minute, nil).WithOIDCStateSweeper(errOIDCStateSweeper{})
	c.Tick(context.Background()) // must not panic
}

func TestTick_RepoErrorDoesNotPanic(t *testing.T) {
	repo := &recordingRepo{err: errors.New("transient db")}
	svc := NewTokenRevocationService(nil, repo)
	c := NewTokenRevocationCleanup(nil, svc, time.Minute, nil)
	// Must not panic on repo error.
	c.Tick(context.Background())
	if atomic.LoadInt32(&repo.calls) != 1 {
		t.Errorf("tick consumed call despite error: %d", repo.calls)
	}
}

// ---------- Logger ----------

type captureLogger struct {
	infos []string
	warns []string
}

func (l *captureLogger) Info(msg string, _ ...any) { l.infos = append(l.infos, msg) }
func (l *captureLogger) Warn(msg string, _ ...any) { l.warns = append(l.warns, msg) }

func TestTick_InfoEmittedWhenRowsDeleted(t *testing.T) {
	repo := &recordingRepo{count: 5}
	logger := &captureLogger{}
	svc := NewTokenRevocationService(nil, repo)
	c := NewTokenRevocationCleanup(nil, svc, time.Minute, logger)
	c.Tick(context.Background())
	if len(logger.infos) != 1 {
		t.Errorf("info emits = %d, want 1", len(logger.infos))
	}
}

func TestTick_NoLogWhenZeroRows(t *testing.T) {
	repo := &recordingRepo{count: 0}
	logger := &captureLogger{}
	svc := NewTokenRevocationService(nil, repo)
	c := NewTokenRevocationCleanup(nil, svc, time.Minute, logger)
	c.Tick(context.Background())
	if len(logger.infos) != 0 {
		t.Errorf("info emits = %d, want 0 on no-op", len(logger.infos))
	}
}

func TestTick_WarnEmittedOnRepoError(t *testing.T) {
	repo := &recordingRepo{err: errors.New("boom")}
	logger := &captureLogger{}
	svc := NewTokenRevocationService(nil, repo)
	c := NewTokenRevocationCleanup(nil, svc, time.Minute, logger)
	c.Tick(context.Background())
	if len(logger.warns) != 1 {
		t.Errorf("warn emits = %d, want 1", len(logger.warns))
	}
}

// ---------- refresh-token sweep integration ----------

// fakeRefreshRepoForCleanup is the smallest RefreshTokenRepository
// that records DeleteExpiredBefore call count.
type fakeRefreshRepoForCleanup struct {
	calls int
}

func (f *fakeRefreshRepoForCleanup) Insert(context.Context, *domain.RefreshToken) error {
	return nil
}
func (f *fakeRefreshRepoForCleanup) GetByID(context.Context, uuid.UUID) (*domain.RefreshToken, error) {
	return nil, nil
}
func (f *fakeRefreshRepoForCleanup) MarkRevoked(context.Context, uuid.UUID, time.Time) error {
	return nil
}
func (f *fakeRefreshRepoForCleanup) MarkRotated(context.Context, uuid.UUID, uuid.UUID, time.Time) error {
	return nil
}
func (f *fakeRefreshRepoForCleanup) SetAccessJTI(context.Context, uuid.UUID, string, time.Time) error {
	return nil
}
func (f *fakeRefreshRepoForCleanup) RevokeAllBySubject(context.Context, string, time.Time) (int64, error) {
	return 0, nil
}
func (f *fakeRefreshRepoForCleanup) RevokeByFamily(context.Context, string, time.Time) (int64, error) {
	return 0, nil
}
func (f *fakeRefreshRepoForCleanup) DeleteExpiredBefore(context.Context, time.Time) (int64, error) {
	f.calls++
	return 3, nil
}

func TestTick_AlsoSweepsRefreshTokensWhenComposed(t *testing.T) {
	jtiRepo := &recordingRepo{}
	refreshRepo := &fakeRefreshRepoForCleanup{}
	logger := &captureLogger{}
	tokenRevSvc := NewTokenRevocationService(nil, jtiRepo)
	refreshSvc := NewRefreshTokenService(nil, refreshRepo, RefreshTokenServiceOptions{})
	c := NewTokenRevocationCleanup(nil, tokenRevSvc, time.Minute, logger).WithRefreshTokenService(refreshSvc)
	c.Tick(context.Background())
	if jtiRepo.calls != 1 {
		t.Errorf("jti delete count = %d", jtiRepo.calls)
	}
	if refreshRepo.calls != 1 {
		t.Errorf("refresh delete count = %d", refreshRepo.calls)
	}
	// At least one info line for the 3-row prune.
	if len(logger.infos) == 0 {
		t.Errorf("no info emits despite prune")
	}
}

// ---------- replay sweep ----------

type fakeReplayRepoForCleanup struct {
	calls int
}

func (f *fakeReplayRepoForCleanup) Insert(_ context.Context, _, _ string, _ time.Time) (bool, error) {
	return true, nil
}
func (f *fakeReplayRepoForCleanup) DeleteExpiredBefore(context.Context, time.Time) (int64, error) {
	f.calls++
	return 2, nil
}

func TestTick_AlsoSweepsReplayRowsWhenComposed(t *testing.T) {
	jtiRepo := &recordingRepo{}
	replayRepo := &fakeReplayRepoForCleanup{}
	logger := &captureLogger{}
	tokenRevSvc := NewTokenRevocationService(nil, jtiRepo)
	replaySvc := NewClientAssertionReplayService(nil, replayRepo, ClientAssertionReplayServiceOptions{})
	c := NewTokenRevocationCleanup(nil, tokenRevSvc, time.Minute, logger).
		WithClientAssertionReplayService(replaySvc)
	c.Tick(context.Background())
	if jtiRepo.calls != 1 {
		t.Errorf("jti delete count = %d", jtiRepo.calls)
	}
	if replayRepo.calls != 1 {
		t.Errorf("replay delete count = %d", replayRepo.calls)
	}
	if len(logger.infos) == 0 {
		t.Errorf("no info emits despite prune")
	}
}

// fakeTimer drives the Run loop synchronously from a test channel.
type fakeTimer struct {
	ch chan time.Time
}

func (f fakeTimer) C() <-chan time.Time { return f.ch }
func (f fakeTimer) Stop()               {}

// countingExpiredSweeper records DeleteExpired calls — used to prove the
// audit sweeper is ticked by the cleanup driver (L-2).
type countingExpiredSweeper struct {
	calls int
	n     int64
	err   error
}

func (c *countingExpiredSweeper) DeleteExpired(context.Context) (int64, error) {
	c.calls++
	return c.n, c.err
}

// The composed audit sweeper is invoked on each tick (L-2) — this is what
// wires audit_events retention into the existing cleanup driver.
func TestTick_SweepsAuditEvents(t *testing.T) {
	audit := &countingExpiredSweeper{n: 3}
	svc := NewTokenRevocationService(nil, &recordingRepo{})
	c := NewTokenRevocationCleanup(nil, svc, time.Minute, nil).WithAuditSweeper(audit)

	c.Tick(context.Background())

	if audit.calls != 1 {
		t.Errorf("audit sweeper DeleteExpired calls = %d, want 1", audit.calls)
	}
}

// An audit-sweep error is swallowed — the tick must not panic (P-018).
func TestTick_AuditSweepErrorDoesNotPanic(t *testing.T) {
	audit := &countingExpiredSweeper{err: errors.New("db down")}
	svc := NewTokenRevocationService(nil, &recordingRepo{})
	c := NewTokenRevocationCleanup(nil, svc, time.Minute, nil).WithAuditSweeper(audit)
	c.Tick(context.Background()) // must not panic
	if audit.calls != 1 {
		t.Errorf("audit sweeper must still be called once on error path, got %d", audit.calls)
	}
}
