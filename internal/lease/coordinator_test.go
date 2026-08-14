package lease

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// --- test doubles ---

type fakeStore struct {
	mu            sync.Mutex
	calls         int
	tryFn         func(call int) (domain.InstanceLeaseOutcome, error)
	releaseCalls  int
	lastReleaseID string
	releaseErr    error
}

func (f *fakeStore) TryAcquire(_ context.Context, _ string, _ time.Duration) (domain.InstanceLeaseOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.tryFn(f.calls)
}

func (f *fakeStore) Release(_ context.Context, instanceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseCalls++
	f.lastReleaseID = instanceID
	return f.releaseErr
}

func (f *fakeStore) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeStore) releaseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.releaseCalls
}

type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (l *logCapture) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logCapture) joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func acquiredBy(id string) domain.InstanceLeaseOutcome {
	return domain.InstanceLeaseOutcome{Acquired: true, Holder: id, AcquiredAt: time.Now(), HeartbeatAt: time.Now()}
}

func heldByOther(id string) domain.InstanceLeaseOutcome {
	return domain.InstanceLeaseOutcome{Acquired: false, Holder: id, AcquiredAt: time.Now(), HeartbeatAt: time.Now()}
}

// fastCfg keeps the coordinator's timings tiny so tests never sleep for
// real seconds. Heartbeat is large by default so it does not fire unless
// a test opts into it.
func fastCfg(id string) Config {
	return Config{
		InstanceID:    id,
		TTL:           45 * time.Second,
		Heartbeat:     time.Hour,
		AcquireWindow: 60 * time.Millisecond,
		RetryInterval: 5 * time.Millisecond,
	}
}

// --- tests ---

// TestAcquire_FirstInstanceWins: the sole instance acquires on the first
// attempt, records no fatal, and holds the lease.
func TestAcquire_FirstInstanceWins(t *testing.T) {
	store := &fakeStore{tryFn: func(int) (domain.InstanceLeaseOutcome, error) {
		return acquiredBy("me"), nil
	}}
	report := lifecycle.NewStartupReport()
	log := &logCapture{}
	c := NewCoordinator(store, fastCfg("me"), report, log.logf)

	if !c.Acquire(context.Background()) {
		t.Fatal("sole instance must acquire the lease")
	}
	if !c.Holds() {
		t.Fatal("coordinator must report it holds the lease")
	}
	if report.HasFatal() {
		t.Fatal("acquiring instance must NOT record a fatal")
	}
	if store.callCount() != 1 {
		t.Fatalf("expected exactly 1 acquire attempt, got %d", store.callCount())
	}

	// Graceful release deletes the row under this instance's id.
	c.Release(context.Background())
	if store.releaseCount() != 1 || store.lastReleaseID != "me" {
		t.Fatalf("Release must delete under the holder id; releases=%d id=%q", store.releaseCount(), store.lastReleaseID)
	}
}

// TestAcquire_LoserRefusesToServe: a second instance facing a live
// incumbent exhausts the window, records a P-018 fatal (NOT-SERVING),
// and logs LOUDLY naming the incumbent. THIS is the boundary test.
// RULE: LEASE-1
func TestAcquire_LoserRefusesToServe(t *testing.T) {
	store := &fakeStore{tryFn: func(int) (domain.InstanceLeaseOutcome, error) {
		return heldByOther("incumbent-pod/abc"), nil
	}}
	report := lifecycle.NewStartupReport()
	log := &logCapture{}
	c := NewCoordinator(store, fastCfg("loser-pod/xyz"), report, log.logf)

	if c.Acquire(context.Background()) {
		t.Fatal("second instance must NOT acquire while a live incumbent holds the lease")
	}
	if c.Holds() {
		t.Fatal("loser must not report holding the lease")
	}
	if !report.HasFatal() {
		t.Fatal("loser must record a P-018 fatal so the process enters NOT-SERVING")
	}
	out := log.joined()
	if !strings.Contains(out, "NOT-SERVING") {
		t.Fatalf("loud ERROR must announce NOT-SERVING; got:\n%s", out)
	}
	if !strings.Contains(out, "incumbent-pod/abc") {
		t.Fatalf("loud ERROR must NAME the incumbent instance id; got:\n%s", out)
	}
	if !strings.Contains(out, "IDENTUUM_IDP_ALLOW_MULTI_REPLICA") {
		t.Fatalf("loud ERROR must point at the override env var; got:\n%s", out)
	}
	// The recorded fatal reason is secret-free and explains the boundary.
	faults := report.Faults()
	if len(faults) != 1 || faults[0].Component != "single-replica-lease" {
		t.Fatalf("expected one single-replica-lease fatal; got %+v", faults)
	}
	if store.callCount() < 2 {
		t.Fatalf("loser must RETRY within the window (a rollout must not be an instant outage); attempts=%d", store.callCount())
	}
}

// TestAcquire_RetriesThenTakesOverStaleLease models a rolling deploy: the
// incumbent's lease is live for the first attempts, then lapses (stale),
// and the incoming instance acquires within the window.
func TestAcquire_RetriesThenTakesOverStaleLease(t *testing.T) {
	store := &fakeStore{tryFn: func(call int) (domain.InstanceLeaseOutcome, error) {
		if call < 3 {
			return heldByOther("old-pod"), nil // predecessor still heartbeating
		}
		return acquiredBy("new-pod"), nil // predecessor's lease lapsed → we take over
	}}
	report := lifecycle.NewStartupReport()
	log := &logCapture{}
	c := NewCoordinator(store, fastCfg("new-pod"), report, log.logf)

	if !c.Acquire(context.Background()) {
		t.Fatal("incoming instance must acquire once the predecessor's lease goes stale")
	}
	if report.HasFatal() {
		t.Fatal("a successful (if delayed) acquire must not record a fatal")
	}
	if store.callCount() < 3 {
		t.Fatalf("expected retries before takeover; attempts=%d", store.callCount())
	}
}

// TestAcquire_TransientDBErrorIsRetried: a transient store error does not
// abort acquisition; the next attempt succeeds and a WARN is logged.
func TestAcquire_TransientDBErrorIsRetried(t *testing.T) {
	store := &fakeStore{tryFn: func(call int) (domain.InstanceLeaseOutcome, error) {
		if call == 1 {
			return domain.InstanceLeaseOutcome{}, errors.New("transient db error")
		}
		return acquiredBy("me"), nil
	}}
	report := lifecycle.NewStartupReport()
	log := &logCapture{}
	c := NewCoordinator(store, fastCfg("me"), report, log.logf)

	if !c.Acquire(context.Background()) {
		t.Fatal("acquire must survive a transient error and succeed on retry")
	}
	if report.HasFatal() {
		t.Fatal("no fatal expected when acquisition eventually succeeds")
	}
	if !strings.Contains(log.joined(), "transient error") {
		t.Fatalf("a transient error should produce a WARN; got:\n%s", log.joined())
	}
}

// TestAcquire_CancelledContextStopsRetrying: a shutdown mid-acquire stops
// the retry loop promptly instead of blocking the whole window.
func TestAcquire_CancelledContextStopsRetrying(t *testing.T) {
	store := &fakeStore{tryFn: func(int) (domain.InstanceLeaseOutcome, error) {
		return heldByOther("incumbent"), nil
	}}
	report := lifecycle.NewStartupReport()
	cfg := fastCfg("me")
	cfg.AcquireWindow = 10 * time.Second // large, so only cancellation ends it fast
	cfg.RetryInterval = 50 * time.Millisecond
	c := NewCoordinator(store, cfg, report, (&logCapture{}).logf)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	got := c.Acquire(ctx)
	if got {
		t.Fatal("acquire must not succeed against a live incumbent")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancellation must stop retrying promptly; took %s", elapsed)
	}
}

// TestHeartbeat_RenewsAndReleaseStops verifies the heartbeat loop renews
// the lease on its interval and that Release stops it and deletes the row.
func TestHeartbeat_RenewsAndReleaseStops(t *testing.T) {
	store := &fakeStore{tryFn: func(int) (domain.InstanceLeaseOutcome, error) {
		return acquiredBy("me"), nil
	}}
	report := lifecycle.NewStartupReport()
	cfg := fastCfg("me")
	cfg.Heartbeat = 10 * time.Millisecond
	c := NewCoordinator(store, cfg, report, (&logCapture{}).logf)

	if !c.Acquire(context.Background()) {
		t.Fatal("must acquire")
	}
	// Wait for several heartbeats to land.
	deadline := time.Now().Add(500 * time.Millisecond)
	for store.callCount() < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if store.callCount() < 4 {
		t.Fatalf("heartbeat must renew the lease repeatedly; total acquire calls=%d", store.callCount())
	}

	c.Release(context.Background())
	after := store.callCount()
	time.Sleep(50 * time.Millisecond)
	if store.callCount() != after {
		t.Fatalf("Release must stop the heartbeat loop; calls kept growing %d -> %d", after, store.callCount())
	}
	if store.releaseCount() != 1 {
		t.Fatalf("Release must delete the lease row exactly once; got %d", store.releaseCount())
	}
}

// TestHeartbeat_LostLeaseLogsLoudly: if the lease is usurped mid-serve,
// the heartbeat logs a loud ERROR (a second instance is running).
func TestHeartbeat_LostLeaseLogsLoudly(t *testing.T) {
	store := &fakeStore{tryFn: func(call int) (domain.InstanceLeaseOutcome, error) {
		if call == 1 {
			return acquiredBy("me"), nil // initial acquire
		}
		return heldByOther("usurper-pod"), nil // usurped on first heartbeat
	}}
	report := lifecycle.NewStartupReport()
	log := &logCapture{}
	cfg := fastCfg("me")
	cfg.Heartbeat = 10 * time.Millisecond
	c := NewCoordinator(store, cfg, report, log.logf)

	if !c.Acquire(context.Background()) {
		t.Fatal("must acquire initially")
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for !strings.Contains(log.joined(), "LOST while serving") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	c.Release(context.Background())

	out := log.joined()
	if !strings.Contains(out, "LOST while serving") {
		t.Fatalf("usurped lease must log a loud ERROR; got:\n%s", out)
	}
	if !strings.Contains(out, "usurper-pod") {
		t.Fatalf("lost-lease ERROR must name the new holder; got:\n%s", out)
	}
	if c.Holds() {
		t.Fatal("after losing the lease, Holds() must be false")
	}
}
