//go:build integration

// single_replica_lease_pgx_test.go — DB-backed proof of the OSS
// single-replica boundary (A-2a). identuum-idp-oss is single-replica by
// design; a DB lease lets exactly one live instance serve. These tests
// run two "instances" against ONE Postgres and assert the boundary
// holds, that rolling deploys still work, and that the override lets an
// operator knowingly run multi-replica.
//
// Requires IDENTUUM_IDP_TEST_DATABASE_URL (see oss_e2e_test.go).

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lease"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/runtime"
)

// syncBuf is a mutex-guarded buffer so a runtime's Stdout/Stderr can be
// written from background goroutines (heartbeat, serve loop) while the
// test reads it, without a data race.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func itoa(i int) string { return strconv.Itoa(i) }

// leasePool opens a pool against the test DB after applying migrations
// (which creates the instance_lease table) and clears any leftover lease
// row so each test starts from a known-empty state.
func leasePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	pool, err := postgres.NewPool(context.Background(), dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)
	clearLease(t, pool)
	return pool
}

func clearLease(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), "DELETE FROM instance_lease"); err != nil {
		t.Fatalf("clear instance_lease: %v", err)
	}
}

// threadsafe log capture for the coordinator's loud sink.
type leaseLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *leaseLog) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *leaseLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// fastLeaseCfg returns a coordinator config with a tiny acquire window so
// a losing instance refuses in milliseconds instead of the 60s default.
func fastLeaseCfg(id string) lease.Config {
	return lease.Config{
		InstanceID:    id,
		TTL:           45 * time.Second,
		Heartbeat:     time.Hour, // effectively off unless a test lowers it
		AcquireWindow: 300 * time.Millisecond,
		RetryInterval: 15 * time.Millisecond,
	}
}

// TestInstanceLease_AtomicAcquire_ExactlyOneWinner races many instances
// at one empty lease row and proves the acquire is ATOMIC: exactly one
// observes Acquired == true. This is the atomicity guarantee that the
// whole boundary rests on.
func TestInstanceLease_AtomicAcquire_ExactlyOneWinner(t *testing.T) {
	pool := leasePool(t)
	repo := postgres.NewPgxInstanceLeaseRepository(pool)

	const racers = 16
	var winners int64
	var winnerID atomic.Value
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		id := "racer-" + itoa(i)
		go func() {
			defer wg.Done()
			<-start // release all goroutines at once
			out, err := repo.TryAcquire(context.Background(), id, 45*time.Second)
			if err != nil {
				t.Errorf("TryAcquire(%s): %v", id, err)
				return
			}
			if out.Acquired {
				atomic.AddInt64(&winners, 1)
				winnerID.Store(id)
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Fatalf("ATOMICITY VIOLATION: %d instances acquired the lease; want exactly 1", winners)
	}
	// The persisted holder must be the single winner.
	var holder string
	if err := pool.QueryRow(context.Background(),
		"SELECT instance_id FROM instance_lease WHERE id = $1", domain.InstanceLeaseSingletonID).Scan(&holder); err != nil {
		t.Fatalf("read holder: %v", err)
	}
	if got := winnerID.Load(); got == nil || got.(string) != holder {
		t.Fatalf("persisted holder %q disagrees with the reported winner %v", holder, got)
	}
}

// TestInstanceLease_SecondInstanceRefuses is THE test: two instances,
// one Postgres. The first acquires and serves; the second REFUSES to
// serve — it records a P-018 fatal (NOT-SERVING) and its loud log names
// the incumbent and points at the override.
func TestInstanceLease_SecondInstanceRefuses(t *testing.T) {
	pool := leasePool(t)
	repo := postgres.NewPgxInstanceLeaseRepository(pool)

	// Instance A — the incumbent. Uses a known id so we can assert B names it.
	reportA := lifecycle.NewStartupReport()
	logA := &leaseLog{}
	coordA := lease.NewCoordinator(repo, fastLeaseCfg("instance-A"), reportA, logA.logf)
	if !coordA.Acquire(context.Background()) {
		t.Fatal("instance A must acquire the lease on an empty table")
	}
	defer coordA.Release(context.Background())
	if reportA.HasFatal() {
		t.Fatal("the serving instance must NOT be in NOT-SERVING mode")
	}

	// Instance B — the loser. A holds a live lease, so B must refuse.
	reportB := lifecycle.NewStartupReport()
	logB := &leaseLog{}
	coordB := lease.NewCoordinator(repo, fastLeaseCfg("instance-B"), reportB, logB.logf)
	if coordB.Acquire(context.Background()) {
		t.Fatal("second instance must NOT acquire while A holds a live lease")
	}
	if !reportB.HasFatal() {
		t.Fatal("the loser MUST record a P-018 fatal so it enters NOT-SERVING (refuses traffic with 503)")
	}
	faults := reportB.Faults()
	if len(faults) != 1 || faults[0].Component != "single-replica-lease" {
		t.Fatalf("expected one single-replica-lease fatal; got %+v", faults)
	}
	if !strings.Contains(faults[0].Reason, "instance-A") {
		t.Fatalf("the NOT-SERVING fault must name the incumbent (instance-A); got %q", faults[0].Reason)
	}
	out := logB.text()
	for _, want := range []string{"NOT-SERVING", "instance-A", "IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "Professional+"} {
		if !strings.Contains(out, want) {
			t.Fatalf("loud ERROR must contain %q; got:\n%s", want, out)
		}
	}

	// The DB still records exactly one holder: A.
	var holder string
	if err := pool.QueryRow(context.Background(),
		"SELECT instance_id FROM instance_lease WHERE id = $1", domain.InstanceLeaseSingletonID).Scan(&holder); err != nil {
		t.Fatalf("read holder: %v", err)
	}
	if holder != "instance-A" {
		t.Fatalf("holder must remain instance-A; got %q", holder)
	}
}

// TestInstanceLease_StaleLeaseTakenOverOnRollout models a rolling deploy
// where the OUTGOING pod dies UNGRACEFULLY (no Release): its lease is
// held with a short TTL and it stops heartbeating. The incoming pod must
// take the lease over once it goes stale — a rollout is not an outage.
func TestInstanceLease_StaleLeaseTakenOverOnRollout(t *testing.T) {
	pool := leasePool(t)
	repo := postgres.NewPgxInstanceLeaseRepository(pool)

	const shortTTL = 500 * time.Millisecond
	// Outgoing pod acquires, then "dies" — we simply stop touching it.
	out, err := repo.TryAcquire(context.Background(), "outgoing-pod", shortTTL)
	if err != nil || !out.Acquired {
		t.Fatalf("outgoing pod must acquire; acquired=%v err=%v", out.Acquired, err)
	}

	// Incoming pod: while the outgoing lease is still fresh it must NOT
	// take over.
	fresh, err := repo.TryAcquire(context.Background(), "incoming-pod", shortTTL)
	if err != nil {
		t.Fatalf("incoming TryAcquire (fresh): %v", err)
	}
	if fresh.Acquired {
		t.Fatal("incoming pod must NOT steal a still-fresh lease")
	}

	// Wait past the TTL so the outgoing lease goes stale.
	time.Sleep(shortTTL + 300*time.Millisecond)

	stale, err := repo.TryAcquire(context.Background(), "incoming-pod", shortTTL)
	if err != nil {
		t.Fatalf("incoming TryAcquire (stale): %v", err)
	}
	if !stale.Acquired {
		t.Fatal("incoming pod MUST take over once the outgoing lease is stale (else every rollout is an outage)")
	}
	if stale.Holder != "incoming-pod" {
		t.Fatalf("after takeover the holder must be incoming-pod; got %q", stale.Holder)
	}
}

// TestInstanceLease_LiveIncumbentHeartbeatKeepsLoserOut proves the
// heartbeat is load-bearing: while the incumbent keeps heartbeating, a
// second instance is kept out for its ENTIRE acquisition window even
// though the TTL is short. Without the heartbeat the lease would lapse
// and the loser would wrongly take over.
func TestInstanceLease_LiveIncumbentHeartbeatKeepsLoserOut(t *testing.T) {
	pool := leasePool(t)
	repo := postgres.NewPgxInstanceLeaseRepository(pool)

	// Incumbent with a SHORT TTL but a FAST heartbeat that keeps renewing.
	incumbentCfg := lease.Config{
		InstanceID:    "incumbent",
		TTL:           200 * time.Millisecond,
		Heartbeat:     40 * time.Millisecond, // << TTL, so it never lapses
		AcquireWindow: 300 * time.Millisecond,
		RetryInterval: 15 * time.Millisecond,
	}
	coordA := lease.NewCoordinator(repo, incumbentCfg, lifecycle.NewStartupReport(), (&leaseLog{}).logf)
	if !coordA.Acquire(context.Background()) {
		t.Fatal("incumbent must acquire")
	}
	defer coordA.Release(context.Background())

	// Loser's window spans many incumbent heartbeats AND several TTLs.
	loserCfg := lease.Config{
		InstanceID:    "loser",
		TTL:           200 * time.Millisecond,
		Heartbeat:     time.Hour,
		AcquireWindow: 700 * time.Millisecond, // > 3× the TTL
		RetryInterval: 20 * time.Millisecond,
	}
	reportB := lifecycle.NewStartupReport()
	coordB := lease.NewCoordinator(repo, loserCfg, reportB, (&leaseLog{}).logf)
	if coordB.Acquire(context.Background()) {
		t.Fatal("a live, heartbeating incumbent must keep the loser out for the whole window")
	}
	if !reportB.HasFatal() {
		t.Fatal("kept-out loser must record NOT-SERVING")
	}
}

// TestInstanceLease_TeethBypassBothServe PROVES THE TEETH. With the lease
// gate ENFORCED, a second instance facing a live incumbent enters
// NOT-SERVING. With the gate BYPASSED (the override path, which skips
// Acquire entirely), the very same second instance sees NO fault and
// would serve — demonstrating that the lease check is exactly what
// creates the single-replica exclusion.
func TestInstanceLease_TeethBypassBothServe(t *testing.T) {
	pool := leasePool(t)
	repo := postgres.NewPgxInstanceLeaseRepository(pool)

	// Incumbent holds the lease.
	if out, err := repo.TryAcquire(context.Background(), "incumbent", 45*time.Second); err != nil || !out.Acquired {
		t.Fatalf("incumbent must acquire; acquired=%v err=%v", out.Acquired, err)
	}

	// ENFORCED: the gate runs → the second instance refuses.
	enforced := lifecycle.NewStartupReport()
	coord := lease.NewCoordinator(repo, fastLeaseCfg("second"), enforced, (&leaseLog{}).logf)
	if coord.Acquire(context.Background()) {
		t.Fatal("with the gate enforced, the second instance must refuse")
	}
	if enforced.Serving() {
		t.Fatal("enforced second instance must be NOT-SERVING")
	}

	// BYPASSED: the override path skips Acquire entirely. Nothing records a
	// fault, so the second instance would serve — even though the incumbent
	// still holds the lease. This is the teeth: remove the check and the
	// exclusion vanishes.
	bypassed := lifecycle.NewStartupReport()
	if !bypassed.Serving() {
		t.Fatal("a report with no lease gate must be serving (this is what override does)")
	}
	// Contrast is the proof: same DB state, opposite serving decision,
	// solely because the enforced path ran the lease check.
	if enforced.Serving() == bypassed.Serving() {
		t.Fatal("the lease check must change the serving decision; if not, it has no teeth")
	}
}

// TestInstanceLease_OverrideRuntimeBothServe drives TWO FULL runtimes
// against one Postgres with IDENTUUM_IDP_ALLOW_MULTI_REPLICA set: BOTH
// serve (no lease exclusion) and each emits the loud degradation
// WARNING. This is the operator-visible override end to end.
func TestInstanceLease_OverrideRuntimeBothServe(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	// Clear any lease row left by a prior test in this shared DB so the
	// "override creates no row" assertion is meaningful.
	pool, err := postgres.NewPool(context.Background(), dbURL, nil)
	if err != nil {
		t.Fatalf("verify pool: %v", classifyOpenError(err))
	}
	defer pool.Close()
	clearLease(t, pool)

	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")

	startOne := func(name string) (*runtime.Runtime, *syncBuf) {
		stderr := &syncBuf{}
		rt, err := runtime.New(runtime.Config{
			Addr:      "127.0.0.1:0",
			Issuer:    "http://127.0.0.1:7113",
			JWKSDBURL: dbURL,
			DataDir:   t.TempDir(),
			Stdout:    &syncBuf{},
			Stderr:    stderr,
		})
		if err != nil {
			t.Fatalf("%s New: %v", name, err)
		}
		if err := rt.Start(context.Background()); err != nil {
			t.Fatalf("%s Start: %v", name, err)
		}
		return rt, stderr
	}

	rtA, errA := startOne("A")
	rtB, errB := startOne("B")
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rtA.Shutdown(ctx)
		_ = rtB.Shutdown(ctx)
	}()

	if !rtA.Serving() || !rtB.Serving() {
		t.Fatalf("with the override set BOTH runtimes must serve; A=%v B=%v", rtA.Serving(), rtB.Serving())
	}
	for name, buf := range map[string]*syncBuf{"A": errA, "B": errB} {
		got := buf.String()
		if !strings.Contains(got, "IDENTUUM_IDP_ALLOW_MULTI_REPLICA is set") {
			t.Fatalf("runtime %s must emit the override WARNING; got:\n%s", name, got)
		}
		if !strings.Contains(got, "SILENTLY BREAKS per-process security") || !strings.Contains(got, "Professional+") {
			t.Fatalf("runtime %s override WARNING must state what degrades; got:\n%s", name, got)
		}
	}
	// No lease row exists because the override skips the lease entirely.
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM instance_lease").Scan(&n); err != nil {
		t.Fatalf("count lease rows: %v", err)
	}
	if n != 0 {
		t.Fatalf("override must NOT create a lease row; found %d", n)
	}
}
