// Package lease implements the OSS single-replica instance-lease
// coordinator (A-2a).
//
// identuum-idp-oss is SINGLE-REPLICA by design. Horizontal scaling / HA
// is a Professional+ commercial capability. The OSS process holds
// per-process security state that is correct for one replica but
// silently broken across replicas (in-process rate-limit buckets,
// in-process WebAuthn ceremony state, a per-process CSRF secret). This
// package enforces the boundary instead of merely assuming it: on
// startup a Coordinator ACQUIRES a singleton DB lease and HEARTBEATS
// it; an instance that cannot acquire a live lease REFUSES TO SERVE by
// recording a fatal on the P-018 StartupReport (NOT-SERVING-JUST-
// ALERTING) and logging loudly — it never panics, Fatals, or exits.
//
// Rolling deploys still work: the outgoing instance releases the lease
// on graceful shutdown (or its heartbeat lapses after the TTL), and the
// incoming instance retries acquisition for a bounded window rather
// than dying instantly.
//
// This package is a leaf over internal/domain + internal/lifecycle so
// runtime may depend on it without a cycle.
package lease

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// Default lease timings. Rationale:
//
//   - Heartbeat 15s / TTL 45s: the TTL is THREE heartbeat intervals, so
//     a healthy holder must miss three consecutive heartbeats (a real
//     stall — process death, a long GC pause, or a sustained DB outage)
//     before its lease is considered stale. Two transient blips never
//     trigger a false handoff.
//   - AcquireWindow 60s / RetryInterval 3s: a starting instance retries
//     for 60s before refusing. 60s > TTL (45s), so even when the
//     predecessor dies UNGRACEFULLY (no Release) the incoming instance
//     still acquires within the window once the stale lease lapses — a
//     rollout is not an outage. On a GRACEFUL rollout the predecessor
//     releases the lease and the successor acquires on its first
//     attempt, so the window is almost never consumed.
const (
	DefaultTTL           = 45 * time.Second
	DefaultHeartbeat     = 15 * time.Second
	DefaultAcquireWindow = 60 * time.Second
	DefaultRetryInterval = 3 * time.Second
)

// Store is the narrow persistence seam the Coordinator needs.
// postgres.PgxInstanceLeaseRepository satisfies it structurally.
type Store interface {
	// TryAcquire atomically acquires or renews the singleton lease for
	// instanceID with the given TTL. Acquired == false means a live
	// incumbent holds it (described by the returned Outcome).
	TryAcquire(ctx context.Context, instanceID string, ttl time.Duration) (domain.InstanceLeaseOutcome, error)
	// Release relinquishes the lease iff instanceID still holds it.
	Release(ctx context.Context, instanceID string) error
}

// Config holds the coordinator's identity and timings. Zero timing
// fields fall back to the Default* values.
type Config struct {
	InstanceID    string
	TTL           time.Duration
	Heartbeat     time.Duration
	AcquireWindow time.Duration
	RetryInterval time.Duration
}

func (c Config) withDefaults() Config {
	if c.TTL <= 0 {
		c.TTL = DefaultTTL
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = DefaultHeartbeat
	}
	// `<= 0`, matching every sibling above. It read `< 0`, so the UNSET zero
	// value — what the production call site produces, since it sets only
	// InstanceID — never got its default: the instance checked once, gave up,
	// and stayed NOT-SERVING (503) forever, because P-018 keeps the process
	// alive and nothing retries. No caller passes 0 deliberately; every test
	// that tunes this sets an explicit positive window.
	if c.AcquireWindow <= 0 {
		c.AcquireWindow = DefaultAcquireWindow
	}
	if c.RetryInterval <= 0 {
		c.RetryInterval = DefaultRetryInterval
	}
	return c
}

// Coordinator drives acquire-with-retry, the heartbeat loop, and
// graceful release for a single serving instance.
type Coordinator struct {
	store  Store
	cfg    Config
	report *lifecycle.StartupReport
	logf   func(format string, args ...any)

	hbCancel context.CancelFunc
	hbDone   chan struct{}
	held     atomic.Bool
}

// NewInstanceID returns an operator-friendly, per-process instance
// identity of the form "<hostname>/<uuid>". The hostname helps an
// operator recognise which pod holds the lease; the uuid guarantees
// uniqueness even across identically-named hosts. It is NOT a secret.
func NewInstanceID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return host + "/" + uuid.NewString()
}

// NewCoordinator builds a coordinator. logf is the loud sink for
// WARN/ERROR diagnostics (the runtime routes it to Stderr); it must be
// non-nil. report is the P-018 StartupReport that carries a fatal into
// NOT-SERVING mode when acquisition fails.
func NewCoordinator(store Store, cfg Config, report *lifecycle.StartupReport, logf func(format string, args ...any)) *Coordinator {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Coordinator{
		store:  store,
		cfg:    cfg.withDefaults(),
		report: report,
		logf:   logf,
	}
}

// Acquire runs the bounded-retry acquisition. It returns true when the
// lease is held (and the heartbeat loop is running). It returns false
// when the window elapsed without acquiring — in that case it has
// ALREADY recorded a fatal on the StartupReport and logged the loud
// ERROR, so the caller must enter NOT-SERVING (never serve normal
// traffic with broken per-process security).
func (c *Coordinator) Acquire(ctx context.Context) bool {
	deadline := time.Now().Add(c.cfg.AcquireWindow)
	var last domain.InstanceLeaseOutcome
	warnedWaiting := false

	for attempt := 1; ; attempt++ {
		out, err := c.store.TryAcquire(ctx, c.cfg.InstanceID, c.cfg.TTL)
		switch {
		case err != nil:
			c.logf("WARN single-replica lease acquire attempt %d hit a transient error; retrying within the %s window",
				attempt, c.cfg.AcquireWindow)
		case out.Acquired:
			c.held.Store(true)
			c.startHeartbeat()
			return true
		default:
			last = out
			if !warnedWaiting {
				// One WARN when we first find a live incumbent, so a
				// normal rolling-deploy wait is visible but not spammy.
				c.logf("WARN single-replica lease held by another instance (incumbent=%q); retrying for up to %s "+
					"(this is expected briefly during a rolling deploy)", incumbentLabel(out), c.cfg.AcquireWindow)
				warnedWaiting = true
			}
		}

		if !time.Now().Before(deadline) {
			break
		}
		if !sleepCtx(ctx, c.cfg.RetryInterval) {
			// Context cancelled (shutdown during startup): stop retrying.
			break
		}
	}

	c.recordLoss(last)
	return false
}

// recordLoss emits the loud ERROR and records the P-018 fatal that puts
// the process into NOT-SERVING. Fault text is secret-free (an instance
// id is operator-facing, never a credential).
func (c *Coordinator) recordLoss(last domain.InstanceLeaseOutcome) {
	incumbent := incumbentLabel(last)
	age := ""
	if !last.HeartbeatAt.IsZero() {
		age = fmt.Sprintf(" (incumbent last heartbeat %s ago)", time.Since(last.HeartbeatAt).Round(time.Second))
	}

	c.logf("ERROR NOT-SERVING: could not acquire the single-replica instance lease after %s; "+
		"this instance=%q, incumbent=%q%s. identuum-idp-oss is SINGLE-REPLICA by design — its rate limiting, "+
		"WebAuthn ceremony state, and CSRF secret are per-process and would be SILENTLY BROKEN across replicas. "+
		"Refusing to serve normal traffic (503). Run exactly one replica, or set IDENTUUM_IDP_ALLOW_MULTI_REPLICA=true "+
		"to KNOWINGLY run multi-replica (horizontal scaling / HA is a Professional+ commercial capability).",
		c.cfg.AcquireWindow, c.cfg.InstanceID, incumbent, age)

	c.report.Fatal("single-replica-lease",
		fmt.Sprintf("another identuum-idp-oss instance holds the single-replica lease (incumbent=%s); refusing to serve. "+
			"OSS is single-replica by design (HA is a Professional+ capability). "+
			"Run one replica or set IDENTUUM_IDP_ALLOW_MULTI_REPLICA=true to override.", incumbent))
}

// startHeartbeat launches the heartbeat loop on a background context so
// it outlives the (short-lived) startup context. Release cancels it.
func (c *Coordinator) startHeartbeat() {
	hbCtx, cancel := context.WithCancel(context.Background())
	c.hbCancel = cancel
	c.hbDone = make(chan struct{})
	go c.heartbeatLoop(hbCtx)
}

// heartbeatLoop renews the lease every Heartbeat interval. A transient
// DB error is logged and retried on the next tick (the same-instance_id
// renewal is idempotent, so a blip self-heals). Losing the lease
// mid-flight — only possible if this instance stalled past the TTL or a
// second instance was force-started — is logged LOUDLY but does NOT
// flap the serving mode (avoids toggling 503s on a transient stall);
// the operator signal is the ERROR log plus the still-live sibling.
func (c *Coordinator) heartbeatLoop(ctx context.Context) {
	defer close(c.hbDone)
	t := time.NewTicker(c.cfg.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			out, err := c.store.TryAcquire(ctx, c.cfg.InstanceID, c.cfg.TTL)
			switch {
			case err != nil:
				c.logf("WARN single-replica lease heartbeat hit a transient error; will retry next interval")
			case !out.Acquired:
				c.held.Store(false)
				c.logf("ERROR single-replica lease LOST while serving: another instance (incumbent=%q) now holds it. "+
					"Two identuum-idp-oss instances appear to be running against one database; per-process security "+
					"(rate limits, WebAuthn, CSRF) is NOT shared across them. Stop the extra replica.", incumbentLabel(out))
			}
		}
	}
}

// Release stops the heartbeat loop and, if this instance still holds the
// lease, deletes the row so a successor can acquire immediately instead
// of waiting out the TTL. Safe to call even if Acquire never succeeded.
func (c *Coordinator) Release(ctx context.Context) {
	if c.hbCancel != nil {
		c.hbCancel()
		<-c.hbDone
		c.hbCancel = nil
	}
	if c.held.Load() {
		if err := c.store.Release(ctx, c.cfg.InstanceID); err != nil {
			c.logf("WARN single-replica lease release on shutdown failed; a successor will wait out the TTL instead")
		}
		c.held.Store(false)
	}
}

// Holds reports whether this instance currently holds the lease.
func (c *Coordinator) Holds() bool { return c.held.Load() }

// incumbentLabel renders a non-empty, human-readable holder id.
func incumbentLabel(o domain.InstanceLeaseOutcome) string {
	if o.Holder == "" {
		return "unknown (another live instance)"
	}
	return o.Holder
}

// sleepCtx sleeps for d or until ctx is cancelled. Returns false if the
// context was cancelled (caller should stop).
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
