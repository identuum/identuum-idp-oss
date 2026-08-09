package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// PgxInstanceLeaseRepository is the pgx-backed accessor for the
// singleton instance_lease row (migration 0023). It realizes the OSS
// single-replica boundary (A-2a): exactly one live instance may hold
// the lease at a time.
//
// The repository is deliberately NOT part of postgres.Repositories:
// the lease is a process-lifecycle concern owned by the runtime, not a
// tenant/domain resource wired into the router. The runtime constructs
// it directly from the pool.
type PgxInstanceLeaseRepository struct {
	db DBTX
}

// NewPgxInstanceLeaseRepository constructs a pgx-backed lease repo.
func NewPgxInstanceLeaseRepository(db DBTX) *PgxInstanceLeaseRepository {
	return &PgxInstanceLeaseRepository{db: db}
}

// TryAcquire atomically attempts to acquire (or renew) the singleton
// lease for instanceID with the given TTL. It is a SINGLE statement so
// two racing instances cannot both win — there is no read-modify-write
// window.
//
// The acquire succeeds (Outcome.Acquired == true) in exactly three
// cases, all handled by one INSERT ... ON CONFLICT DO UPDATE:
//
//  1. No lease row exists yet → the INSERT creates it (first boot).
//  2. The row is already ours (instance_id == instanceID) → the DO
//     UPDATE refreshes heartbeat_at (this is ALSO the heartbeat path).
//  3. The incumbent's heartbeat is STALE (older than ttl) → the DO
//     UPDATE takes the row over (rolling-deploy / crash recovery).
//
// When a DIFFERENT instance holds a LIVE (non-stale) lease, the
// ON CONFLICT DO UPDATE's WHERE is false: Postgres performs no update,
// RETURNING yields zero rows, and NO unique-violation is raised (the
// conflict was consumed by DO UPDATE). The caller LOST. A follow-up
// read fills Outcome.Holder / HeartbeatAt so the loser can name the
// incumbent in its NOT-SERVING log.
//
// Atomicity guarantee: under concurrent inserts on the same primary
// key, PostgreSQL serializes the conflicting row via a row lock — one
// INSERT commits and every other attempt is funneled into the
// ON CONFLICT branch. With a freshly-inserted (non-stale, foreign)
// incumbent the WHERE is false for all losers, so exactly one instance
// observes Acquired == true.
func (r *PgxInstanceLeaseRepository) TryAcquire(ctx context.Context, instanceID string, ttl time.Duration) (domain.InstanceLeaseOutcome, error) {
	const query = `
		INSERT INTO instance_lease (id, instance_id, acquired_at, heartbeat_at)
		VALUES ($1, $2, now(), now())
		ON CONFLICT (id) DO UPDATE
			SET instance_id  = EXCLUDED.instance_id,
			    acquired_at  = CASE
			                     WHEN instance_lease.instance_id = EXCLUDED.instance_id
			                     THEN instance_lease.acquired_at
			                     ELSE now()
			                   END,
			    heartbeat_at = now()
			WHERE instance_lease.instance_id = EXCLUDED.instance_id
			   OR instance_lease.heartbeat_at < now() - make_interval(secs => $3)
		RETURNING instance_id, acquired_at, heartbeat_at
	`
	var out domain.InstanceLeaseOutcome
	err := r.db.QueryRow(ctx, query, domain.InstanceLeaseSingletonID, instanceID, ttl.Seconds()).
		Scan(&out.Holder, &out.AcquiredAt, &out.HeartbeatAt)
	switch {
	case err == nil:
		out.Acquired = true
		return out, nil
	case errors.Is(err, pgx.ErrNoRows):
		// Lost the race to a live incumbent. Read who holds it so the
		// caller can name them. A benign race (the incumbent releasing
		// between the upsert and this read) leaves the row absent — we
		// report a zero Holder rather than fail; the caller treats a
		// non-acquire as NOT-SERVING regardless.
		return r.readHolder(ctx)
	default:
		return domain.InstanceLeaseOutcome{}, fmt.Errorf("instance_lease: try acquire: %w", err)
	}
}

// readHolder returns the current lease holder without mutating the row.
// Used only on the loss path to describe the incumbent.
func (r *PgxInstanceLeaseRepository) readHolder(ctx context.Context) (domain.InstanceLeaseOutcome, error) {
	const query = `
		SELECT instance_id, acquired_at, heartbeat_at
		FROM instance_lease
		WHERE id = $1
	`
	var out domain.InstanceLeaseOutcome
	err := r.db.QueryRow(ctx, query, domain.InstanceLeaseSingletonID).
		Scan(&out.Holder, &out.AcquiredAt, &out.HeartbeatAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// Row vanished between the failed upsert and this read; treat as
		// "lost, holder unknown".
		return domain.InstanceLeaseOutcome{Acquired: false}, nil
	}
	if err != nil {
		return domain.InstanceLeaseOutcome{}, fmt.Errorf("instance_lease: read holder: %w", err)
	}
	out.Acquired = false
	return out, nil
}

// Release relinquishes the lease iff the caller still holds it. It is a
// best-effort graceful-shutdown courtesy that lets the successor
// acquire immediately instead of waiting out the TTL. The instance_id
// guard ensures an instance never deletes a successor's lease (e.g. if
// this instance's lease had already lapsed and been taken over).
func (r *PgxInstanceLeaseRepository) Release(ctx context.Context, instanceID string) error {
	const query = `
		DELETE FROM instance_lease
		WHERE id = $1 AND instance_id = $2
	`
	if _, err := r.db.Exec(ctx, query, domain.InstanceLeaseSingletonID, instanceID); err != nil {
		return fmt.Errorf("instance_lease: release: %w", err)
	}
	return nil
}
