package domain

import (
	"time"

	"github.com/google/uuid"
)

// instance_lease.go — value types for the OSS single-replica instance
// lease (A-2a). OSS is single-replica by design; the lease is the
// enforcement point that lets exactly one live instance serve. See
// migration 0023_instance_lease.sql for the schema and the boundary
// rationale, and internal/lease for the acquire/heartbeat coordinator.

// InstanceLeaseSingletonID is the reserved UUIDv7-zero sentinel that
// addresses the single instance_lease row on every installation. It
// mirrors the SetupStateSingletonID discipline (…0010); the lease uses
// …0020. The migration's CHECK constraint pins the row to this id.
var InstanceLeaseSingletonID = uuid.MustParse("00000000-0000-7000-0000-000000000020")

// InstanceLeaseOutcome is the result of an atomic TryAcquire attempt.
//
// Acquired reports whether the calling instance now holds the lease
// (either it inserted the row, it already held it and refreshed the
// heartbeat, or it took over a stale lease). When Acquired is false the
// caller LOST the race to a live incumbent, and Holder / HeartbeatAt
// describe that incumbent so the loser can name it in its NOT-SERVING
// ERROR log.
type InstanceLeaseOutcome struct {
	// Acquired is true when the calling instance holds the lease after
	// the attempt.
	Acquired bool

	// Holder is the instance_id currently recorded in the lease row.
	// On a successful acquire this equals the caller's own instance id;
	// on a loss it is the live incumbent's id. It is operator-facing,
	// not a secret.
	Holder string

	// AcquiredAt is when the current holder first acquired the lease.
	AcquiredAt time.Time

	// HeartbeatAt is the current holder's most recent heartbeat.
	HeartbeatAt time.Time
}
