// Package audit defines the OSS-safe audit-emission seam.
//
// OSS handlers and services depend on the Service interface defined
// here. The default OSS build wires NoopService, which discards every
// event — appropriate for deployments that do not need an append-only
// audit ledger. The commercial edition (identuum-idp-ce) supplies a
// real Service implementation that writes to the commercial
// audit_events table, signs the per-org hash chain, and runs the
// compliance-mode webhook fan-out.
//
// Composition contract:
//
//	oss handler/service → audit.Service                (always)
//	default wiring      → audit.NoopService            (OSS deploys)
//	commercial wiring   → ce.NewAppendOnlyAuditService (CE deploys)
//
// The package has zero database, network, or filesystem dependencies.
// It must not import anything beyond stdlib + OSS domain types.
package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Service is the narrowest seam any OSS-side audit caller depends on.
// Returning an error gives the caller a hint that the event failed,
// but no caller is expected to fail their request because audit
// rejected the event — audit is best-effort by design. Callers that
// care about durability should pair Record with a higher-tier
// implementation (the commercial AppendOnlyAuditService).
type Service interface {
	Record(ctx context.Context, event Event) error
}

// Event is the OSS-safe shape passed through Service.Record. The
// field set covers what every OSS-side caller can populate without
// reaching into commercial-only state. Append-only chain fields
// (prev_hash, entry_hash, head signature, KID) deliberately do NOT
// live here — they are an implementation detail of the commercial
// audit store, computed AT INSERT TIME by the CE service, and
// callers must never construct them by hand.
//
// Field semantics:
//
//   - Action is a short, machine-readable identifier for what
//     happened (e.g. "user.login.success", "org.created"). Keeping
//     the type as a string here (rather than the monolith's
//     domain.AuditEventType) lets future handlers move into OSS
//     without first agreeing on the canonical enum surface.
//
//   - Actor* describe who performed the action.
//
//   - Subject* describe what was acted upon. Both ActorID and
//     SubjectID accept zero UUIDs (uuid.Nil) when the field is not
//     applicable to the action (e.g. system events with no human
//     actor).
//
//   - OrganizationID is the tenant scope. uuid.Nil is allowed for
//     site-admin / platform-wide events.
//
//   - Outcome is a short status token ("success", "denied",
//     "error"). Kept as a string rather than an enum so OSS does
//     not have to grow a typed surface for every commercial
//     status.
//
//   - Metadata is an open map of structured context. Callers MUST
//     NOT put credentials, raw tokens, private keys, or any other
//     secret material here. The audit pipeline does not redact
//     dynamically.
//
//   - RequestID + CorrelationID link the event to the originating
//     HTTP request and any cross-request correlation header
//     respectively. Both empty means "not available".
//
//   - IPAddress + UserAgent are populated by the request-context
//     middleware. Empty when the event was emitted outside an HTTP
//     request (e.g. background jobs).
//
//   - Timestamp is the wall-clock event time. Zero values are
//     replaced with time.Now() by NoopService and the canonical
//     commercial implementation; callers may set it explicitly to
//     preserve clock-source semantics.
type Event struct {
	Action         string
	Outcome        string
	Metadata       map[string]any
	ActorID        uuid.UUID
	ActorType      string
	ActorEmail     string
	ActorRole      string
	OrganizationID uuid.UUID
	SubjectID      uuid.UUID
	SubjectType    string
	SubjectEmail   string
	RequestID      string
	CorrelationID  string
	IPAddress      string
	UserAgent      string
	Timestamp      time.Time
}

// Static interface assertions live next to their consumers (NoopService
// in noop.go, Recorder in recorder.go) so adding a new method to
// Service breaks the build at every implementation point at once.
