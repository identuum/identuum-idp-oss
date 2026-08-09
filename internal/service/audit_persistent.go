package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// auditInserter is the narrow seam the persistent audit service writes
// through — postgres.PgxAuditRepository satisfies it. Kept as an interface so
// the mapping is unit-testable without a database.
type auditInserter interface {
	Insert(ctx context.Context, e domain.AuditEvent) error
}

// PersistentAuditService is the OSS plain persistent audit.Service (L-2). It
// maps the OSS-safe audit.Event seam onto internal/domain.AuditEvent and
// appends it to audit_events. NoopService stays the default/fallback; this is
// wired only when the DB-backed runtime is up. It carries NO hash chain and
// no signing — that is the commercial line.
type PersistentAuditService struct {
	repo auditInserter
}

var _ audit.Service = (*PersistentAuditService)(nil)

// NewPersistentAuditService constructs the service over an inserter (the
// audit repository). A nil repo is a programming error; the runtime only
// wires this when repos.Audit is present.
func NewPersistentAuditService(repo auditInserter) *PersistentAuditService {
	return &PersistentAuditService{repo: repo}
}

// Record maps and appends one event. Best-effort by the Service contract: the
// returned error is a hint, callers do not fail their request on it.
func (s *PersistentAuditService) Record(ctx context.Context, e audit.Event) error {
	if s == nil || s.repo == nil {
		return nil
	}
	return s.repo.Insert(ctx, mapAuditEvent(e))
}

// mapAuditEvent converts the OSS-safe audit.Event into the persistence shape.
// Zero values become NULL (nil pointers): uuid.Nil → nil *uuid.UUID, "" → nil
// *string. actor_type/priority are non-null value columns. A fresh UUIDv7 id
// is minted per event; a zero Timestamp is replaced with now() (matching the
// NoopService/commercial clock-source rule). Metadata passes through untouched.
func mapAuditEvent(e audit.Event) domain.AuditEvent {
	id, err := uuidgen.NewV7()
	if err != nil {
		// UUIDv7 generation only fails if the system RNG fails; fall back to
		// v4 so an audit write is never lost on a transient RNG hiccup.
		id = uuid.New()
	}

	createdAt := e.Timestamp
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	priority := domain.AuditPriorityNormal // audit.Event carries no priority

	return domain.AuditEvent{
		ID:                  id,
		CreatedAt:           createdAt,
		EventType:           domain.AuditEventType(e.Action),
		Outcome:             nilStr(e.Outcome),
		ActorType:           e.ActorType, // NOT NULL column; "" is a valid value
		Priority:            priority,
		ActorID:             nilUUID(e.ActorID),
		ActorEmail:          nilStr(e.ActorEmail),
		ActorRole:           nilStr(e.ActorRole),
		ActorOrganizationID: nilUUID(e.OrganizationID),
		SubjectID:           nilUUID(e.SubjectID),
		SubjectType:         nilStr(e.SubjectType),
		SubjectEmail:        nilStr(e.SubjectEmail),
		IPAddress:           nilStr(e.IPAddress),
		UserAgent:           nilStr(e.UserAgent),
		RequestID:           nilStr(e.RequestID),
		CorrelationID:       nilStr(e.CorrelationID),
		Metadata:            e.Metadata,
	}
}

func nilUUID(u uuid.UUID) *uuid.UUID {
	if u == uuid.Nil {
		return nil
	}
	v := u
	return &v
}

func nilStr(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}
