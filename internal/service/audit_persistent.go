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
	return s.repo.Insert(ctx, mapAuditEvent(ctx, e))
}

// resolveAuditParties fills what the call site left empty (OSS-FIN-3):
//
//   - the actor, from the request's audit.Actor — never overwriting a field
//     the call site set, and taking the id only when the types agree;
//     "anonymous" for a request with no principal, "system" for work no
//     request started;
//   - the organization acted upon: the event's own, else
//     Metadata["organization_id"], else the actor's organization when the
//     actor is bound to one (a site_admin is not: its org is the system's);
//   - the actor's organization: the request actor's, else (no principal)
//     the event's, as before.
//
// It returns the event with the actor filled, the organization acted upon
// and the actor's organization.
func resolveAuditParties(ctx context.Context, e audit.Event) (audit.Event, uuid.UUID, uuid.UUID) {
	a, hasActor := audit.ActorFrom(ctx)
	actorOrg := e.OrganizationID
	if hasActor {
		if e.ActorType == "" {
			e.ActorType = a.Type
		}
		if e.ActorType == a.Type {
			if e.ActorID == uuid.Nil {
				e.ActorID = a.ID
			}
			if e.ActorEmail == "" {
				e.ActorEmail = a.Email
			}
			if e.ActorRole == "" {
				e.ActorRole = a.Role
			}
			if a.ClientID != "" {
				if _, set := e.Metadata["actor_client_id"]; !set {
					md := make(map[string]any, len(e.Metadata)+1)
					for k, v := range e.Metadata {
						md[k] = v
					}
					md["actor_client_id"] = a.ClientID
					e.Metadata = md
				}
			}
		}
		if a.OrganizationID != uuid.Nil {
			actorOrg = a.OrganizationID
		}
	}
	if e.ActorType == "" {
		if audit.IsRequest(ctx) {
			e.ActorType = audit.ActorTypeAnonymous
		} else {
			e.ActorType = audit.ActorTypeSystem
		}
	}
	target := e.OrganizationID
	if target == uuid.Nil {
		target = metadataOrganization(e.Metadata)
	}
	if target == uuid.Nil && hasActor && a.Role != string(domain.RoleSiteAdmin) &&
		a.OrganizationID != uuid.Nil && a.OrganizationID.String() != domain.SystemOrgID {
		target = a.OrganizationID
	}
	return e, target, actorOrg
}

// metadataOrganization reads Metadata["organization_id"] when it holds a
// uuid (as a uuid.UUID, a *uuid.UUID or its string form); uuid.Nil otherwise.
func metadataOrganization(md map[string]any) uuid.UUID {
	switch v := md["organization_id"].(type) {
	case uuid.UUID:
		return v
	case *uuid.UUID:
		if v != nil {
			return *v
		}
	case string:
		if id, err := uuid.Parse(v); err == nil {
			return id
		}
	}
	return uuid.Nil
}

// mapAuditEvent converts the OSS-safe audit.Event into the persistence shape.
// Zero values become NULL (nil pointers): uuid.Nil → nil *uuid.UUID, "" → nil
// *string. actor_type/priority are non-null value columns. A fresh UUIDv7 id
// is minted per event; a zero Timestamp is replaced with now() (matching the
// NoopService/commercial clock-source rule). The actor and both
// organizations are resolved first (resolveAuditParties).
func mapAuditEvent(ctx context.Context, e audit.Event) domain.AuditEvent {
	e, target, actorOrg := resolveAuditParties(ctx, e)
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
		ActorOrganizationID: nilUUID(actorOrg),
		OrganizationID:      nilUUID(target),
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
