package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// DefaultAuditRetention is the OSS audit-log retention window when no override
// is configured (L-2). 30 days of a plain, mutable log — long-retention and
// tamper-evidence are the commercial line.
const DefaultAuditRetention = 30 * 24 * time.Hour

// PgxAuditRepository is the pgx-backed store for the OSS plain persistent
// audit log (audit_events, migration 0025). It does exactly two things:
// append an event, and prune events older than the retention window. There is
// no read/list surface (out of L-2 scope) and no hash chain (commercial).
type PgxAuditRepository struct {
	db DBTX
	// retention bounds DeleteExpired. A non-positive retention DISABLES
	// pruning (DeleteExpired becomes a no-op) but never affects Insert, so
	// misconfiguration can drop the sweep but never lose a write.
	retention time.Duration
}

// NewPgxAuditRepository constructs the repo with a retention window. Pass
// DefaultAuditRetention unless an override is resolved.
// PgxAuditRepository satisfies the handlers.AuditReader read seam via
// ListEvents (asserted in the handlers package to avoid an import cycle here).

func NewPgxAuditRepository(db DBTX, retention time.Duration) *PgxAuditRepository {
	return &PgxAuditRepository{db: db, retention: retention}
}

// SetRetention overrides the prune window on an existing instance (used by the
// runtime after resolving the env override). Non-positive disables pruning.
func (r *PgxAuditRepository) SetRetention(d time.Duration) {
	if r != nil {
		r.retention = d
	}
}

// Insert appends one audit event. Nullable columns receive NULL when the
// mapped domain.AuditEvent left the corresponding pointer nil; metadata is
// written verbatim (nil is stored as the '{}' default). created_at is written
// from the event so the caller's clock-source is preserved.
func (r *PgxAuditRepository) Insert(ctx context.Context, e domain.AuditEvent) error {
	const query = `
		INSERT INTO audit_events (
			id, created_at, event_type, outcome, actor_id, actor_type, actor_email,
			actor_role, actor_organization_id, subject_id, subject_type,
			subject_email, ip_address, user_agent, request_id, correlation_id,
			priority, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
		)`

	metadata := e.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}

	_, err := r.db.Exec(ctx, query,
		e.ID,
		e.CreatedAt,
		string(e.EventType),
		e.Outcome,
		e.ActorID,
		e.ActorType,
		e.ActorEmail,
		e.ActorRole,
		e.ActorOrganizationID,
		e.SubjectID,
		e.SubjectType,
		e.SubjectEmail,
		e.IPAddress,
		e.UserAgent,
		e.RequestID,
		e.CorrelationID,
		string(e.Priority),
		metadata,
	)
	if err != nil {
		return fmt.Errorf("failed to insert audit event: %w", err)
	}
	return nil
}

// DeleteExpired prunes rows older than the retention window and returns how
// many were removed. It satisfies service.ExpiredRowSweeper so the existing
// cleanup driver can tick it. A non-positive retention is a no-op (0, nil) —
// pruning disabled, writes unaffected.
func (r *PgxAuditRepository) DeleteExpired(ctx context.Context) (int64, error) {
	if r.retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-r.retention)
	tag, err := r.db.Exec(ctx, `DELETE FROM audit_events WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired audit events: %w", err)
	}
	return tag.RowsAffected(), nil
}

// AuditListDefaultLimit and AuditListMaxLimit bound the read API's page size
// (L-2). OSS had no such convention before; these set it. limit defaults to
// AuditListDefaultLimit and is clamped to AuditListMaxLimit.
const (
	AuditListDefaultLimit = 50
	AuditListMaxLimit     = 200
)

// ClampAuditLimit applies the read API's page-size policy: a non-positive
// request becomes the default (50), anything above the cap (200) is clamped
// DOWN — a caller cannot ask for an unbounded page.
func ClampAuditLimit(requested int) int {
	if requested <= 0 {
		return AuditListDefaultLimit
	}
	if requested > AuditListMaxLimit {
		return AuditListMaxLimit
	}
	return requested
}

// ListEvents returns one page of audit events, newest first, plus whether more
// rows exist beyond the page (computed by fetching limit+1 — no COUNT(*)).
//
// THE TENANT BOUNDARY (P3-13: the predicate lives in SQL so no caller can
// forget it): orgScope is an EXPLICIT argument, never read from the
// caller-controlled AuditFilters. A non-nil orgScope clamps the result to that
// organization; nil is the unscoped (site_admin) path. AuditFilters.ActorOrgID
// is deliberately IGNORED here — the handler routes the org through orgScope,
// so a client-supplied organization filter can never widen a tenant's view.
//
// Every filter is servable by migration 0025's three existing indexes (no new
// index): created_at DESC ordering with an actor_organization_id or event_type
// prefix; outcome/actor_id/subject_id/created_at-range are residual predicates.
// Sort is created_at DESC, id DESC — a stable total order (the id
// tiebreaker keeps offset paging from repeating or skipping a row when
// several share a created_at). SortColumn/SortOrder are not honoured.
func (r *PgxAuditRepository) ListEvents(ctx context.Context, orgScope *uuid.UUID, f domain.AuditFilters) ([]domain.AuditEvent, bool, error) {
	limit := ClampAuditLimit(f.Limit)
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	where := make([]string, 0, 8)
	args := make([]any, 0, 8)
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}

	// Tenant clamp — from the EXPLICIT arg, never from f.
	if orgScope != nil {
		add("actor_organization_id = $%d", *orgScope)
	}
	if f.EventType != nil {
		add("event_type = $%d", string(*f.EventType))
	}
	if f.Outcome != nil {
		add("outcome = $%d", *f.Outcome)
	}
	if f.ActorID != nil {
		add("actor_id = $%d", *f.ActorID)
	}
	if f.SubjectID != nil {
		add("subject_id = $%d", *f.SubjectID)
	}
	if f.StartDate != nil {
		add("created_at >= $%d", *f.StartDate)
	}
	if f.EndDate != nil {
		add("created_at < $%d", *f.EndDate)
	}

	query := `
		SELECT id, created_at, event_type, outcome, actor_id, actor_type,
		       actor_email, actor_role, actor_organization_id, subject_id,
		       subject_type, subject_email, host(ip_address), user_agent,
		       request_id, correlation_id, priority, metadata
		FROM audit_events`
	if len(where) > 0 {
		query += "\n\t\tWHERE " + strings.Join(where, " AND ")
	}
	// Fetch limit+1 so has_more is known without a COUNT(*).
	args = append(args, limit+1, offset)
	query += fmt.Sprintf("\n\t\tORDER BY created_at DESC, id DESC\n\t\tLIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, false, fmt.Errorf("failed to list audit events: %w", err)
	}
	defer rows.Close()

	out := make([]domain.AuditEvent, 0, limit)
	for rows.Next() {
		var e domain.AuditEvent
		var priority string
		var eventType string
		if err := rows.Scan(
			&e.ID, &e.CreatedAt, &eventType, &e.Outcome, &e.ActorID, &e.ActorType,
			&e.ActorEmail, &e.ActorRole, &e.ActorOrganizationID, &e.SubjectID,
			&e.SubjectType, &e.SubjectEmail, &e.IPAddress, &e.UserAgent,
			&e.RequestID, &e.CorrelationID, &priority, &e.Metadata,
		); err != nil {
			return nil, false, fmt.Errorf("failed to scan audit event: %w", err)
		}
		e.EventType = domain.AuditEventType(eventType)
		e.Priority = domain.AuditEventPriority(priority)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("audit event row iteration failed: %w", err)
	}

	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}
