package handlers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// AuditReader is the narrow read seam the audit-log surface depends on
// (L-2 read half). postgres.PgxAuditRepository satisfies it. orgScope is the
// EXPLICIT tenant clamp (nil = site_admin unscoped); it is NEVER taken from
// the caller-controlled AuditFilters.
type AuditReader interface {
	ListEvents(ctx context.Context, orgScope *uuid.UUID, f domain.AuditFilters) ([]domain.AuditEvent, bool, error)
}

// Compile-time assertion that the pgx audit repo satisfies AuditReader lives
// in the postgres package's test (postgres imports nothing from handlers).

// AuditHandlerDeps wires the OSS audit-log READ surface: GET
// /api/v1/audit/events. Authority: site_admin (unscoped, all orgs) OR
// org_admin of their OWN org with the audit:read scope. org_user is refused
// even holding the scope. The guard
// (RequireSiteAdminOrOrgAdminWithScopesAudit) enforces that; the tenant clamp
// below enforces the row boundary.
type AuditHandlerDeps struct {
	AuditReader   AuditReader
	Audit         audit.Service
	StartupReport *lifecycle.StartupReport
}

// auditEventView is the handler-local response shape (mirrors safeClient /
// selfSessionView). Domain types are never returned. Nullable columns are
// omitted when NULL. metadata is included by owner decision.
type auditEventView struct {
	ID                  string         `json:"id"`
	CreatedAt           string         `json:"created_at"`
	EventType           string         `json:"event_type"`
	Outcome             *string        `json:"outcome,omitempty"`
	ActorID             *string        `json:"actor_id,omitempty"`
	ActorType           string         `json:"actor_type"`
	ActorEmail          *string        `json:"actor_email,omitempty"`
	ActorRole           *string        `json:"actor_role,omitempty"`
	ActorOrganizationID *string        `json:"actor_organization_id,omitempty"`
	SubjectID           *string        `json:"subject_id,omitempty"`
	SubjectType         *string        `json:"subject_type,omitempty"`
	SubjectEmail        *string        `json:"subject_email,omitempty"`
	IPAddress           *string        `json:"ip_address,omitempty"`
	UserAgent           *string        `json:"user_agent,omitempty"`
	RequestID           *string        `json:"request_id,omitempty"`
	CorrelationID       *string        `json:"correlation_id,omitempty"`
	Priority            string         `json:"priority"`
	Metadata            map[string]any `json:"metadata,omitempty"`
}

type auditEventsResponse struct {
	Events  []auditEventView `json:"events"`
	HasMore bool             `json:"has_more"`
}

// RegisterAuditRoutes mounts the single audit-log read route. Mirrors
// RegisterOrganizationIdentityProviderRoutes: P-018 fatal + service-missing
// fallback when the reader is unwired, deps.Audit nil → NoopService, a guarded
// group, and a docgen block above the method call.
func RegisterAuditRoutes(router gin.IRouter, deps AuditHandlerDeps) {
	if deps.AuditReader == nil {
		// P-018: the audit-log surface is security-relevant. Record the fault
		// and mount a uniform service-missing fallback instead of panicking.
		deps.StartupReport.Fatal(
			"audit-routes",
			"audit-log read surface unavailable: AuditReader not wired",
		)
		g := router.Group("/api/v1/audit/events")
		g.GET("", serviceMissingFallback("audit"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	g := router.Group("/api/v1/audit/events")
	g.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeAuditRead))

	// docgen:endpoint
	// docgen:surface=audit
	// docgen:method=GET
	// docgen:path=/api/v1/audit/events
	// docgen:summary=Read the OSS plain persistent audit log, newest first. Filter by event_type, outcome, actor_id, subject_id and a created_at range; paginate with limit (default 50, max 200) + offset.
	// docgen:tier=oss
	// docgen:auth=site_admin|org_admin
	// docgen:notes=site_admin sees all orgs (unscoped); an org_admin with the audit:read scope sees ONLY their own org — the org clamp is an explicit repository argument taken from Principal.OrganizationID, and any client-supplied actor_organization_id filter is IGNORED for a non-site_admin (P3-13 tenant boundary). org_user is refused 403 even holding the scope. No COUNT(*): the response carries the page plus has_more. Reading the log emits no audit event of its own.
	// docgen:status=200
	g.GET("", HandleListAuditEvents(deps))
}

// HandleListAuditEvents serves GET /api/v1/audit/events.
func HandleListAuditEvents(deps AuditHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")

		principal, ok := mw.PrincipalFromContext(c)
		if !ok || principal == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		// THE TENANT CLAMP. For a non-site_admin the org scope is ONLY the
		// principal's own org — a client-supplied actor_organization_id is
		// ignored, never merged. site_admin is the unscoped path and MAY
		// narrow to one org via actor_organization_id. Either way the org
		// predicate travels as the explicit repository argument, never inside
		// the AuditFilters the handler builds below.
		var orgScope *uuid.UUID
		if principal.IsSiteAdmin() {
			if raw := c.Query("actor_organization_id"); raw != "" {
				id, err := uuid.Parse(raw)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_actor_organization_id"})
					return
				}
				orgScope = &id
			}
		} else {
			org := principal.OrganizationID // guard guarantees non-nil for org_admin
			orgScope = &org
		}

		filters, badReq := parseAuditFilters(c)
		if badReq != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": badReq})
			return
		}

		events, hasMore, err := deps.AuditReader.ListEvents(c.Request.Context(), orgScope, filters)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}

		views := make([]auditEventView, 0, len(events))
		for i := range events {
			views = append(views, toAuditEventView(events[i]))
		}
		c.JSON(http.StatusOK, auditEventsResponse{Events: views, HasMore: hasMore})
	}
}

// parseAuditFilters reads the query filters (never the org — see the clamp).
// Returns a non-empty error token when a value is malformed.
func parseAuditFilters(c *gin.Context) (domain.AuditFilters, string) {
	var f domain.AuditFilters

	if v := c.Query("event_type"); v != "" {
		et := domain.AuditEventType(v)
		f.EventType = &et
	}
	if v := c.Query("outcome"); v != "" {
		f.Outcome = &v
	}
	if v := c.Query("actor_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return f, "invalid_actor_id"
		}
		f.ActorID = &id
	}
	if v := c.Query("subject_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return f, "invalid_subject_id"
		}
		f.SubjectID = &id
	}
	if v := c.Query("start"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, "invalid_start"
		}
		f.StartDate = &t
	}
	if v := c.Query("end"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, "invalid_end"
		}
		f.EndDate = &t
	}
	if v := c.Query("limit"); v != "" {
		n, err := parsePositiveInt(v)
		if err != nil {
			return f, "invalid_limit"
		}
		f.Limit = n // clamp to the cap lives in the repo
	}
	if v := c.Query("offset"); v != "" {
		n, err := parseNonNegativeInt(v)
		if err != nil {
			return f, "invalid_offset"
		}
		f.Offset = n
	}
	return f, ""
}

func toAuditEventView(e domain.AuditEvent) auditEventView {
	uuidStr := func(p *uuid.UUID) *string {
		if p == nil {
			return nil
		}
		s := p.String()
		return &s
	}
	return auditEventView{
		ID:                  e.ID.String(),
		CreatedAt:           e.CreatedAt.UTC().Format(time.RFC3339),
		EventType:           string(e.EventType),
		Outcome:             e.Outcome,
		ActorID:             uuidStr(e.ActorID),
		ActorType:           e.ActorType,
		ActorEmail:          e.ActorEmail,
		ActorRole:           e.ActorRole,
		ActorOrganizationID: uuidStr(e.ActorOrganizationID),
		SubjectID:           uuidStr(e.SubjectID),
		SubjectType:         e.SubjectType,
		SubjectEmail:        e.SubjectEmail,
		IPAddress:           e.IPAddress,
		UserAgent:           e.UserAgent,
		RequestID:           e.RequestID,
		CorrelationID:       e.CorrelationID,
		Priority:            string(e.Priority),
		Metadata:            e.Metadata,
	}
}

// parsePositiveInt parses a strictly-positive base-10 integer.
func parsePositiveInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, errInvalidInt
	}
	return n, nil
}

// parseNonNegativeInt parses a >= 0 base-10 integer.
func parseNonNegativeInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, errInvalidInt
	}
	return n, nil
}

var errInvalidInt = errInt("invalid integer")

type errInt string

func (e errInt) Error() string { return string(e) }
