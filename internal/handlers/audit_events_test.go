package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// recordingAuditReader captures the org clamp + filters it was called with and
// returns canned events, so tests can prove WHAT the handler passed to the
// repository — the tenant boundary is the explicit orgScope argument.
type recordingAuditReader struct {
	gotOrgScope *uuid.UUID
	gotFilters  domain.AuditFilters
	calls       int
	ret         []domain.AuditEvent
	hasMore     bool
}

func (r *recordingAuditReader) ListEvents(_ context.Context, orgScope *uuid.UUID, f domain.AuditFilters) ([]domain.AuditEvent, bool, error) {
	r.calls++
	r.gotOrgScope = orgScope
	r.gotFilters = f
	return r.ret, r.hasMore, nil
}

func auditEngine(t *testing.T, principal *domain.Principal, reader AuditReader) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// Inject the principal BEFORE the guarded group (production wiring does
	// this via BearerPrincipal).
	r.Use(func(c *gin.Context) {
		if principal != nil {
			mw.SetPrincipal(c, principal)
		}
		c.Next()
	})
	RegisterAuditRoutes(r, AuditHandlerDeps{
		AuditReader:   reader,
		StartupReport: lifecycle.NewStartupReport(),
	})
	return r
}

func getAudit(r *gin.Engine, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events"+query, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func orgAdmin(org uuid.UUID) *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgAdmin, Scope: domain.ScopeAuditRead}
}

// TEETH 1 (mandatory, revert-proof): an org_admin of A supplying
// actor_organization_id=<B> is clamped to A. The handler ignores the query's
// org and passes ONLY Principal.OrganizationID as the explicit repo argument.
// Revert: change the clamp to honour the query for a non-site_admin -> the
// reader receives B -> this assertion fails.
func TestAuditRead_OrgAdminClampIgnoresClientOrgFilter(t *testing.T) {
	orgA := uuid.New()
	orgB := uuid.New()
	reader := &recordingAuditReader{}
	r := auditEngine(t, orgAdmin(orgA), reader)

	rec := getAudit(r, "?actor_organization_id="+orgB.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if reader.calls != 1 {
		t.Fatalf("reader calls = %d, want 1", reader.calls)
	}
	if reader.gotOrgScope == nil || *reader.gotOrgScope != orgA {
		t.Fatalf("org clamp = %v, want A (%s) — a client-supplied actor_organization_id must be IGNORED for org_admin", reader.gotOrgScope, orgA)
	}
	if *reader.gotOrgScope == orgB {
		t.Fatalf("tenant boundary breached: org_admin of A read org B")
	}
}

// TEETH 2: org_user holding audit:read is refused 403; the reader is never
// consulted (the guard rejects before the handler).
func TestAuditRead_OrgUserWithScopeForbidden(t *testing.T) {
	reader := &recordingAuditReader{}
	p := &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser, Scope: domain.ScopeAuditRead}
	rec := getAudit(auditEngine(t, p, reader), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("org_user with audit:read: status = %d, want 403", rec.Code)
	}
	if reader.calls != 0 {
		t.Fatalf("reader must not be consulted on a 403, got %d calls", reader.calls)
	}
}

// TEETH 3: org_admin WITHOUT the scope is refused 403.
func TestAuditRead_OrgAdminWithoutScopeForbidden(t *testing.T) {
	reader := &recordingAuditReader{}
	p := &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgAdmin, Scope: ""}
	rec := getAudit(auditEngine(t, p, reader), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("org_admin without audit:read: status = %d, want 403", rec.Code)
	}
	if reader.calls != 0 {
		t.Fatalf("reader must not be consulted on a 403, got %d calls", reader.calls)
	}
}

// TEETH 4: site_admin is unscoped — the org clamp is nil, so the reader sees
// all orgs. The response returns whatever the reader (all orgs) yields.
func TestAuditRead_SiteAdminUnscoped(t *testing.T) {
	reader := &recordingAuditReader{ret: []domain.AuditEvent{
		{ID: uuid.New(), ActorType: "user", EventType: "a"},
		{ID: uuid.New(), ActorType: "user", EventType: "b"},
	}}
	p := &domain.Principal{UserID: uuid.New(), Role: domain.RoleSiteAdmin}
	rec := getAudit(auditEngine(t, p, reader), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("site_admin: status = %d, want 200", rec.Code)
	}
	if reader.gotOrgScope != nil {
		t.Fatalf("site_admin org clamp = %v, want nil (unscoped)", reader.gotOrgScope)
	}
	var body auditEventsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Events) != 2 {
		t.Fatalf("site_admin sees %d events, want both orgs' (2)", len(body.Events))
	}
}

// site_admin MAY narrow to one org via actor_organization_id (its only org
// mechanism — still the explicit arg, never inside AuditFilters).
func TestAuditRead_SiteAdminMayNarrowByOrg(t *testing.T) {
	reader := &recordingAuditReader{}
	target := uuid.New()
	p := &domain.Principal{UserID: uuid.New(), Role: domain.RoleSiteAdmin}
	rec := getAudit(auditEngine(t, p, reader), "?actor_organization_id="+target.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if reader.gotOrgScope == nil || *reader.gotOrgScope != target {
		t.Fatalf("site_admin org narrow = %v, want %s", reader.gotOrgScope, target)
	}
}

// The org is never placed in the AuditFilters the handler builds — it travels
// only through the explicit orgScope argument (P3-13: a filter field a caller
// could set must never carry the tenant boundary).
func TestAuditRead_OrgNeverInFilters(t *testing.T) {
	reader := &recordingAuditReader{}
	org := uuid.New()
	getAudit(auditEngine(t, orgAdmin(org), reader), "?event_type=user.login&outcome=denied")
	if reader.gotFilters.ActorOrgID != nil {
		t.Fatalf("AuditFilters.ActorOrgID must stay nil (org travels via orgScope), got %v", reader.gotFilters.ActorOrgID)
	}
	if reader.gotFilters.EventType == nil || *reader.gotFilters.EventType != "user.login" {
		t.Fatalf("event_type filter not parsed: %v", reader.gotFilters.EventType)
	}
	if reader.gotFilters.Outcome == nil || *reader.gotFilters.Outcome != "denied" {
		t.Fatalf("outcome filter not parsed: %v", reader.gotFilters.Outcome)
	}
}
