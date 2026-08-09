package mw

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// scopeAuditEngine wires a single test route under a chosen
// audit-aware scope guard so the same fixture can pin
// allowed/denied behavior and metadata shape.
func scopeAuditEngine(t *testing.T, principal *domain.Principal, route string, guard gin.HandlerFunc) (*gin.Engine, *audit.Recorder) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(InjectPrincipalForTest(principal))
	}
	r.GET(route, guard, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r, nil
}

func auditEngine(t *testing.T, principal *domain.Principal, route string, build func(rec *audit.Recorder) gin.HandlerFunc) (*gin.Engine, *audit.Recorder) {
	t.Helper()
	rec := &audit.Recorder{}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(InjectPrincipalForTest(principal))
	}
	r.GET(route, build(rec), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r, rec
}

// ---------- RequireScopesAnyWithAudit ----------

func TestRequireScopesAnyWithAudit_AllowedNoEvent(t *testing.T) {
	r, rec := auditEngine(t,
		&domain.Principal{Role: domain.RoleOrgAdmin, Scope: "users:read"},
		"/x",
		func(rec *audit.Recorder) gin.HandlerFunc {
			return RequireScopesAnyWithAudit(rec, "users:read")
		},
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if len(rec.Events()) != 0 {
		t.Errorf("allowed emitted audit: %+v", rec.Events())
	}
}

func TestRequireScopesAnyWithAudit_DeniedEmitsSafeEvent(t *testing.T) {
	p := &domain.Principal{Role: domain.RoleOrgAdmin, UserID: uuid.New(), OrganizationID: uuid.New(), Scope: "other:scope", Email: "leak@test"}
	r, rec := auditEngine(t, p, "/api/v1/users", func(rec *audit.Recorder) gin.HandlerFunc {
		return RequireScopesAnyWithAudit(rec, "users:read", "users:write")
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	events := rec.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Action != "scope.denied" || e.Outcome != "denied" {
		t.Errorf("action/outcome = %q/%q, want scope.denied/denied", e.Action, e.Outcome)
	}
	req, _ := e.Metadata["required_scopes"].([]string)
	if len(req) != 2 || req[0] != "users:read" || req[1] != "users:write" {
		t.Errorf("required_scopes = %v, want [users:read users:write]", req)
	}
	if e.Metadata["method"] != http.MethodGet || e.Metadata["path"] != "/api/v1/users" {
		t.Errorf("method/path = %v/%v", e.Metadata["method"], e.Metadata["path"])
	}
	if e.Metadata["actor_role"] != string(domain.RoleOrgAdmin) {
		t.Errorf("actor_role = %v, want org_admin", e.Metadata["actor_role"])
	}
	// Safety: principal's held scopes, email, user_id, org_id, session_id, client_id must NOT appear.
	for _, banned := range []string{"other:scope", "leak@test", p.UserID.String(), p.OrganizationID.String()} {
		for _, v := range e.Metadata {
			if s, ok := v.(string); ok && strings.Contains(s, banned) {
				t.Errorf("metadata leaked %q in %v", banned, v)
			}
		}
	}
	for _, k := range []string{"scope", "email", "user_id", "org_id", "session_id", "client_id", "token"} {
		if _, present := e.Metadata[k]; present {
			t.Errorf("metadata contains banned key %q", k)
		}
	}
}

func TestRequireScopesAnyWithAudit_NoPrincipal401NoEvent(t *testing.T) {
	r, rec := auditEngine(t, nil, "/x", func(rec *audit.Recorder) gin.HandlerFunc {
		return RequireScopesAnyWithAudit(rec, "users:read")
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if len(rec.Events()) != 0 {
		t.Errorf("401 emitted scope.denied: %+v", rec.Events())
	}
}

func TestRequireScopesAnyWithAudit_EmptyScopesIsPassthrough(t *testing.T) {
	r, rec := auditEngine(t,
		&domain.Principal{Role: domain.RoleOrgUser},
		"/x",
		func(rec *audit.Recorder) gin.HandlerFunc {
			return RequireScopesAnyWithAudit(rec)
		},
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (empty-scopes is no-op)", w.Code)
	}
	if len(rec.Events()) != 0 {
		t.Errorf("empty-scopes emitted audit: %+v", rec.Events())
	}
}

func TestRequireScopesAnyWithAudit_NilAuditDoesNotPanic(t *testing.T) {
	r, _ := scopeAuditEngine(t,
		&domain.Principal{Role: domain.RoleOrgAdmin, Scope: ""},
		"/x",
		RequireScopesAnyWithAudit(nil, "users:read"),
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (nil audit must still deny)", w.Code)
	}
}

// failingAuditService mirrors the audit.Service contract but
// always errors. Used to pin "audit error does not leak to client".
type failingAuditService struct{}

func (failingAuditService) Record(_ context.Context, _ audit.Event) error {
	return errors.New("audit down")
}

func TestRequireScopesAnyWithAudit_AuditErrorSwallowed(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(InjectPrincipalForTest(&domain.Principal{Role: domain.RoleOrgAdmin, Scope: ""}))
	r.GET("/x", RequireScopesAnyWithAudit(failingAuditService{}, "users:read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "audit") {
		t.Errorf("response leaked audit-error detail: %q", body)
	}
}

// ---------- RequireSiteAdminOrSameOrgAdminWithScopesAudit ----------

func TestSameOrgAdminWithScopesAudit_ScopeFailEmitsEvent(t *testing.T) {
	org := uuid.New()
	r, rec := auditEngine(t,
		&domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, Scope: "wrong:scope"},
		"/orgs/:id",
		func(rec *audit.Recorder) gin.HandlerFunc {
			return RequireSiteAdminOrSameOrgAdminWithScopesAudit(nil, rec, "id", "orgs:update")
		},
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/orgs/"+org.String(), nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	events := rec.Events()
	if len(events) != 1 || events[0].Action != "scope.denied" {
		t.Errorf("expected one scope.denied event, got %+v", events)
	}
}

// Cross-org 403 must NOT emit scope.denied — it is a role/tenant
// failure, not a scope failure.
func TestSameOrgAdminWithScopesAudit_CrossOrg403NoEvent(t *testing.T) {
	r, rec := auditEngine(t,
		&domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New(), Scope: "orgs:update"},
		"/orgs/:id",
		func(rec *audit.Recorder) gin.HandlerFunc {
			return RequireSiteAdminOrSameOrgAdminWithScopesAudit(nil, rec, "id", "orgs:update")
		},
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/orgs/"+uuid.NewString(), nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	for _, e := range rec.Events() {
		if e.Action == "scope.denied" {
			t.Errorf("cross-org should not emit scope.denied; got %+v", e)
		}
	}
}

func TestSameOrgAdminWithScopesAudit_SiteAdminAllowedNoEvent(t *testing.T) {
	r, rec := auditEngine(t,
		&domain.Principal{Role: domain.RoleSiteAdmin},
		"/orgs/:id",
		func(rec *audit.Recorder) gin.HandlerFunc {
			return RequireSiteAdminOrSameOrgAdminWithScopesAudit(nil, rec, "id", "orgs:update")
		},
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/orgs/"+uuid.NewString(), nil))
	if w.Code != http.StatusOK {
		t.Errorf("site_admin status = %d, want 200", w.Code)
	}
	if len(rec.Events()) != 0 {
		t.Errorf("site_admin emitted audit: %+v", rec.Events())
	}
}

func TestSameOrgAdminWithScopesAudit_InvalidUUID400NoEvent(t *testing.T) {
	r, rec := auditEngine(t,
		&domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New(), Scope: "orgs:update"},
		"/orgs/:id",
		func(rec *audit.Recorder) gin.HandlerFunc {
			return RequireSiteAdminOrSameOrgAdminWithScopesAudit(nil, rec, "id", "orgs:update")
		},
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/orgs/not-a-uuid", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if len(rec.Events()) != 0 {
		t.Errorf("400 emitted audit: %+v", rec.Events())
	}
}

// ---------- RequireSiteAdminOrOrgAdminWithScopesAudit ----------

func TestOrgAdminWithScopesAudit_ScopeFailEmitsEvent(t *testing.T) {
	r, rec := auditEngine(t,
		&domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New(), Scope: "wrong:scope"},
		"/users",
		func(rec *audit.Recorder) gin.HandlerFunc {
			return RequireSiteAdminOrOrgAdminWithScopesAudit(rec, "users:read")
		},
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	events := rec.Events()
	if len(events) != 1 || events[0].Action != "scope.denied" {
		t.Errorf("expected one scope.denied event, got %+v", events)
	}
	req, _ := events[0].Metadata["required_scopes"].([]string)
	if len(req) != 1 || req[0] != "users:read" {
		t.Errorf("required_scopes = %v", req)
	}
}

func TestOrgAdminWithScopesAudit_OrgUser403NoEvent(t *testing.T) {
	// Wrong role hits the role-check denial, not the scope-check denial.
	r, rec := auditEngine(t,
		&domain.Principal{Role: domain.RoleOrgUser, OrganizationID: uuid.New(), Scope: "users:read"},
		"/users",
		func(rec *audit.Recorder) gin.HandlerFunc {
			return RequireSiteAdminOrOrgAdminWithScopesAudit(rec, "users:read")
		},
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	for _, e := range rec.Events() {
		if e.Action == "scope.denied" {
			t.Errorf("role-denial should not emit scope.denied; got %+v", e)
		}
	}
}

func TestOrgAdminWithScopesAudit_NilOrgPrincipal403NoEvent(t *testing.T) {
	r, rec := auditEngine(t,
		&domain.Principal{Role: domain.RoleOrgAdmin, Scope: "users:read"}, // no org id
		"/users",
		func(rec *audit.Recorder) gin.HandlerFunc {
			return RequireSiteAdminOrOrgAdminWithScopesAudit(rec, "users:read")
		},
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	for _, e := range rec.Events() {
		if e.Action == "scope.denied" {
			t.Errorf("nil-org denial should not emit scope.denied; got %+v", e)
		}
	}
}
