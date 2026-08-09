package mw

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/features"
)

func newFeatureEngine(t *testing.T, gate features.FeatureGate, feature string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("/x", RequireFeature(gate, feature), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestRequireFeature_OpenGateAllows(t *testing.T) {
	r := newFeatureEngine(t, features.OpenGate{}, features.AuthorizationServer)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequireFeature_ClosedGateDenies(t *testing.T) {
	r := newFeatureEngine(t, features.ClosedGate{}, features.AuthorizationServer)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["error"] != "feature not enabled" {
		t.Errorf("body error = %v, want 'feature not enabled'", body["error"])
	}
	if body["feature"] != features.AuthorizationServer {
		t.Errorf("body feature = %v, want %q", body["feature"], features.AuthorizationServer)
	}
	if strings.Contains(rec.Body.String(), "license") || strings.Contains(rec.Body.String(), "tier") || strings.Contains(rec.Body.String(), "scope") {
		t.Errorf("response leaked internal gate/scope/license detail: %q", rec.Body.String())
	}
}

func TestRequireFeature_NilGateDefaultsToOpen(t *testing.T) {
	r := newFeatureEngine(t, nil, features.AuthorizationServer)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("nil gate status = %d, want 200 (documented default)", rec.Code)
	}
}

func TestRequireFeature_StaticGateAllowsListed(t *testing.T) {
	r := newFeatureEngine(t, features.NewStaticGate(map[string]bool{
		features.AuthorizationServer: true,
	}), features.AuthorizationServer)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("static-allow status = %d, want 200", rec.Code)
	}
}

func TestRequireFeature_StaticGateDeniesUnlisted(t *testing.T) {
	r := newFeatureEngine(t, features.NewStaticGate(map[string]bool{
		features.MFA: true,
	}), features.AuthorizationServer)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("static-deny status = %d, want 403", rec.Code)
	}
}

// Roles are forwarded to the gate so a role-aware gate (the OSS
// StarterFeatureGate honours site_admin for MFA) keeps its
// behaviour through the middleware.
func TestRequireFeature_RolesForwardedToGate(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("/y", RequireFeature(features.StarterFeatureGate{}, features.MFA, "site_admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/y", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("starter+site_admin MFA status = %d, want 200", rec.Code)
	}
}

// ---------- RequireFeatureWithAudit ----------

func TestRequireFeatureWithAudit_OpenGateNoAuditEmitted(t *testing.T) {
	rec := &audit.Recorder{}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("/x", RequireFeatureWithAudit(features.OpenGate{}, rec, features.AuthorizationServer), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if len(rec.Events()) != 0 {
		t.Errorf("OpenGate emitted audit events: %+v", rec.Events())
	}
}

func TestRequireFeatureWithAudit_ClosedGateEmitsSafeEvent(t *testing.T) {
	rec := &audit.Recorder{}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	p := &domain.Principal{Role: domain.RoleOrgAdmin, UserID: uuid.New(), OrganizationID: uuid.New()}
	r.Use(InjectPrincipalForTest(p))
	r.GET("/api/v1/scope-templates", RequireFeatureWithAudit(features.ClosedGate{}, rec, features.AuthorizationServer), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/scope-templates", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	events := rec.Events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Action != "feature.denied" || e.Outcome != "denied" {
		t.Errorf("event = action=%q outcome=%q, want feature.denied/denied", e.Action, e.Outcome)
	}
	if e.Metadata["feature"] != features.AuthorizationServer {
		t.Errorf("metadata.feature = %v, want %q", e.Metadata["feature"], features.AuthorizationServer)
	}
	if e.Metadata["method"] != http.MethodGet || e.Metadata["path"] != "/api/v1/scope-templates" {
		t.Errorf("metadata = %+v, want method+path populated", e.Metadata)
	}
	if e.Metadata["actor_role"] != string(domain.RoleOrgAdmin) {
		t.Errorf("metadata.actor_role = %v, want org_admin", e.Metadata["actor_role"])
	}
	// Safety: no token/scope/secret-bearing metadata.
	for k, v := range e.Metadata {
		if k == "scope" || k == "token" || k == "client_secret" || k == "session_id" || k == "user_id" {
			t.Errorf("metadata leaked %s = %v", k, v)
		}
	}
}

func TestRequireFeatureWithAudit_NilAuditDoesNotPanic(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("/x", RequireFeatureWithAudit(features.ClosedGate{}, nil, features.AuthorizationServer), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (nil audit defaults to noop, denial still returns 403)", w.Code)
	}
}

// audit emission errors do not leak to the client — even if a
// recorder fails, the 403 body is unchanged.
type failingAudit struct{}

func (failingAudit) Record(_ context.Context, _ audit.Event) error { return errInjected }

var errInjected = errors.New("audit down")

func TestRequireFeatureWithAudit_AuditErrorSwallowed(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("/x", RequireFeatureWithAudit(features.ClosedGate{}, failingAudit{}, features.AuthorizationServer), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (audit error must not change response)", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "audit down") || strings.Contains(body, "audit") {
		t.Errorf("response leaked audit-error detail: %q", body)
	}
}
