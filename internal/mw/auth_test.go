package mw

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func newEngineWith(t *testing.T, handlers ...gin.HandlerFunc) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("/probe", handlers...)
	return r
}

func TestSetPrincipalAndPrincipalFromContext_RoundTrip(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	p := &domain.Principal{UserID: uuid.New(), Role: domain.RoleSiteAdmin}
	SetPrincipal(c, p)
	got, ok := PrincipalFromContext(c)
	if !ok || got != p {
		t.Errorf("PrincipalFromContext = %v ok=%v, want round-trip", got, ok)
	}
}

func TestPrincipalFromContext_AbsentKey(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got, ok := PrincipalFromContext(c); ok || got != nil {
		t.Errorf("PrincipalFromContext returned %v ok=%v on empty context; want nil/false", got, ok)
	}
}

func TestPrincipalFromContext_ExplicitNilTreatedAsAbsent(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	SetPrincipal(c, nil)
	if got, ok := PrincipalFromContext(c); ok || got != nil {
		t.Errorf("explicit nil principal must read as absent; got %v ok=%v", got, ok)
	}
}

func TestRequireAuthenticated_NoPrincipalIs401(t *testing.T) {
	called := false
	r := newEngineWith(t, RequireAuthenticated(), func(c *gin.Context) { called = true })
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if called {
		t.Errorf("downstream handler ran despite missing principal")
	}
}

func TestRequireAuthenticated_PrincipalIs200(t *testing.T) {
	r := newEngineWith(t,
		InjectPrincipalForTest(&domain.Principal{Role: domain.RoleOrgUser}),
		RequireAuthenticated(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequireSiteAdmin_NoPrincipalIs401(t *testing.T) {
	r := newEngineWith(t, RequireSiteAdmin(), func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireSiteAdmin_NonSiteAdminIs403(t *testing.T) {
	r := newEngineWith(t,
		InjectPrincipalForTest(&domain.Principal{Role: domain.RoleOrgAdmin}),
		RequireSiteAdmin(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestRequireSiteAdmin_SiteAdminPasses(t *testing.T) {
	r := newEngineWith(t,
		InjectPrincipalForTest(&domain.Principal{Role: domain.RoleSiteAdmin}),
		RequireSiteAdmin(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequireScopesAny_NoScopeArgsIsPassThrough(t *testing.T) {
	r := newEngineWith(t, RequireScopesAny(), func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (no scopes → no-op)", rec.Code)
	}
}

func TestRequireScopesAny_NoPrincipalIs401(t *testing.T) {
	r := newEngineWith(t, RequireScopesAny("keys:read"), func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireScopesAny_PrincipalMissingScopeIs403(t *testing.T) {
	r := newEngineWith(t,
		InjectPrincipalForTest(&domain.Principal{Scope: "other:scope another"}),
		RequireScopesAny("keys:read"),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestRequireScopesAny_PrincipalHasOneScopePasses(t *testing.T) {
	r := newEngineWith(t,
		InjectPrincipalForTest(&domain.Principal{Scope: "keys:read keys:write"}),
		RequireScopesAny("keys:rotate", "keys:read"),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (overlap on keys:read)", rec.Code)
	}
}

func TestErrorBodyShape(t *testing.T) {
	r := newEngineWith(t, RequireAuthenticated(), func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `"unauthorized"`) {
		t.Errorf("body missing unauthorized marker: %q", body)
	}
	// Guard responses must not leak the principal context-key path.
	for _, leak := range []string{"identuum-oss-principal", "principal"} {
		if strings.Contains(body, leak) {
			t.Errorf("body leaks internal key %q: %q", leak, body)
		}
	}
}

func TestInjectPrincipalForTest_NilPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Errorf("InjectPrincipalForTest(nil) did not panic")
		}
	}()
	_ = InjectPrincipalForTest(nil)
}
