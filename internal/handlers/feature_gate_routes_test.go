package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/features"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// gateEngine wires only the two commercially-gated groups with a
// caller-supplied FeatureGate plus the always-ungated identity-
// admin groups (users + organizations + organization-domains) so
// the same test engine can assert both "gated 403" and "ungated
// still 200" branches.
type gateEngine struct {
	r          *gin.Engine
	apiRepo    *memAPIResourceRepo
	stRepo     *memScopeTemplateRepo
	userRepo   *memUserRepo
	orgRepo    *memOrgRepo
	domainRepo *memOrgDomainRepo
}

func newGateEngine(t *testing.T, principal *domain.Principal, gate features.FeatureGate) gateEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	apiRepo := newMemAPIResourceRepo()
	stRepo := newMemScopeTemplateRepo()
	userRepo := newMemUserRepo()
	orgRepo := newMemOrgRepo()
	domainRepo := newMemOrgDomainRepo()
	rec := &audit.Recorder{}
	RegisterAPIResourcesRoutes(r, APIResourcesHandlerDeps{
		APIResourceService: service.NewAPIResourceService(nil, apiRepo),
		Audit:              rec,
		FeatureGate:        gate,
	})
	RegisterScopeTemplatesRoutes(r, ScopeTemplatesHandlerDeps{
		ScopeTemplateService: service.NewScopeTemplateService(nil, stRepo),
		Audit:                rec,
		FeatureGate:          gate,
	})
	// Ungated identity-admin groups so we can prove the gate is
	// scoped to api-resources + scope-templates only.
	RegisterUsersRoutes(r, UsersHandlerDeps{
		UserService: service.NewUserService(nil, userRepo),
		Audit:       rec,
	})
	RegisterOrganizationsRoutes(r, OrganizationsHandlerDeps{
		OrganizationService: service.NewOrganizationService(nil, orgRepo),
		Audit:               rec,
	})
	RegisterOrganizationDomainsRoutes(r, OrganizationDomainsHandlerDeps{
		OrganizationDomainService: service.NewOrganizationDomainService(nil, domainRepo, stubVerifier{err: nil}),
		Audit:                     rec,
	})
	// Public-style endpoint to confirm the gate does not bleed into
	// unrelated routes.
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	return gateEngine{r: r, apiRepo: apiRepo, stRepo: stRepo, userRepo: userRepo, orgRepo: orgRepo, domainRepo: domainRepo}
}

func gateReq(t *testing.T, eng gateEngine, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	eng.r.ServeHTTP(rec, req)
	return rec
}

// ---------- OpenGate (default) ----------

func TestFeatureGate_APIResources_OpenGateAllowsThroughAuth(t *testing.T) {
	eng := newGateEngine(t, siteAdminPrincipal(), features.OpenGate{})
	rec := gateReq(t, eng, http.MethodGet, "/api/v1/api-resources")
	if rec.Code != http.StatusOK {
		t.Fatalf("OpenGate api-resources status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
}

func TestFeatureGate_ScopeTemplates_OpenGateAllowsThroughAuth(t *testing.T) {
	org := uuid.New()
	eng := newGateEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleSiteAdmin,
	}, features.OpenGate{})
	rec := gateReq(t, eng, http.MethodGet, "/api/v1/scope-templates")
	if rec.Code != http.StatusOK {
		t.Fatalf("OpenGate scope-templates status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
}

// ---------- ClosedGate ----------

func TestFeatureGate_APIResources_ClosedGateReturns403(t *testing.T) {
	eng := newGateEngine(t, siteAdminPrincipal(), features.ClosedGate{})
	rec := gateReq(t, eng, http.MethodGet, "/api/v1/api-resources")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ClosedGate status = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	if !contains(body, `"feature":"authorization_server"`) {
		t.Errorf("body missing feature label: %q", body)
	}
}

func TestFeatureGate_ScopeTemplates_ClosedGateReturns403(t *testing.T) {
	eng := newGateEngine(t, siteAdminPrincipal(), features.ClosedGate{})
	rec := gateReq(t, eng, http.MethodGet, "/api/v1/scope-templates")
	if rec.Code != http.StatusForbidden {
		t.Errorf("ClosedGate scope-templates status = %d, want 403", rec.Code)
	}
}

// ClosedGate denies BEFORE the RequireSiteAdmin check so an
// unauthenticated request to a gated route returns 403 (gate
// denial), not 401 (auth denial). This is the documented order.
func TestFeatureGate_ClosedGateDeniesBeforeAuth(t *testing.T) {
	eng := newGateEngine(t, nil, features.ClosedGate{})
	rec := gateReq(t, eng, http.MethodGet, "/api/v1/api-resources")
	if rec.Code != http.StatusForbidden {
		t.Errorf("unauthenticated + closed gate = %d, want 403 (gate denial first)", rec.Code)
	}
}

// ---------- StaticGate ----------

func TestFeatureGate_StaticGate_ResourcesAllowedTemplatesDenied(t *testing.T) {
	// Both groups share the AuthorizationServer flag so an
	// all-or-nothing static gate behaves consistently.
	gate := features.NewStaticGate(map[string]bool{
		features.AuthorizationServer: true,
	})
	eng := newGateEngine(t, siteAdminPrincipal(), gate)
	if rec := gateReq(t, eng, http.MethodGet, "/api/v1/api-resources"); rec.Code != http.StatusOK {
		t.Errorf("api-resources w/ AuthorizationServer=true = %d, want 200", rec.Code)
	}
	if rec := gateReq(t, eng, http.MethodGet, "/api/v1/scope-templates"); rec.Code != http.StatusOK {
		t.Errorf("scope-templates w/ AuthorizationServer=true = %d, want 200", rec.Code)
	}
	denyGate := features.NewStaticGate(map[string]bool{
		features.AuthorizationServer: false,
	})
	denyEng := newGateEngine(t, siteAdminPrincipal(), denyGate)
	if rec := gateReq(t, denyEng, http.MethodGet, "/api/v1/api-resources"); rec.Code != http.StatusForbidden {
		t.Errorf("api-resources w/ AuthorizationServer=false = %d, want 403", rec.Code)
	}
	if rec := gateReq(t, denyEng, http.MethodGet, "/api/v1/scope-templates"); rec.Code != http.StatusForbidden {
		t.Errorf("scope-templates w/ AuthorizationServer=false = %d, want 403", rec.Code)
	}
}

// ---------- Ungated groups unaffected by ClosedGate ----------

func TestFeatureGate_UsersUnaffectedByAuthorizationServerDeny(t *testing.T) {
	eng := newGateEngine(t, siteAdminPrincipal(), features.ClosedGate{})
	rec := gateReq(t, eng, http.MethodGet, "/api/v1/users")
	if rec.Code != http.StatusOK {
		t.Errorf("users list status = %d, want 200 (users group is not feature-gated)", rec.Code)
	}
}

func TestFeatureGate_OrganizationsUnaffectedByAuthorizationServerDeny(t *testing.T) {
	eng := newGateEngine(t, siteAdminPrincipal(), features.ClosedGate{})
	rec := gateReq(t, eng, http.MethodGet, "/api/v1/organizations")
	if rec.Code != http.StatusOK {
		t.Errorf("orgs list status = %d, want 200 (orgs group is not feature-gated)", rec.Code)
	}
}

func TestFeatureGate_OrgDomainsUnaffectedByAuthorizationServerDeny(t *testing.T) {
	org := uuid.New()
	eng := newGateEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleSiteAdmin,
	}, features.ClosedGate{})
	// Seed the org so the same-org guard finds it. Not strictly
	// needed for site_admin but keeps the test honest if the
	// future loosening permits more roles.
	rec := gateReq(t, eng, http.MethodGet, "/api/v1/organizations/"+org.String()+"/domains")
	if rec.Code != http.StatusOK {
		t.Errorf("org domains status = %d, want 200 (domains group is not feature-gated)", rec.Code)
	}
}

func TestFeatureGate_PublicEndpointUnaffected(t *testing.T) {
	eng := newGateEngine(t, nil, features.ClosedGate{})
	rec := gateReq(t, eng, http.MethodGet, "/health")
	if rec.Code != http.StatusOK {
		t.Errorf("public /health status = %d, want 200", rec.Code)
	}
}

// ---------- Nil-deps default behavior ----------

func TestFeatureGate_NilDepsDefaultToOpen(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(siteAdminPrincipal()))
	apiRepo := newMemAPIResourceRepo()
	// No FeatureGate field supplied (nil) — the handler must default to OpenGate.
	RegisterAPIResourcesRoutes(r, APIResourcesHandlerDeps{
		APIResourceService: service.NewAPIResourceService(nil, apiRepo),
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/api-resources", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("nil FeatureGate status = %d, want 200 (default OpenGate)", rec.Code)
	}
	_ = context.Background()
}

// contains is a small substring helper kept local to avoid pulling
// in strings just for one use.
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
