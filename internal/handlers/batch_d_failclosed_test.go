package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// TestRegisterOrganizationsRoutes_NilDepsFailsClosed proves the P-018
// straggler conversion: RegisterOrganizationsRoutes no longer panics when
// neither OrganizationService nor OrganizationRepo is wired — it records a
// fatal fault naming organizations-routes and mounts a uniform
// service-missing fallback so the group's routes refuse with 503.
func TestRegisterOrganizationsRoutes_NilDepsFailsClosed(t *testing.T) {
	report := lifecycle.NewStartupReport()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("RegisterOrganizationsRoutes(nil deps) panicked: %v", rec)
			}
		}()
		RegisterOrganizationsRoutes(r, OrganizationsHandlerDeps{StartupReport: report})
	}()

	if !report.HasFatal() {
		t.Fatalf("nil organization deps must record a fatal fault")
	}
	named := false
	for _, f := range report.Faults() {
		if f.Component == "organizations-routes" && f.Severity == lifecycle.SeverityFatal {
			named = true
		}
	}
	if !named {
		t.Errorf("fault must name organizations-routes; got %+v", report.Faults())
	}

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/organizations"},
		{http.MethodPost, "/api/v1/organizations"},
		{http.MethodGet, "/api/v1/organizations/abc"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s (no deps) status = %d, want 503", tc.method, tc.path, rec.Code)
		}
	}
	t.Logf("EVIDENCE organizations nil-deps: no panic; faults=%+v; group routes → 503", report.Faults())
}
