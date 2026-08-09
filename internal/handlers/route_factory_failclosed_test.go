package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// TestRegisterUsersRoutes_NilDepsFailsClosed proves the P-018 conversion
// of the users route factory: with neither UserService nor UserRepo wired
// it does NOT panic (which would kill the process). It records a fatal
// startup fault naming the users-routes component and mounts a uniform
// service-missing fallback, so the group's routes refuse cleanly with 503.
func TestRegisterUsersRoutes_NilDepsFailsClosed(t *testing.T) {
	report := lifecycle.NewStartupReport()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("RegisterUsersRoutes(nil deps) panicked: %v", rec)
			}
		}()
		RegisterUsersRoutes(r, UsersHandlerDeps{StartupReport: report})
	}()

	if !report.HasFatal() {
		t.Fatalf("nil user deps must record a fatal fault")
	}
	named := false
	for _, f := range report.Faults() {
		if f.Component == "users-routes" && f.Severity == lifecycle.SeverityFatal {
			named = true
		}
	}
	if !named {
		t.Errorf("fault must name users-routes; got %+v", report.Faults())
	}

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/users"},
		{http.MethodPost, "/api/v1/users"},
		{http.MethodDelete, "/api/v1/users/abc"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s (no deps) status = %d, want 503", tc.method, tc.path, rec.Code)
		}
	}
	t.Logf("EVIDENCE users nil-deps: no panic; faults=%+v; group routes → 503", report.Faults())
}
