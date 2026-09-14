package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

func TestHealthReportsBruteForceProtection(t *testing.T) {
	for _, active := range []bool{false, true} {
		for _, fatal := range []bool{false, true} {
			report := &lifecycle.StartupReport{}
			if fatal {
				report.Fatal("fixture", "fixture unavailable")
			}
			deps := OSSRouterDeps{StartupReport: report, BruteForceProtectionDisabled: active}
			router := gin.New()
			mountPublicSurface(router, deps)
			for i := 0; i < 3; i++ {
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
				wantStatus := http.StatusOK
				if fatal {
					wantStatus = http.StatusServiceUnavailable
				}
				if w.Code != wantStatus {
					t.Fatalf("health status=%d, want %d", w.Code, wantStatus)
				}
				want := ""
				if active {
					want = "disabled"
				}
				if got := w.Header().Get("X-Identuum-Brute-Force-Protection"); got != want {
					t.Errorf("active=%t: health observation=%q, want %q", active, got, want)
				}
			}
		}
	}
}
