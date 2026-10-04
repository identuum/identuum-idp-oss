package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// The real engine carries the warning: it is mounted ahead of every route.
func TestNewOSSEngine_WarnsAboutAnUntrustedForwardingProxy(t *testing.T) {
	var warned []string
	t.Cleanup(mw.SetForwardedHeaderWarnForTest(func(_ context.Context, peer string) { warned = append(warned, peer) }))

	e := NewOSSEngine(OSSRouterDeps{})
	req := httptest.NewRequest(http.MethodGet, "/system/info", nil)
	req.RemoteAddr = "10.0.0.5:4000"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatalf("CONTROL FAILED: /system/info is not mounted (404)")
	}
	if len(warned) != 1 || warned[0] != "10.0.0.5" {
		t.Errorf("warned = %v; want one warning naming 10.0.0.5", warned)
	}
}
