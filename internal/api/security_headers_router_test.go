package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// (b) End-to-end wiring: the security-headers middleware is applied
// globally by NewOSSEngine, so a real response (here /health, always
// mounted, no deps required) carries every security header.
func TestNewOSSEngine_SetsSecurityHeaders(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	for _, h := range []string{
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Content-Security-Policy",
	} {
		if rec.Header().Get(h) == "" {
			t.Errorf("global security header %q missing on /health via NewOSSEngine", h)
		}
	}
	// (d) the endpoint still functions — status is not clobbered.
	if rec.Code == 0 {
		t.Errorf("no status written")
	}
}
