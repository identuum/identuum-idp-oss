package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// (b) End-to-end wiring: the CORS middleware is applied globally by
// NewOSSEngine using OSSRouterDeps.CORSAllowedOrigins. A request from an
// allowlisted origin to /health (always mounted, no deps required) gets
// the exact origin echoed with credentials.
func TestNewOSSEngine_CORS_AllowlistedOriginEchoed(t *testing.T) {
	const origin = "https://console.example.com"
	e := NewOSSEngine(OSSRouterDeps{CORSAllowedOrigins: []string{origin}})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", origin)
	e.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("global CORS: Access-Control-Allow-Origin = %q, want %q", got, origin)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("global CORS: Access-Control-Allow-Credentials = %q, want \"true\"", got)
	}
	// The endpoint still functions — CORS is additive, not a gate.
	if rec.Code == 0 {
		t.Errorf("no status written")
	}
}

// (b)+(c) Deny-by-default wiring: with no CORSAllowedOrigins configured
// (the default OSSRouterDeps), a cross-origin request gets NO
// Access-Control-Allow-Origin — the browser blocks it — while the
// endpoint itself is unaffected.
func TestNewOSSEngine_CORS_DefaultDeniesCrossOrigin(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{}) // empty allowlist == deny all

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	e.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("default deps: Access-Control-Allow-Origin = %q, want empty (deny-by-default)", got)
	}
	if rec.Code == 0 {
		t.Errorf("no status written")
	}
}
