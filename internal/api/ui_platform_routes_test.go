package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/server"
)

// PLAN-D-4: the two UI routes the site-admin overview reads (GET /api/status,
// GET /api/runtime-config) and the IdP probe the settings page reads (GET
// /healthz), served by the binary in the shapes identuum-ui's Next routes
// answer (src/app/api/status/route.ts, src/app/api/runtime-config/route.ts).

func TestHealthz_AnswersExactlyAsHealth(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		e := NewOSSEngine(OSSRouterDeps{Version: "9.9.9", BruteForceProtectionDisabled: disabled})
		health, healthz := uiGet(e, "/health"), uiGet(e, "/healthz")
		if healthz.Code != health.Code || healthz.Body.String() != health.Body.String() {
			t.Fatalf("GET /healthz = %d %q, want /health's %d %q", healthz.Code, healthz.Body.String(), health.Code, health.Body.String())
		}
		if got, want := healthz.Header().Get("X-Identuum-Brute-Force-Protection"), health.Header().Get("X-Identuum-Brute-Force-Protection"); got != want {
			t.Fatalf("brute-force header on /healthz = %q, want /health's %q", got, want)
		}
		if healthz.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("/healthz Cache-Control = %q, want no-store", healthz.Header().Get("Cache-Control"))
		}
	}
}

func TestUIPlatformRoutes_UnknownProbeAndAPIPathsNeverBecomeTheShell(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	for _, p := range []string{"/healthz/extra", "/api/status/extra", "/api/unknown", "/api/runtime-config/x"} {
		rec := uiGet(e, p)
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "<title>shell</title>") {
			t.Fatalf("GET %s: %d %q, want a plain 404, never the shell", p, rec.Code, rec.Body.String())
		}
	}
	if rec := uiGet(e, "/healthz"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"mode":"oss"`) {
		t.Fatalf("GET /healthz with the UI mounted: %d %q, want the health body", rec.Code, rec.Body.String())
	}
}

func TestUIPlatformRoutes_Status(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		e := NewOSSEngine(OSSRouterDeps{UIStaticDir: uiExportDir(t), BruteForceProtectionDisabled: disabled})
		rec := uiGet(e, "/api/status")
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("GET /api/status: %d cache=%q", rec.Code, rec.Header().Get("Cache-Control"))
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("body %q: %v", rec.Body.String(), err)
		}
		idp := map[string]any{"enabled": true, "healthy": true, "product": "identuum-idp-oss"}
		if disabled {
			idp["brute_force_protection_disabled"] = true
		}
		// PLAN-F-2: the binary names its edition, so the one UI artifact
		// both editions embed can read it.
		want := map[string]any{
			"edition": "oss",
			"idp":     idp,
			"ag":      map[string]any{"enabled": false, "healthy": nil, "product": "identuum-ag"},
		}
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		if string(gotJSON) != string(wantJSON) {
			t.Fatalf("disabled=%t: /api/status = %s, want %s", disabled, gotJSON, wantJSON)
		}
	}
}

func TestUIPlatformRoutes_RuntimeConfig(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{
		UIStaticDir:     uiExportDir(t),
		DiscoveryConfig: server.OIDCDiscoveryConfig{Issuer: "https://idp.example.test"},
	})
	rec := uiGet(e, "/api/runtime-config")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/runtime-config: %d %q", rec.Code, rec.Body.String())
	}
	// The export's own platform answers ui_origin with window.location.origin:
	// the UI is served by this binary, so its origin is the request's own.
	want := `{"ag":{"enabled":false,"public_base_url":""},"configured":true,"edition":"oss","idp":{"enabled":true,"public_base_url":"https://idp.example.test"},"ui_origin":"http://example.com"}`
	var v any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	got, _ := json.Marshal(v)
	if string(got) != want {
		t.Fatalf("/api/runtime-config = %s, want %s", got, want)
	}
	if strings.Contains(rec.Body.String(), "internal_base_url") {
		t.Fatal("runtime config must never carry internal_base_url")
	}
}

// Opt-in like the rest of the UI: a binary without a UI directory serves
// neither UI route.
func TestUIPlatformRoutes_NotMountedWithoutTheUI(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	for _, p := range []string{"/api/status", "/api/runtime-config"} {
		if rec := uiGet(e, p); rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s without the UI: %d, want 404", p, rec.Code)
		}
	}
}
