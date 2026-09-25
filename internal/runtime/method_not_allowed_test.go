package runtime

import (
	"context"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/internal/uiexport"
	"github.com/identuum/identuum-idp-oss/pkg/uiserve"
)

// OSS-405: a wrong method on a path the IdP registers is answered 405 with an
// Allow header naming the registered methods — never the UI shell, never a
// 404 — on the engine the binary actually serves (New + Start → buildDeps →
// NewOSSEngine), so the route table below is the production one.

const (
	mnaOrigin = "https://admin.example.test"
	mnaParam  = "00000000-0000-4000-8000-000000000001"
	mnaBody   = `{"error":"method_not_allowed"}`
)

// mnaMethods are the methods probed against every registered path, in the
// order an Allow header names them.
var mnaMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions}

// mnaUIRoutes are the identuum-ui pages (every src/app/**/page.tsx of
// identuum-ui d3e7022, route groups dropped, [id] segments given a value);
// the export serves each one the app shell.
var mnaUIRoutes = []string{
	"/", "/account/settings", "/activate", "/ag-admin", "/ag-admin/agents", "/ag-admin/agents/[id]",
	"/ag-admin/agents/[id]/edit", "/ag-admin/agents/new", "/ag-admin/audit", "/ag-admin/hitl",
	"/ag-admin/hitl/[id]", "/ag-admin/login", "/ag-admin/mcp", "/ag-admin/policy-packs",
	"/ag-admin/revocations", "/ag-admin/sessions", "/ag-admin/sessions/[id]", "/claim", "/dashboard",
	"/dashboard/security", "/forgot-password", "/login", "/org-admin", "/org-admin/api-resources",
	"/org-admin/api-resources/[id]", "/org-admin/api-resources/[id]/edit", "/org-admin/api-resources/new",
	"/org-admin/applications", "/org-admin/applications/[id]", "/org-admin/applications/[id]/edit",
	"/org-admin/applications/new", "/org-admin/audit", "/org-admin/service-accounts",
	"/org-admin/service-accounts/[id]", "/org-admin/service-accounts/new", "/org-admin/settings",
	"/org-admin/users", "/org-admin/users/[id]", "/platform-status", "/reset-password", "/setup",
	"/setup-required", "/site-admin", "/site-admin/anomaly", "/site-admin/audit", "/site-admin/keys",
	"/site-admin/license", "/site-admin/org-link", "/site-admin/org-link/ag-plan",
	"/site-admin/org-link/readiness", "/site-admin/organizations", "/site-admin/organizations/[id]",
	"/site-admin/organizations/[id]/assign-admin", "/site-admin/organizations/[id]/deactivate",
	"/site-admin/organizations/[id]/delete", "/site-admin/organizations/[id]/edit",
	"/site-admin/organizations/[id]/reactivate", "/site-admin/organizations/[id]/restore",
	"/site-admin/organizations/new", "/site-admin/reports", "/site-admin/settings", "/site-admin/system",
	"/site-admin/system/audit-chain", "/site-admin/system/info", "/site-admin/system/sessions",
	"/unavailable", "/upgrade", "/verify-email",
}

func startMNARuntime(t *testing.T) *gin.Engine {
	t.Helper()
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")
	rt, err := New(Config{
		Addr:               "127.0.0.1:0",
		Issuer:             "http://127.0.0.1:7113",
		JWKSDBURL:          dbURL,
		DataDir:            t.TempDir(),
		CORSAllowedOrigins: []string{mnaOrigin},
		Stdout:             io.Discard,
		Stderr:             io.Discard,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rt.Shutdown(ctx)
	})
	return rt.Engine()
}

func mnaDo(e http.Handler, method, target string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// mnaConcrete gives every parameter segment a value and every wildcard one
// segment.
func mnaConcrete(pattern string) string {
	segs := strings.Split(pattern, "/")
	for i, s := range segs {
		switch {
		case strings.HasPrefix(s, ":"):
			segs[i] = mnaParam
		case strings.HasPrefix(s, "*"):
			segs[i] = "x"
		case s == "[id]":
			segs[i] = mnaParam
		}
	}
	return strings.Join(segs, "/")
}

// mnaMatches is gin's path match for one pattern: static segments equal, a
// parameter any one non-empty segment, a wildcard the rest.
func mnaMatches(pattern, p string) bool {
	ps, xs := strings.Split(pattern, "/"), strings.Split(p, "/")
	for i, s := range ps {
		if strings.HasPrefix(s, "*") {
			return true
		}
		if i >= len(xs) {
			return false
		}
		if strings.HasPrefix(s, ":") {
			if xs[i] == "" {
				return false
			}
			continue
		}
		if s != xs[i] {
			return false
		}
	}
	return len(ps) == len(xs)
}

// mnaAllow is the Allow header the engine owes a wrong method on p: every
// method some registered route answers there, in mnaMethods order.
func mnaAllow(routes gin.RoutesInfo, p string) []string {
	set := map[string]bool{}
	for _, r := range routes {
		if mnaMatches(r.Path, p) {
			set[r.Method] = true
		}
	}
	var out []string
	for _, m := range mnaMethods {
		if set[m] {
			out = append(out, m)
		}
	}
	return out
}

// mnaPaths are the registered path patterns, the boundary's catch-all
// excluded (it answers every method; its own cases are below).
func mnaPaths(routes gin.RoutesInfo) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range routes {
		if strings.HasPrefix(r.Path, uiserve.BFFPrefix+"/") || seen[r.Path] {
			continue
		}
		seen[r.Path] = true
		out = append(out, r.Path)
	}
	sort.Strings(out)
	return out
}

func mnaWant405(t *testing.T, rec *httptest.ResponseRecorder, what, allow string) {
	t.Helper()
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != allow ||
		rec.Header().Get("Content-Type") != "application/json; charset=utf-8" || rec.Body.String() != mnaBody {
		t.Errorf("%s: %d Allow=%q Content-Type=%q body=%.60q; want 405 Allow=%q application/json %s",
			what, rec.Code, rec.Header().Get("Allow"), rec.Header().Get("Content-Type"), rec.Body.String(), allow, mnaBody)
	}
}

// TestMethodNotAllowed_EveryRegisteredRoute is generated from the engine's
// own route table: every method a registered path does not answer gets 405
// and the exact Allow. HEAD where GET is registered is not a wrong method
// here (it keeps today's answer; see the regressions below).
func TestMethodNotAllowed_EveryRegisteredRoute(t *testing.T) {
	e := startMNARuntime(t)
	routes := e.Routes()
	paths := mnaPaths(routes)
	requests := 0
	for _, pattern := range paths {
		p := mnaConcrete(pattern)
		allow := mnaAllow(routes, p)
		for _, m := range mnaMethods {
			if slices.Contains(allow, m) || (m == http.MethodHead && slices.Contains(allow, http.MethodGet)) {
				continue
			}
			requests++
			mnaWant405(t, mnaDo(e, m, p, nil), m+" "+p, strings.Join(allow, ", "))
		}
	}
	t.Logf("covered %d registered paths (%d routes, the %s catch-all excluded) with %d wrong-method requests",
		len(paths), len(routes), uiserve.BFFPrefix, requests)
}

// TestMethodNotAllowed_TheMeasuredCases are the cases measured on b4c90df:
// each answered the UI shell or a 404.
func TestMethodNotAllowed_TheMeasuredCases(t *testing.T) {
	e := startMNARuntime(t)
	for _, c := range []struct{ method, path, allow string }{
		{http.MethodGet, "/api/v1/auth/login", "POST"},
		{http.MethodPut, "/api/v1/auth/login", "POST"},
		{http.MethodDelete, "/api/v1/organizations", "GET, POST"},
		{http.MethodGet, uiserve.RefreshPath, "POST"},
		{http.MethodGet, uiserve.LogoutPath, "POST"},
		{http.MethodGet, "/api/v1/oauth/token", "POST"},
	} {
		mnaWant405(t, mnaDo(e, c.method, c.path, nil), c.method+" "+c.path, c.allow)
	}
	// /oauth/token is not an OSS route (it is CE's): a page path, the shell.
	rec := mnaDo(e, http.MethodGet, "/oauth/token", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<div id="root">`) || rec.Header().Get("Allow") != "" {
		t.Errorf("GET /oauth/token: %d Allow=%q; want 200, the shell, no Allow", rec.Code, rec.Header().Get("Allow"))
	}
}

// TestMethodNotAllowed_WhatDoesNotChange pins the answers the fix must not
// move: HEAD on GET routes, CORS preflight, UI pages and assets, unknown
// API paths, and the global middleware on a 405 as on a 404.
func TestMethodNotAllowed_WhatDoesNotChange(t *testing.T) {
	e := startMNARuntime(t)
	routes := e.Routes()

	t.Run("HEAD on every GET route", func(t *testing.T) {
		n := 0
		for _, r := range routes {
			if r.Method != http.MethodGet || strings.HasPrefix(r.Path, uiserve.BFFPrefix+"/") {
				continue
			}
			n++
			rec := mnaDo(e, http.MethodHead, mnaConcrete(r.Path), nil)
			if rec.Code != http.StatusNotFound || rec.Header().Get("Allow") != "" ||
				rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
				t.Errorf("HEAD %s: %d Allow=%q Content-Type=%q; want 404 text/plain, no Allow",
					r.Path, rec.Code, rec.Header().Get("Allow"), rec.Header().Get("Content-Type"))
			}
		}
		t.Logf("HEAD on %d GET routes", n)
	})

	t.Run("CORS preflight", func(t *testing.T) {
		for _, p := range []string{"/api/v1/auth/login", "/api/v1/organizations", "/api/v1/oauth/token"} {
			allowed := mnaDo(e, http.MethodOptions, p, map[string]string{"Origin": mnaOrigin, "Access-Control-Request-Method": "POST"})
			h := allowed.Header()
			if allowed.Code != http.StatusNoContent || h.Get("Allow") != "" || allowed.Body.Len() != 0 ||
				h.Get("Access-Control-Allow-Origin") != mnaOrigin || h.Get("Access-Control-Allow-Credentials") != "true" ||
				h.Get("Access-Control-Allow-Methods") == "" || h.Get("Access-Control-Max-Age") == "" {
				t.Errorf("preflight %s from an allowed origin: %d headers=%v", p, allowed.Code, h)
			}
			foreign := mnaDo(e, http.MethodOptions, p, map[string]string{"Origin": "https://evil.example.test", "Access-Control-Request-Method": "POST"})
			h = foreign.Header()
			if foreign.Code != http.StatusNoContent || h.Get("Allow") != "" || foreign.Body.Len() != 0 ||
				h.Get("Access-Control-Allow-Origin") != "" || h.Get("Access-Control-Allow-Methods") != "" {
				t.Errorf("preflight %s from a foreign origin: %d headers=%v", p, foreign.Code, h)
			}
		}
	})

	t.Run("every UI page", func(t *testing.T) {
		for _, page := range mnaUIRoutes {
			p := mnaConcrete(page)
			rec := mnaDo(e, http.MethodGet, p, nil)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<div id="root">`) ||
				rec.Header().Get("Cache-Control") != uiserve.ShellCacheControl || rec.Header().Get("Allow") != "" {
				t.Errorf("GET %s: %d Cache-Control=%q Allow=%q; want 200, the shell", p, rec.Code,
					rec.Header().Get("Cache-Control"), rec.Header().Get("Allow"))
			}
		}
		t.Logf("GET on %d UI pages", len(mnaUIRoutes))
	})

	t.Run("an asset", func(t *testing.T) {
		assets, err := fs.ReadDir(uiexport.FS(), "assets")
		if err != nil || len(assets) == 0 {
			t.Fatalf("no vendored assets: %v", err)
		}
		p := "/assets/" + assets[0].Name()
		rec := mnaDo(e, http.MethodGet, p, nil)
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != uiserve.AssetCacheControl || rec.Header().Get("Allow") != "" {
			t.Errorf("GET %s: %d Cache-Control=%q Allow=%q", p, rec.Code, rec.Header().Get("Cache-Control"), rec.Header().Get("Allow"))
		}
	})

	t.Run("an unknown API path", func(t *testing.T) {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			rec := mnaDo(e, m, "/api/v1/no-such-route", nil)
			if rec.Code != http.StatusNotFound || rec.Body.String() != uiserve.NotFoundBody || rec.Header().Get("Allow") != "" {
				t.Errorf("%s /api/v1/no-such-route: %d body=%.40q Allow=%q; want the plain 404", m, rec.Code, rec.Body.String(), rec.Header().Get("Allow"))
			}
		}
	})

	t.Run("global middleware on a 405 as on a 404", func(t *testing.T) {
		hdr := map[string]string{"Origin": mnaOrigin, "X-Request-ID": "oss-405-proof"}
		notFound := mnaDo(e, http.MethodGet, "/api/v1/no-such-route", hdr)
		wrong := mnaDo(e, http.MethodGet, "/api/v1/auth/login", hdr)
		if notFound.Code != http.StatusNotFound || wrong.Code != http.StatusMethodNotAllowed {
			t.Fatalf("statuses %d / %d; want 404 / 405", notFound.Code, wrong.Code)
		}
		for _, name := range []string{"X-Content-Type-Options", "X-Request-ID", "Access-Control-Allow-Origin"} {
			if v := notFound.Header().Get(name); v == "" || wrong.Header().Get(name) != v {
				t.Errorf("%s: 404 carries %q, 405 carries %q", name, v, wrong.Header().Get(name))
			}
		}
	})
}

// TestMethodNotAllowed_TheBoundary: a wrong-method /bff request is answered
// 405 before the browser proof is checked and never reaches the forwarder;
// a right-method request without the proof is still refused 403.
func TestMethodNotAllowed_TheBoundary(t *testing.T) {
	e := startMNARuntime(t)
	routes := e.Routes()
	requests := 0
	for _, pattern := range mnaPaths(routes) {
		if !strings.HasPrefix(pattern, "/api/v1/") {
			continue
		}
		p := mnaConcrete(pattern)
		allow := mnaAllow(routes, p)
		for _, m := range mnaMethods {
			if slices.Contains(allow, m) || (m == http.MethodHead && slices.Contains(allow, http.MethodGet)) {
				continue
			}
			requests++
			mnaWant405(t, mnaDo(e, m, uiserve.BFFPrefix+p, nil), m+" /bff"+p+" without the header", strings.Join(allow, ", "))
		}
	}
	t.Logf("%d wrong-method /bff requests", requests)
	for _, p := range []string{"/bff/api/v1/auth/login", uiserve.RefreshPath, uiserve.LogoutPath} {
		mnaWant405(t, mnaDo(e, http.MethodGet, p, nil), "GET "+p+" without the header", "POST")
		rec := mnaDo(e, http.MethodPost, p, nil)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "missing_request_header") {
			t.Errorf("POST %s without the header: %d %.80q; want 403 missing_request_header", p, rec.Code, rec.Body.String())
		}
	}
}
