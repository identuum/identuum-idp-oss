package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// The IdP's own server-rendered pages (sign-in, consent, step-up) load nothing
// and run no script: a markup-injection bug in one of them cannot execute code.
// The rest of the surface (the JSON API and the embedded console) keeps the
// engine-wide policy.
func TestAuthPageCSP_AppliesToTheServerRenderedPagesOnly(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	mountAuthPageCSP(r)
	ok := func(c *gin.Context) { c.Status(http.StatusOK) }

	pages := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/auth/browser-login"},
		{http.MethodPost, "/api/v1/auth/browser-login"},
		{http.MethodGet, "/api/v1/auth/step-up"},
		{http.MethodPost, "/api/v1/auth/step-up"},
		{http.MethodGet, "/api/v1/auth/step-up/passkey"},
		{http.MethodGet, "/api/v1/oauth/consent"},
		{http.MethodPost, "/api/v1/oauth/consent"},
		{http.MethodGet, "/api/v1/oauth/authorize"},
	}
	others := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/users"},
		{http.MethodGet, "/api/v1/oidc/logout"},
		{http.MethodPost, "/api/v1/oauth/token"},
		{http.MethodGet, "/admin"},
	}
	for _, p := range append(append([]struct{ method, path string }{}, pages...), others...) {
		r.Handle(p.method, p.path, ok)
	}

	for _, p := range pages {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(p.method, p.path, nil))
		csp := w.Header().Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "style-src 'unsafe-inline'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s %s: CSP %q lacks %q", p.method, p.path, csp, want)
			}
		}
		if strings.Contains(csp, "script-src") {
			t.Errorf("%s %s: CSP %q grants a script source", p.method, p.path, csp)
		}
	}
	for _, p := range others {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(p.method, p.path, nil))
		if csp := w.Header().Get("Content-Security-Policy"); csp != "" {
			t.Errorf("%s %s: the page policy leaked onto a non-page route: %q", p.method, p.path, csp)
		}
	}
}
