package mw

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// (c) The middleware writes every security header with the expected
// value; (d) the response body, status, and cookies are unaffected.
func TestSecurityHeaders_PresentAndResponseUnaffected(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(SecurityHeaders())
	r.GET("/x", func(c *gin.Context) {
		c.SetCookie("sess", "abc", 3600, "/", "", true, true) // Secure + HttpOnly
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	want := map[string]string{
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Content-Security-Policy":   "frame-ancestors 'none'",
	}
	for h, exp := range want {
		if got := rec.Header().Get(h); got != exp {
			t.Errorf("header %s = %q, want %q", h, got, exp)
		}
	}

	// Response body + status unchanged.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"ok":true}` {
		t.Errorf("body = %q, want {\"ok\":true}", got)
	}
	// Cookie unaffected (present with its Secure + HttpOnly attributes).
	sc := rec.Header().Get("Set-Cookie")
	if sc == "" || !strings.Contains(sc, "sess=abc") || !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "Secure") {
		t.Errorf("cookie altered/missing: %q", sc)
	}
}

// (b/e) A downstream handler can override a header (e.g. an HTML page's
// own CSP), proving the middleware does not clobber per-route policies —
// and the non-overridden security headers still apply.
func TestSecurityHeaders_HandlerCanOverrideCSP(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(SecurityHeaders())
	r.GET("/html", func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, "<html></html>")
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/html", nil))

	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'none'; style-src 'unsafe-inline'" {
		t.Errorf("handler CSP override lost: got %q", got)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options missing on a route that overrode CSP")
	}
}

// Headers appear even on an aborted (503/4xx) response, since they are
// written before c.Next().
func TestSecurityHeaders_PresentOnAbortedResponse(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(SecurityHeaders())
	r.Use(func(c *gin.Context) { c.AbortWithStatus(http.StatusServiceUnavailable) })
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "unreached") })
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Errorf("HSTS missing on the 503 response — security headers must apply to aborted responses too")
	}
}

// An empty option field is skipped (no empty header emitted); a set field
// is written.
func TestSecurityHeaders_EmptyOptionSkipped(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(SecurityHeadersWithOptions(SecurityHeadersOptions{XFrameOptions: "DENY"}))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("set header missing")
	}
	if _, ok := rec.Header()["Strict-Transport-Security"]; ok {
		t.Errorf("empty HSTS option must not emit the header")
	}
}
