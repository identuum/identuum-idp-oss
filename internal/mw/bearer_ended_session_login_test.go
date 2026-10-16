package mw

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// G1: a client still holding the bearer token of a session that has ended
// (signed out, revoked, user or organization no longer live) must be able to
// sign in again. The sign-in routes therefore continue WITHOUT a principal
// when the liveness verdict is false; every other route still refuses with
// session_not_live.

func endedSessionEngine(planted *bool) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	v := &stubVerifier{principal: sessionPrincipal()}
	sessions := &stubSessionLookup{session: revokedSession()}
	r.Use(BearerPrincipal(nil, v, sessions, nil))
	h := func(c *gin.Context) {
		_, *planted = PrincipalFromContext(c)
		c.Status(http.StatusOK)
	}
	for _, p := range signInPaths {
		r.POST(p, h)
	}
	// Production also serves the browser login form on GET
	// (handlers.RegisterBrowserLoginRoutes).
	r.GET("/api/v1/auth/browser-login", h)
	r.POST("/api/v1/auth/logout", h)
	r.GET("/api/v1/me", h)
	r.GET("/api/v1/auth/login-history", h)
	return r
}

func doEndedRequest(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer ended-session-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

var signInPaths = []string{
	"/api/v1/auth/login",
	"/api/v1/auth/login/mfa",
	"/api/v1/auth/login/mfa/enroll/initiate",
	"/api/v1/auth/login/mfa/enroll/complete",
	"/api/v1/auth/login/password-change",
	"/api/v1/auth/login/webauthn/begin",
	"/api/v1/auth/login/webauthn/finish",
	"/api/v1/auth/browser-login",
}

func TestBearerPrincipal_EndedSessionDoesNotBlockSignIn(t *testing.T) {
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/auth/browser-login"},
	}
	for _, p := range signInPaths {
		cases = append(cases, struct{ method, path string }{http.MethodPost, p})
	}
	for _, tc := range cases {
		var planted bool
		w := doEndedRequest(endedSessionEngine(&planted), tc.method, tc.path)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s with an ended session token: status = %d, want 200 (sign-in must proceed)", tc.method, tc.path, w.Code)
		}
		if planted {
			t.Fatalf("%s %s: a principal was planted for an ended session", tc.method, tc.path)
		}
	}
}

func assertSessionNotLive(t *testing.T, method, path string) {
	t.Helper()
	var planted bool
	w := doEndedRequest(endedSessionEngine(&planted), method, path)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), ReasonSessionNotLive) {
		t.Errorf("%s %s with an ended session token: status = %d body = %q, want 401 %s", method, path, w.Code, w.Body.String(), ReasonSessionNotLive)
	}
	if planted {
		t.Errorf("%s %s: a principal was planted for an ended session", method, path)
	}
}

// The exemption is keyed on the routed template for the request's method. A
// sign-in path called with a method it is not registered for has no sign-in
// template and is refused like any other route.
func TestBearerPrincipal_EndedSessionWrongMethodSignInNotExempt(t *testing.T) {
	assertSessionNotLive(t, http.MethodGet, "/api/v1/auth/login")
	assertSessionNotLive(t, http.MethodGet, "/api/v1/auth/login/webauthn/finish")
	assertSessionNotLive(t, http.MethodPut, "/api/v1/auth/login")
	assertSessionNotLive(t, http.MethodPut, "/api/v1/auth/browser-login")
	assertSessionNotLive(t, http.MethodDelete, "/api/v1/auth/browser-login")
	assertSessionNotLive(t, http.MethodHead, "/api/v1/auth/browser-login")
}

// Only the canonical path the router serves as sign-in is exempt. An encoded,
// case-variant or doubled-slash spelling of a sign-in path is refused with
// session_not_live on an ended token.
func TestBearerPrincipal_EndedSessionVariantSignInPathsNotExempt(t *testing.T) {
	cases := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/auth/%6cogin"},
		{http.MethodPost, "/api/v1/auth%2flogin"},
		{http.MethodPost, "/api/v1/auth/login%2fmfa"},
		{http.MethodPost, "/api%2fv1/auth/browser-login"},
		{http.MethodPost, "/api/v1/auth/LOGIN"},
		{http.MethodPost, "//api/v1/auth/login"},
		{http.MethodPost, "/api/v1//auth/login"},
		{http.MethodGet, "/api/v1/auth/%62rowser-login"},
		{http.MethodGet, "/api/v1/auth/BROWSER-LOGIN"},
		{http.MethodGet, "/api/v1//auth/browser-login"},
	}
	for _, tc := range cases {
		assertSessionNotLive(t, tc.method, tc.path)
	}
}

// A trailing-slash spelling is NOT refused with session_not_live: Gin's
// default RedirectTrailingSlash answers it before any middleware runs (307 for
// POST, 301 for GET) and points the client at the canonical path, where the
// exemption then applies. This predates the exemption and admits no identity:
// the redirect is served without consulting the bearer and with no principal.
func TestBearerPrincipal_EndedSessionTrailingSlashRedirects(t *testing.T) {
	cases := []struct {
		method, path, location string
		want                   int
	}{
		{http.MethodPost, "/api/v1/auth/login/", "/api/v1/auth/login", http.StatusTemporaryRedirect},
		{http.MethodPost, "/api/v1/auth/browser-login/", "/api/v1/auth/browser-login", http.StatusTemporaryRedirect},
		{http.MethodGet, "/api/v1/auth/browser-login/", "/api/v1/auth/browser-login", http.StatusMovedPermanently},
	}
	for _, tc := range cases {
		var planted bool
		w := doEndedRequest(endedSessionEngine(&planted), tc.method, tc.path)
		if w.Code != tc.want || w.Header().Get("Location") != tc.location {
			t.Errorf("%s %s with an ended session token: status = %d location = %q, want %d %q", tc.method, tc.path, w.Code, w.Header().Get("Location"), tc.want, tc.location)
		}
		if planted {
			t.Errorf("%s %s: a principal was planted for an ended session", tc.method, tc.path)
		}
	}
}

func TestBearerPrincipal_EndedSessionStillRefusedElsewhere(t *testing.T) {
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/me"},
		{http.MethodPost, "/api/v1/auth/logout"},
		{http.MethodGet, "/api/v1/auth/login-history"},
	}
	for _, tc := range cases {
		var planted bool
		w := doEndedRequest(endedSessionEngine(&planted), tc.method, tc.path)
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), ReasonSessionNotLive) {
			t.Fatalf("%s %s with an ended session token: status = %d body = %q, want 401 %s", tc.method, tc.path, w.Code, w.Body.String(), ReasonSessionNotLive)
		}
	}
}
