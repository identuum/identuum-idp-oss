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
	for _, p := range signInPaths {
		var planted bool
		w := doEndedRequest(endedSessionEngine(&planted), http.MethodPost, p)
		if w.Code != http.StatusOK {
			t.Fatalf("POST %s with an ended session token: status = %d, want 200 (sign-in must proceed)", p, w.Code)
		}
		if planted {
			t.Fatalf("POST %s: a principal was planted for an ended session", p)
		}
	}
}

// Only the canonical path the router serves as sign-in is exempt. An encoded
// or variant spelling that the router decodes or folds onto the same route
// must not reach the sign-in handler on an ended token: it is refused, or
// redirected to the canonical path, and never served as-is.
func TestBearerPrincipal_EndedSessionVariantSignInPathsNotExempt(t *testing.T) {
	paths := []string{
		"/api/v1/auth/%6cogin",
		"/api/v1/auth%2flogin",
		"/api/v1/auth/login%2fmfa",
		"/api%2fv1/auth/browser-login",
		"/api/v1/auth/LOGIN",
		"//api/v1/auth/login",
		"/api/v1//auth/login",
		"/api/v1/auth/login/",
	}
	for _, p := range paths {
		var planted bool
		w := doEndedRequest(endedSessionEngine(&planted), http.MethodPost, p)
		if w.Code == http.StatusOK {
			t.Errorf("POST %s with an ended session token: status = 200, want refusal or redirect (variant path took the sign-in exemption)", p)
		}
		if planted {
			t.Errorf("POST %s: a principal was planted for an ended session", p)
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
