package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// THE-BROWSER-BOUNDARY-IN-GO-2 (Plan C): a route that MINTS the browser's
// auth cookies is a login-CSRF target — a cross-site page can force the
// victim's browser into the attacker's account. The global CORS middleware
// lets a disallowed-origin SIMPLE request through to the handler (it only
// withholds the Allow-* headers), and ShouldBindJSON decodes a text/plain
// body, so a cross-site `<form enctype="text/plain">` carrying JSON used to
// log the browser in. A browser always sends Origin on such a POST; a
// cross-origin request with Content-Type application/json needs a CORS
// preflight the allowlist refuses. Non-browser clients send no Origin and
// keep their contract. Unit proofs (in-memory stores).

func loginCSRFEngine(t *testing.T) http.Handler {
	t.Helper()
	r, _, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["alice@example.com"] = []*domain.User{{
			ID: uuid.New(), Email: "alice@example.com",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
		}}
	})
	return r
}

func loginWith(r http.Handler, contentType, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		strings.NewReader(`{"email":"alice@example.com","password":"correct"}`))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// mintedAuthCookie reports whether the response set either auth cookie to a
// value (an expiring `name=;` clear does not count).
func mintedAuthCookie(w *httptest.ResponseRecorder) bool {
	for _, sc := range w.Header().Values("Set-Cookie") {
		for _, name := range []string{"access_token=", "refresh_token="} {
			if strings.HasPrefix(sc, name) && !strings.HasPrefix(sc, name+";") {
				return true
			}
		}
	}
	return false
}

// Assertion messages never print a login body: it carries token material.

func TestLoginCSRF_CrossSiteSimpleBodyIsRefusedAndMintsNothing(t *testing.T) {
	r := loginCSRFEngine(t)
	for _, ct := range []string{"text/plain", "text/plain;charset=UTF-8", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", ""} {
		w := loginWith(r, ct, "https://evil.example")
		if w.Code != http.StatusForbidden {
			t.Fatalf("cross-site login with Content-Type %q: status %d, want 403 csrf_failed", ct, w.Code)
		}
		if mintedAuthCookie(w) {
			t.Fatalf("cross-site login with Content-Type %q minted an auth cookie", ct)
		}
	}
}

// The other three routes that mint the auth cookies refuse the same shape
// BEFORE reading the body or consulting any dependency (zero deps here).
func TestLoginCSRF_EveryCookieMintingRouteRefusesCrossSiteSimpleBodies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/mfa/enroll/complete", HandleMFAEnrollComplete(AuthSessionsHandlerDeps{}))
	r.POST("/mfa/verify", HandleMFAVerifyLogin(AuthSessionsHandlerDeps{}))
	r.POST("/webauthn/finish", HandleWebAuthnLoginFinish(WebAuthnHandlerDeps{}))
	for _, route := range []string{"/mfa/enroll/complete", "/mfa/verify", "/webauthn/finish?session_id=x"} {
		req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{"session_id":"x","code":"123456"}`))
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "csrf_failed") || mintedAuthCookie(w) {
			t.Fatalf("%s cross-site text/plain: status %d, minted %v, want 403 csrf_failed", route, w.Code, mintedAuthCookie(w))
		}
	}
}

func TestLoginCSRF_BrowserJSONAndNonBrowserClientsKeepTheirContract(t *testing.T) {
	r := loginCSRFEngine(t)
	// The same-origin export (fetch, application/json, Origin present).
	if w := loginWith(r, "application/json", "http://example.com"); w.Code != http.StatusOK || !mintedAuthCookie(w) {
		t.Fatalf("browser JSON login: status %d, minted %v", w.Code, mintedAuthCookie(w))
	}
	// A server-to-server caller (the Next proxy strips Origin; curl sends none).
	if w := loginWith(r, "application/json", ""); w.Code != http.StatusOK {
		t.Fatalf("non-browser JSON login: status %d", w.Code)
	}
	if w := loginWith(r, "text/plain", ""); w.Code != http.StatusOK {
		t.Fatalf("non-browser login without Origin must keep its contract: status %d", w.Code)
	}
}
