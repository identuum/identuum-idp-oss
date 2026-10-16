package mw

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// A client still holding an EXPIRED (or otherwise invalid) bearer token must
// be able to sign in again, exactly as G1 lets an ended-session token through.
// The sign-in routes continue WITHOUT a principal; every other route still
// refuses with token_invalid and the Bearer invalid_token challenge.

type invalidTokenProbe struct {
	reached bool
	planted bool
	query   string
}

func invalidTokenEngine(v TokenVerifier, revs BearerRevocationLookup, p *invalidTokenProbe) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BearerPrincipal(nil, v, nil, revs))
	h := func(c *gin.Context) {
		p.reached = true
		_, p.planted = PrincipalFromContext(c)
		p.query = c.Request.URL.RawQuery
		c.Status(http.StatusOK)
	}
	for _, path := range signInPaths {
		r.POST(path, h)
	}
	r.GET("/api/v1/auth/browser-login", h)
	for _, rt := range invalidTokenProtectedRoutes {
		r.Handle(rt.method, rt.path, h)
	}
	return r
}

var invalidTokenProtectedRoutes = []struct{ method, path string }{
	{http.MethodPost, "/api/v1/auth/session/refresh"},
	{http.MethodPost, "/api/v1/oauth/token"},
	{http.MethodPost, "/api/v1/auth/step-up/passkey/begin"},
	{http.MethodPost, "/api/v1/auth/change-password"},
	{http.MethodGet, "/api/v1/validate"},
	{http.MethodGet, "/api/v1/me"},
	{http.MethodPost, "/api/v1/auth/logout"},
	{http.MethodGet, "/api/v1/oauth/userinfo"},
	{http.MethodPost, "/api/v1/organizations/activate"},
	{http.MethodGet, "/api/v1/admin/users"},
}

func signInCases() []struct{ method, path string } {
	cases := []struct{ method, path string }{{http.MethodGet, "/api/v1/auth/browser-login"}}
	for _, p := range signInPaths {
		cases = append(cases, struct{ method, path string }{http.MethodPost, p})
	}
	return cases
}

func doBearer(r *gin.Engine, method, path, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", authorization)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func expiredVerifier() *stubVerifier {
	return &stubVerifier{err: errors.New("token has invalid claims: token is expired")}
}

func TestBearerPrincipal_InvalidTokenDoesNotBlockSignIn(t *testing.T) {
	verifiers := map[string]func() *stubVerifier{
		"verifier error": expiredVerifier,
		"nil principal":  func() *stubVerifier { return &stubVerifier{} },
	}
	for name, mk := range verifiers {
		for _, tc := range signInCases() {
			var p invalidTokenProbe
			w := doBearer(invalidTokenEngine(mk(), nil, &p), tc.method, tc.path, "Bearer expired-token")
			if w.Code != http.StatusOK || !p.reached {
				t.Errorf("%s: %s %s: status = %d body = %q, want 200 (sign-in must proceed)", name, tc.method, tc.path, w.Code, w.Body.String())
			}
			if p.planted {
				t.Errorf("%s: %s %s: a principal was planted for an invalid token", name, tc.method, tc.path)
			}
		}
	}
}

func TestBearerPrincipal_EmptyBearerDoesNotBlockSignIn(t *testing.T) {
	for _, tc := range signInCases() {
		var p invalidTokenProbe
		v := &stubVerifier{principal: sessionPrincipal()}
		w := doBearer(invalidTokenEngine(v, nil, &p), tc.method, tc.path, "Bearer ")
		if w.Code != http.StatusOK || !p.reached || p.planted {
			t.Errorf("%s %s with an empty bearer: status = %d reached = %v planted = %v, want 200 with no principal", tc.method, tc.path, w.Code, p.reached, p.planted)
		}
		if v.calls != 0 {
			t.Errorf("%s %s: the verifier was called for an empty bearer", tc.method, tc.path)
		}
	}
}

func TestBearerPrincipal_InvalidTokenSignInKeepsQuery(t *testing.T) {
	var p invalidTokenProbe
	w := doBearer(invalidTokenEngine(expiredVerifier(), nil, &p), http.MethodGet, "/api/v1/auth/browser-login?return_to=%2Fauthorize%3Fx%3D1", "Bearer expired-token")
	if w.Code != http.StatusOK || p.query != "return_to=%2Fauthorize%3Fx%3D1" {
		t.Errorf("status = %d query = %q, want 200 with the query unchanged", w.Code, p.query)
	}
}

func assertTokenInvalid(t *testing.T, method, path string) {
	t.Helper()
	var p invalidTokenProbe
	w := doBearer(invalidTokenEngine(expiredVerifier(), nil, &p), method, path, "Bearer expired-token")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), ReasonTokenInvalid) {
		t.Errorf("%s %s with an invalid token: status = %d body = %q, want 401 %s", method, path, w.Code, w.Body.String(), ReasonTokenInvalid)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Errorf("%s %s: WWW-Authenticate = %q, want the invalid_token challenge", method, path, got)
	}
	if p.reached || p.planted {
		t.Errorf("%s %s: handler reached = %v planted = %v for an invalid token", method, path, p.reached, p.planted)
	}
}

func TestBearerPrincipal_InvalidTokenStillRefusedElsewhere(t *testing.T) {
	for _, rt := range invalidTokenProtectedRoutes {
		assertTokenInvalid(t, rt.method, rt.path)
	}
	// An unrouted path is not a sign-in route either.
	assertTokenInvalid(t, http.MethodPost, "/api/v1/auth/login/other")
	assertTokenInvalid(t, http.MethodPost, "/api/v1/auth/loginx")
	assertTokenInvalid(t, http.MethodPost, "/api/v1/auth")
}

func TestBearerPrincipal_EmptyBearerStillRefusedElsewhere(t *testing.T) {
	for _, rt := range invalidTokenProtectedRoutes {
		var p invalidTokenProbe
		w := doBearer(invalidTokenEngine(&stubVerifier{principal: sessionPrincipal()}, nil, &p), rt.method, rt.path, "Bearer ")
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), ReasonMissingCredential) || p.reached {
			t.Errorf("%s %s with an empty bearer: status = %d body = %q reached = %v, want 401 %s", rt.method, rt.path, w.Code, w.Body.String(), p.reached, ReasonMissingCredential)
		}
	}
}

func TestBearerPrincipal_InvalidTokenWrongMethodSignInNotExempt(t *testing.T) {
	assertTokenInvalid(t, http.MethodGet, "/api/v1/auth/login")
	assertTokenInvalid(t, http.MethodGet, "/api/v1/auth/login/webauthn/finish")
	assertTokenInvalid(t, http.MethodPut, "/api/v1/auth/login")
	assertTokenInvalid(t, http.MethodPut, "/api/v1/auth/browser-login")
	assertTokenInvalid(t, http.MethodDelete, "/api/v1/auth/browser-login")
	assertTokenInvalid(t, http.MethodHead, "/api/v1/auth/browser-login")
}

func TestBearerPrincipal_InvalidTokenVariantSignInPathsNotExempt(t *testing.T) {
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
		assertTokenInvalid(t, tc.method, tc.path)
	}
}

// As for G1, a trailing-slash spelling is answered by Gin's redirect before
// any middleware runs; the follow-up request to the canonical path is judged.
func TestBearerPrincipal_InvalidTokenTrailingSlashRedirects(t *testing.T) {
	cases := []struct {
		method, path, location string
		want                   int
	}{
		{http.MethodPost, "/api/v1/auth/login/", "/api/v1/auth/login", http.StatusTemporaryRedirect},
		{http.MethodGet, "/api/v1/auth/browser-login/", "/api/v1/auth/browser-login", http.StatusMovedPermanently},
	}
	for _, tc := range cases {
		var p invalidTokenProbe
		w := doBearer(invalidTokenEngine(expiredVerifier(), nil, &p), tc.method, tc.path, "Bearer expired-token")
		if w.Code != tc.want || w.Header().Get("Location") != tc.location || p.reached {
			t.Errorf("%s %s: status = %d location = %q reached = %v, want %d %q", tc.method, tc.path, w.Code, w.Header().Get("Location"), p.reached, tc.want, tc.location)
		}
	}
}

func TestBearerPrincipal_SignInStoreErrorStill503(t *testing.T) {
	v := &stubVerifier{err: domain.AuthStoreUnavailable("signing-keys", errors.New("pgx: connection reset by peer"))}
	for _, tc := range signInCases() {
		var p invalidTokenProbe
		w := doBearer(invalidTokenEngine(v, nil, &p), tc.method, tc.path, "Bearer some-token")
		if w.Code != http.StatusServiceUnavailable || p.reached {
			t.Errorf("%s %s with the key store down: status = %d reached = %v, want 503", tc.method, tc.path, w.Code, p.reached)
		}
	}
	principal := sessionPrincipal()
	principal.TokenID = "jti-1"
	revs := &stubRevocation{err: errors.New("pgx: connection reset by peer")}
	var p invalidTokenProbe
	w := doBearer(invalidTokenEngine(&stubVerifier{principal: principal}, revs, &p), http.MethodPost, "/api/v1/auth/login", "Bearer some-token")
	if w.Code != http.StatusServiceUnavailable || p.reached {
		t.Errorf("POST /api/v1/auth/login with the revocation store down: status = %d reached = %v, want 503", w.Code, p.reached)
	}
}

func TestBearerPrincipal_SignInRevokedTokenStillRefused(t *testing.T) {
	principal := sessionPrincipal()
	principal.TokenID = "jti-revoked"
	revs := &stubRevocation{revoked: map[string]bool{"jti-revoked": true}}
	for _, tc := range signInCases() {
		var p invalidTokenProbe
		w := doBearer(invalidTokenEngine(&stubVerifier{principal: principal}, revs, &p), tc.method, tc.path, "Bearer revoked-token")
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), ReasonTokenRevoked) || p.reached {
			t.Errorf("%s %s with a revoked token: status = %d body = %q reached = %v, want 401 %s", tc.method, tc.path, w.Code, w.Body.String(), p.reached, ReasonTokenRevoked)
		}
	}
}
