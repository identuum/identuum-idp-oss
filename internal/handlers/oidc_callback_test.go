package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type fakeCallbackHandler struct {
	result *service.OIDCCallbackResult
	err    error
	calls  int
}

func (f *fakeCallbackHandler) HandleCallback(_ context.Context, _ uuid.UUID, _, _, _, _ string) (*service.OIDCCallbackResult, error) {
	f.calls++
	return f.result, f.err
}

func newOIDCCallbackEngine(t *testing.T, cb *fakeCallbackHandler) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// A real CookieSessionService (concrete type) so the completed-login tail
	// (Issue → Set-Cookie) runs exactly as production — same helper browser
	// login uses. AllowPlainHTTP keeps the test cookie inspectable.
	repo := newHandlersSessionRepo()
	sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	RegisterOIDCCallbackRoutes(r, OIDCCallbackHandlerDeps{OIDCCallback: cb, CookieSession: cookies, Audit: &audit.Recorder{}})
	return r
}

func oidcCbGET(r *gin.Engine, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func cbPath(id uuid.UUID) string { return "/api/v1/auth/idp/" + id.String() + "/callback" }

func okResult(returnURL string) *service.OIDCCallbackResult {
	name := "Alice"
	extID := "iss|sub"
	return &service.OIDCCallbackResult{
		User:         &domain.User{Email: "alice@example.com", Name: &name, ExternalID: &extID},
		Session:      &domain.Session{ID: uuid.New(), UserID: uuid.New(), ExpiresAt: time.Now().Add(time.Hour)},
		RefreshToken: "refresh-secret-xyz",
		ReturnURL:    returnURL,
	}
}

// Success → 302 to the STORED sanitized ReturnURL, session cookie planted, and
// the response leaks NO resolved-user PII.
func TestOIDCCallbackRoute_SuccessRedirectsWithCookie(t *testing.T) {
	cb := &fakeCallbackHandler{result: okResult("/dashboard")}
	r := newOIDCCallbackEngine(t, cb)
	rec := oidcCbGET(r, cbPath(uuid.New())+"?state=s&code=c")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%q", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("Location = %q, want the stored /dashboard", loc)
	}
	if sc := rec.Header().Get("Set-Cookie"); sc == "" {
		t.Errorf("no Set-Cookie header — session cookie not planted")
	}
	body := rec.Body.String()
	if strings.Contains(body, "alice@example.com") || strings.Contains(body, "Alice") || strings.Contains(body, "iss|sub") {
		t.Errorf("callback response leaked resolved-user PII: %q", body)
	}
}

// Empty stored ReturnURL → 302 to "/" (safe-landing default).
func TestOIDCCallbackRoute_EmptyReturnURLDefaultsToRoot(t *testing.T) {
	cb := &fakeCallbackHandler{result: okResult("")}
	r := newOIDCCallbackEngine(t, cb)
	rec := oidcCbGET(r, cbPath(uuid.New())+"?state=s&code=c")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want / (safe-landing default for empty ReturnURL)", loc)
	}
	if rec.Header().Get("Set-Cookie") == "" {
		t.Errorf("no Set-Cookie header on the default-landing redirect")
	}
}

// Error sentinels map to their statuses; NO cookie is set and NO redirect
// happens on any failure.
func TestOIDCCallbackRoute_ErrorStatusMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{service.ErrCallbackValidationFailed, http.StatusUnauthorized},
		{service.ErrCallbackForbidden, http.StatusForbidden},
		{service.ErrCallbackProvisionFailed, http.StatusInternalServerError},
		{service.ErrCallbackSessionFailed, http.StatusInternalServerError},
		{service.ErrCallbackDiscoveryFailed, http.StatusBadGateway},
		{service.ErrCallbackExchangeFailed, http.StatusBadGateway},
		{service.ErrCallbackStateInvalid, http.StatusBadRequest},
	}
	for _, tc := range cases {
		cb := &fakeCallbackHandler{err: tc.err}
		r := newOIDCCallbackEngine(t, cb)
		rec := oidcCbGET(r, cbPath(uuid.New())+"?state=s&code=c")
		if rec.Code != tc.want {
			t.Errorf("err %v: status = %d, want %d", tc.err, rec.Code, tc.want)
		}
		if sc := rec.Header().Get("Set-Cookie"); sc != "" {
			t.Errorf("err %v: a cookie was set on a failed login: %q", tc.err, sc)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("err %v: a redirect was issued on a failed login: %q", tc.err, loc)
		}
	}
}

// A provider-reported ?error= → 400 login-failed, service NOT called.
func TestOIDCCallbackRoute_ProviderError(t *testing.T) {
	cb := &fakeCallbackHandler{}
	r := newOIDCCallbackEngine(t, cb)
	rec := oidcCbGET(r, cbPath(uuid.New())+"?error=access_denied&state=s")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if cb.calls != 0 {
		t.Errorf("service called %d times on provider error; want 0", cb.calls)
	}
}

// Missing state or code → 400, service NOT called.
func TestOIDCCallbackRoute_MissingParams(t *testing.T) {
	for _, q := range []string{"?state=s", "?code=c", ""} {
		cb := &fakeCallbackHandler{}
		r := newOIDCCallbackEngine(t, cb)
		rec := oidcCbGET(r, cbPath(uuid.New())+q)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("query %q: status = %d, want 400", q, rec.Code)
		}
		if cb.calls != 0 {
			t.Errorf("query %q: service called %d times; want 0", q, cb.calls)
		}
	}
}

// Malformed provider id → 400 before the service.
func TestOIDCCallbackRoute_InvalidProviderID(t *testing.T) {
	cb := &fakeCallbackHandler{}
	r := newOIDCCallbackEngine(t, cb)
	rec := oidcCbGET(r, "/api/v1/auth/idp/not-a-uuid/callback?state=s&code=c")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if cb.calls != 0 {
		t.Errorf("service called %d times for malformed id; want 0", cb.calls)
	}
}

// Nil service ⇒ route absent.
func TestOIDCCallbackRoute_AbsentWhenServiceNil(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterOIDCCallbackRoutes(r, OIDCCallbackHandlerDeps{})
	rec := oidcCbGET(r, cbPath(uuid.New())+"?state=s&code=c")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (route absent when service nil)", rec.Code)
	}
}

// Nil CookieSession ⇒ route absent (login cannot complete without the cookie tail).
func TestOIDCCallbackRoute_AbsentWhenCookieNil(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterOIDCCallbackRoutes(r, OIDCCallbackHandlerDeps{OIDCCallback: &fakeCallbackHandler{}})
	rec := oidcCbGET(r, cbPath(uuid.New())+"?state=s&code=c")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (route absent when CookieSession nil)", rec.Code)
	}
}
