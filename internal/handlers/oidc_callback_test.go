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
	return newOIDCCallbackEngineWith(t, cb, nil)
}

// newOIDCCallbackEngineWith mounts the callback with an optional access-token
// minter — the console's session (V4-025) is written only when one is wired.
func newOIDCCallbackEngineWith(t *testing.T, cb *fakeCallbackHandler, userToken *service.UserTokenService) *gin.Engine {
	t.Helper()
	r, _ := newOIDCCallbackEngineAudited(t, cb, userToken)
	return r
}

// newOIDCCallbackEngineAudited also returns the recorder the callback audits to.
func newOIDCCallbackEngineAudited(t *testing.T, cb *fakeCallbackHandler, userToken *service.UserTokenService) (*gin.Engine, *audit.Recorder) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// A real CookieSessionService (concrete type) so the completed-login tail
	// (Issue → Set-Cookie) runs exactly as production — same helper browser
	// login uses. AllowPlainHTTP keeps the test cookie inspectable.
	repo := newHandlersSessionRepo()
	sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	recorder := &audit.Recorder{}
	RegisterOIDCCallbackRoutes(r, OIDCCallbackHandlerDeps{OIDCCallback: cb, CookieSession: cookies, UserToken: userToken, Audit: recorder})
	return r, recorder
}

// OSS-CONFORMANCE-FIXES item 5 (OSS-UPSTREAM-CONSOLE-SESSION Q2, owner: yes):
// an upstream sign-in is findable by the one sign-in event every console
// sign-in records, user_session.login.success, carrying the method so an
// auditor cannot read it as a password sign-in; and both it and the upstream
// event name the person and their organization, so an org_admin can audit
// its own members' upstream sign-ins.
func TestOIDCCallbackRoute_SuccessIsAuditedAsASignInOfTheTenant(t *testing.T) {
	res := okResult("/")
	res.User.ID = res.Session.UserID
	res.User.OrganizationID = uuid.New()
	res.User.Role = domain.RoleOrgUser
	pid := uuid.New()
	cb := &fakeCallbackHandler{result: res}
	r, rec := newOIDCCallbackEngineAudited(t, cb, nil)
	if w := oidcCbGET(r, cbPath(pid)+"?state=s&code=c"); w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	var signIn, upstream *audit.Event
	for _, e := range rec.Events() {
		ev := e
		switch e.Action {
		case "user_session.login.success":
			signIn = &ev
		case "auth.oidc_login.success":
			upstream = &ev
		}
	}
	if signIn == nil {
		t.Fatalf("user_session.login.success not recorded; events = %+v", rec.Events())
	}
	if signIn.Metadata["method"] != "oidc_upstream" || signIn.Metadata["provider_id"] != pid.String() ||
		signIn.Metadata["user_id"] != res.User.ID.String() || signIn.Metadata["session_id"] != res.Session.ID.String() {
		t.Errorf("sign-in event metadata = %+v; want method=oidc_upstream, provider_id, user_id and session_id", signIn.Metadata)
	}
	for _, ev := range []*audit.Event{signIn, upstream} {
		if ev == nil {
			t.Fatalf("auth.oidc_login.success not recorded")
		}
		if ev.ActorType != audit.ActorTypeUser || ev.ActorID != res.User.ID || ev.ActorEmail != res.User.Email || ev.ActorRole != string(domain.RoleOrgUser) || ev.OrganizationID != res.User.OrganizationID {
			t.Errorf("%s: actor = %s/%s %q %q org %s; want the signed-in user of organization %s", ev.Action, ev.ActorType, ev.ActorID, ev.ActorEmail, ev.ActorRole, ev.OrganizationID, res.User.OrganizationID)
		}
	}
	if upstream.Metadata["provider_id"] != pid.String() || upstream.Metadata["session_id"] != res.Session.ID.String() {
		t.Errorf("upstream event metadata = %+v", upstream.Metadata)
	}
}

// consoleMinter is a real UserTokenService over a test signing key: the same
// minter the password login's handler is given.
func consoleMinter(t *testing.T) *service.UserTokenService {
	t.Helper()
	return service.NewUserTokenService(nil, userTokenKeyProvider(t), service.UserTokenServiceOptions{Issuer: "https://idp.test", AccessTokenTTL: 15 * time.Minute})
}

func oidcCallbackCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func oidcCbGET(r *gin.Engine, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	// The browser that started the sign-in carries the binding cookie for its state.
	if state := req.URL.Query().Get("state"); state != "" {
		req.AddCookie(&http.Cookie{Name: upstreamLoginCookieName(state), Value: state})
	}
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
	// With and without the console's minter: a refused sign-in writes neither
	// the browser-session cookie nor the console's two.
	for _, tc := range cases {
		for _, minter := range []*service.UserTokenService{nil, consoleMinter(t)} {
			cb := &fakeCallbackHandler{err: tc.err}
			r := newOIDCCallbackEngineWith(t, cb, minter)
			rec := oidcCbGET(r, cbPath(uuid.New())+"?state=s&code=c")
			if rec.Code != tc.want {
				t.Errorf("err %v: status = %d, want %d", tc.err, rec.Code, tc.want)
			}
			if sc := rec.Header().Get("Set-Cookie"); sc != "" {
				t.Errorf("err %v (minter %v): a cookie was set on a failed login: %q", tc.err, minter != nil, sc)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("err %v: a redirect was issued on a failed login: %q", tc.err, loc)
			}
		}
	}
}

// OSS-UPSTREAM-CONSOLE-SESSION (V4-025, F-1): with the minter wired, a console
// sign-in's success answer carries the console's access_token and
// refresh_token cookies, shaped exactly as POST /api/v1/auth/login shapes them
// without "remember me" — the same writer, so the attributes cannot drift
// apart — and, since OSS-REVIEW-FIXES-1 (F5, D-023), NOT the application
// browser-session cookie.
func TestOIDCCallbackRoute_SuccessSetsTheConsoleCookies(t *testing.T) {
	res := okResult("/")
	res.User.ID = res.Session.UserID
	cb := &fakeCallbackHandler{result: res}
	r := newOIDCCallbackEngineWith(t, cb, consoleMinter(t))
	rec := oidcCbGET(r, cbPath(uuid.New())+"?state=s&code=c")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("status = %d to %q; want 302 to /", rec.Code, rec.Header().Get("Location"))
	}
	if c := oidcCallbackCookie(rec, "identuum_session"); c != nil {
		t.Errorf("a console sign-in planted the application browser-session cookie %+v (D-023)", c)
	}
	access := oidcCallbackCookie(rec, "access_token")
	if access == nil || access.Value == "" || access.Path != "/" || !access.HttpOnly || access.SameSite != http.SameSiteLaxMode || access.MaxAge != accessTokenCookieMaxAgeSec {
		t.Errorf("access_token cookie = %+v; want a signed token at Path=/, HttpOnly, Lax, MaxAge %d (the password login's shape)", access, accessTokenCookieMaxAgeSec)
	}
	refresh := oidcCallbackCookie(rec, "refresh_token")
	if refresh == nil || refresh.Value != res.RefreshToken || refresh.Path != refreshTokenCookiePath || !refresh.HttpOnly || refresh.SameSite != http.SameSiteLaxMode || refresh.MaxAge != 0 {
		t.Errorf("refresh_token cookie = %+v; want the session's refresh token at Path=%s, HttpOnly, Lax, a session cookie (no remember-me)", refresh, refreshTokenCookiePath)
	}
	// The password login writes the same two through setAuthCookies: compare
	// attribute for attribute against a direct write with the same inputs.
	want := httptest.NewRecorder()
	ctl, _ := gin.CreateTestContext(want)
	ctl.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	setAuthCookies(ctl, access.Value, res.RefreshToken, false)
	for _, name := range []string{"access_token", "refresh_token"} {
		got, exp := oidcCallbackCookie(rec, name), oidcCallbackCookie(want, name)
		if got.Path != exp.Path || got.HttpOnly != exp.HttpOnly || got.SameSite != exp.SameSite || got.Secure != exp.Secure || got.MaxAge != exp.MaxAge {
			t.Errorf("%s cookie differs from the password login's: got %+v, want %+v", name, got, exp)
		}
	}
	// No token rides in the redirect.
	if loc := rec.Header().Get("Location"); strings.Contains(loc, access.Value) || strings.Contains(loc, res.RefreshToken) {
		t.Errorf("a token rides in the redirect target")
	}
}

// Without the minter nothing changes: the browser-session cookie alone, as
// before this slice (an edition that mounts no console).
func TestOIDCCallbackRoute_WithoutMinterPlantsOnlyTheBrowserSessionCookie(t *testing.T) {
	cb := &fakeCallbackHandler{result: okResult("/")}
	rec := oidcCbGET(newOIDCCallbackEngine(t, cb), cbPath(uuid.New())+"?state=s&code=c")
	if rec.Code != http.StatusFound || oidcCallbackCookie(rec, "identuum_session") == nil {
		t.Fatalf("status = %d; want 302 with the browser-session cookie", rec.Code)
	}
	if oidcCallbackCookie(rec, "access_token") != nil || oidcCallbackCookie(rec, "refresh_token") != nil {
		t.Errorf("console cookies were written with no minter wired")
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
