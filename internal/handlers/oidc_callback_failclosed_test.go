package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OSS-HARDENING-2 item 2: when BrowserTokens is wired and Issue fails, the
// upstream callback fails closed exactly as the browser login does (P2-8):
// no cookie of any kind, no redirect, 503 "temporarily unavailable", a
// failure audited and never a success — and, beyond the browser login, the
// session the callback service created is revoked, so nothing live is left.
// Since OSS-REVIEW-FIXES-1 (F5) the browser-session token is minted only for
// a sign-in started for an application's /authorize, so these sign-ins
// return there (oidcCallbackAuthorizeReturn).

const oidcCallbackAuthorizeReturn = "/api/v1/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Frp.example%2Fdashboard&response_type=code&scope=openid&state=s2"

// newOIDCCallbackWorld builds the callback route over a real in-memory session
// store (so the test can seed the session the callback service "created" and
// read its state afterwards), the console minter, and the given browser-token
// indirection.
func newOIDCCallbackWorld(t *testing.T, cb *fakeCallbackHandler, browserTokens *service.BrowserSessionTokenService) (*gin.Engine, *audit.Recorder, *handlersSessionRepo) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	repo := newHandlersSessionRepo()
	sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	recorder := &audit.Recorder{}
	RegisterOIDCCallbackRoutes(r, OIDCCallbackHandlerDeps{
		OIDCCallback:  cb,
		CookieSession: cookies,
		BrowserTokens: browserTokens,
		UserToken:     consoleMinter(t),
		UserSession:   sessions,
		Audit:         recorder,
	})
	return r, recorder, repo
}

func seedCallbackSession(t *testing.T, repo *handlersSessionRepo, res *service.OIDCCallbackResult) {
	t.Helper()
	res.User.ID = res.Session.UserID
	res.User.OrganizationID = uuid.New()
	res.User.Role = domain.RoleOrgUser
	res.Session.IsValid = true
	if _, err := repo.Create(context.Background(), res.Session); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func TestOIDCCallbackRoute_TokenIssueError_FailsClosed(t *testing.T) {
	res := okResult(oidcCallbackAuthorizeReturn)
	pid := uuid.New()
	bts := service.NewBrowserSessionTokenService(nil, failingBrowserTokenRepo{}, service.BrowserSessionTokenServiceOptions{})
	r, rec, repo := newOIDCCallbackWorld(t, &fakeCallbackHandler{result: res}, bts)
	seedCallbackSession(t, repo, res)

	w := oidcCbGET(r, cbPath(pid)+"?state=s&code=c")

	if sc := w.Header().Values("Set-Cookie"); len(sc) != 0 {
		t.Fatalf("fail-closed VIOLATED: %d cookie(s) written on a refused sign-in", len(sc))
	}
	if w.Code == http.StatusFound || w.Header().Get("Location") != "" {
		t.Fatalf("fail-closed VIOLATED: success redirect (code=%d, location=%q)", w.Code, w.Header().Get("Location"))
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%q", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "temporarily unavailable") || strings.Contains(body, res.RefreshToken) {
		t.Fatalf("body = %q; want the browser login's temporarily-unavailable text and no token", body)
	}
	// The session the callback service created is revoked, not left live.
	stored := repo.byID[res.Session.ID]
	if stored == nil || stored.RevokedAt == nil || stored.IsValid {
		t.Fatalf("the created session was left live: %+v", stored)
	}
	// Audit: a failure naming the reason and the session, never a sign-in.
	var sawFailure bool
	for _, e := range rec.Events() {
		switch e.Action {
		case "user_session.login.success", "auth.oidc_login.success":
			t.Fatalf("audit recorded a SUCCESS (%s) on the fail-closed path", e.Action)
		case "auth.oidc_login.failure":
			if e.Outcome != "error" || e.Metadata["reason"] != "browser_session_token_issue_failed" ||
				e.Metadata["session_id"] != res.Session.ID.String() || e.Metadata["provider_id"] != pid.String() ||
				e.Metadata["session_revoked"] != true {
				t.Fatalf("failure event = outcome %q metadata %+v; want error, reason browser_session_token_issue_failed, session_id, provider_id, session_revoked true", e.Outcome, e.Metadata)
			}
			sawFailure = true
		}
	}
	if !sawFailure {
		t.Fatalf("audit did not record auth.oidc_login.failure; events = %+v", rec.Events())
	}
}

func TestOIDCCallbackRoute_TokenIssueSuccess_OpaqueCookie(t *testing.T) {
	// Control: with a working token store the application sign-in completes
	// as before — the browser-session cookie is the opaque token, the
	// redirect goes to the stored return URL, the session stays live; the
	// console cookies belong to a console sign-in and are not set (F5).
	res := okResult(oidcCallbackAuthorizeReturn)
	bts := service.NewBrowserSessionTokenService(nil, newInMemoryBrowserTokenRepo(), service.BrowserSessionTokenServiceOptions{})
	r, rec, repo := newOIDCCallbackWorld(t, &fakeCallbackHandler{result: res}, bts)
	seedCallbackSession(t, repo, res)

	w := oidcCbGET(r, cbPath(uuid.New())+"?state=s&code=c")

	if w.Code != http.StatusFound || w.Header().Get("Location") != oidcCallbackAuthorizeReturn {
		t.Fatalf("status = %d to %q; want 302 back to the authorize request", w.Code, w.Header().Get("Location"))
	}
	c := oidcCallbackCookie(w, "identuum_session")
	if c == nil || c.Value == "" || c.Value == res.RefreshToken {
		t.Fatalf("browser-session cookie = %+v; want the opaque token, never the raw refresh token", c)
	}
	if resolved, err := bts.Resolve(context.Background(), c.Value); err != nil || resolved == nil {
		t.Fatalf("cookie value is not an opaque browser-session token (err=%v)", err)
	}
	if oidcCallbackCookie(w, "access_token") != nil || oidcCallbackCookie(w, "refresh_token") != nil {
		t.Fatalf("the console cookies were set on an application sign-in (D-023)")
	}
	if stored := repo.byID[res.Session.ID]; stored == nil || stored.RevokedAt != nil {
		t.Fatalf("the session was revoked on the success path: %+v", stored)
	}
	for _, e := range rec.Events() {
		if e.Action == "auth.oidc_login.failure" {
			t.Fatalf("a failure was audited on the success path: %+v", e)
		}
	}
}
