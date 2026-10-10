package handlers

import (
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

// F2 (OSS-PRE-RELEASE-REVIEW-2026-10-10, OSS-REVIEW-FIXES-1): the console's
// credentials are minted BEFORE any cookie or redirect, and a mint that fails
// refuses the sign-in exactly as a browser-session token that cannot issue
// does. Before, the callback wrote the browser-session and refresh cookies,
// swallowed the failed access-token mint, and redirected "signed in": a jar
// that still held user A's valid access_token cookie then validated as A in
// the console while the audit said B had signed in.

// failingConsoleMinter is a real UserTokenService over a key provider that
// holds no signing key, so IssueForSession fails as a key-store read does.
func failingConsoleMinter(t *testing.T) *service.UserTokenService {
	t.Helper()
	return service.NewUserTokenService(nil, &handlerKeyProvider{}, service.UserTokenServiceOptions{Issuer: "https://idp.test", AccessTokenTTL: 15 * time.Minute})
}

// newOIDCCallbackWorldWithMinter is newOIDCCallbackWorld with the console
// minter chosen by the test.
func newOIDCCallbackWorldWithMinter(t *testing.T, cb *fakeCallbackHandler, browserTokens *service.BrowserSessionTokenService, minter *service.UserTokenService) (*gin.Engine, *audit.Recorder, *handlersSessionRepo) {
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
		UserToken:     minter,
		UserSession:   sessions,
		Audit:         recorder,
	})
	return r, recorder, repo
}

// oidcCbGETWithJar is oidcCbGET for a browser whose jar already holds cookies.
func oidcCbGETWithJar(r *gin.Engine, path string, jar ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if state := req.URL.Query().Get("state"); state != "" {
		req.AddCookie(&http.Cookie{Name: upstreamLoginCookieName(state), Value: state})
	}
	for _, c := range jar {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

const userAConsoleToken = "console-access-token-of-user-a"

func userAJar() []*http.Cookie {
	return []*http.Cookie{
		{Name: "access_token", Value: userAConsoleToken},
		{Name: "refresh_token", Value: "console-refresh-token-of-user-a"},
	}
}

func TestOIDCCallbackRoute_ConsoleMintFailure_RefusesAndNeverLeavesTheOldUser(t *testing.T) {
	for _, tc := range []struct {
		name string
		jar  []*http.Cookie
	}{
		{"a jar holding user A's console cookies", userAJar()},
		{"an empty jar (control)", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := okResult("/dashboard")
			pid := uuid.New()
			bts := service.NewBrowserSessionTokenService(nil, newInMemoryBrowserTokenRepo(), service.BrowserSessionTokenServiceOptions{})
			r, rec, repo := newOIDCCallbackWorldWithMinter(t, &fakeCallbackHandler{result: res}, bts, failingConsoleMinter(t))
			seedCallbackSession(t, repo, res)

			w := oidcCbGETWithJar(r, cbPath(pid)+"?state=s&code=c", tc.jar...)

			// A refusal, never a half sign-in: no cookie of any kind (so
			// nothing of B is planted beside A), no redirect, 503.
			if sc := w.Header().Values("Set-Cookie"); len(sc) != 0 {
				t.Fatalf("fail-closed VIOLATED: %d cookie(s) written when the console mint failed: %q", len(sc), sc)
			}
			if w.Code == http.StatusFound || w.Header().Get("Location") != "" {
				t.Fatalf("fail-closed VIOLATED: success redirect (code=%d, location=%q) over a failed console mint", w.Code, w.Header().Get("Location"))
			}
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503; body=%q", w.Code, w.Body.String())
			}
			if body := w.Body.String(); body == "" || containsAny(body, res.RefreshToken, userAConsoleToken) {
				t.Fatalf("body = %q; want the temporarily-unavailable text and no token", body)
			}
			// B's session is revoked, not left live behind a refusal.
			if stored := repo.byID[res.Session.ID]; stored == nil || stored.RevokedAt == nil || stored.IsValid {
				t.Fatalf("the created session was left live: %+v", stored)
			}
			// Audit: a failure naming the reason and the session; never a sign-in of B.
			var sawFailure bool
			for _, e := range rec.Events() {
				switch e.Action {
				case "user_session.login.success", "auth.oidc_login.success":
					t.Fatalf("audit recorded a SUCCESS (%s) over a failed console mint", e.Action)
				case "auth.oidc_login.failure":
					if e.Outcome != "error" || e.Metadata["reason"] != "console_token_issue_failed" ||
						e.Metadata["session_id"] != res.Session.ID.String() || e.Metadata["provider_id"] != pid.String() ||
						e.Metadata["session_revoked"] != true {
						t.Fatalf("failure event = outcome %q metadata %+v; want error, reason console_token_issue_failed, session_id, provider_id, session_revoked true", e.Outcome, e.Metadata)
					}
					sawFailure = true
				}
			}
			if !sawFailure {
				t.Fatalf("audit did not record auth.oidc_login.failure; events = %+v", rec.Events())
			}
		})
	}
}

// Control: with a working minter the sign-in as B REPLACES A's console
// cookies, so the console validates B, never A.
func TestOIDCCallbackRoute_ConsoleMintSuccess_ReplacesTheOldUsersCookies(t *testing.T) {
	res := okResult("/dashboard")
	bts := service.NewBrowserSessionTokenService(nil, newInMemoryBrowserTokenRepo(), service.BrowserSessionTokenServiceOptions{})
	r, _, repo := newOIDCCallbackWorldWithMinter(t, &fakeCallbackHandler{result: res}, bts, consoleMinter(t))
	seedCallbackSession(t, repo, res)

	w := oidcCbGETWithJar(r, cbPath(uuid.New())+"?state=s&code=c", userAJar()...)

	if w.Code != http.StatusFound || w.Header().Get("Location") != "/dashboard" {
		t.Fatalf("status = %d to %q; want 302 to /dashboard", w.Code, w.Header().Get("Location"))
	}
	access := oidcCallbackCookie(w, "access_token")
	if access == nil || access.Value == "" || access.Value == userAConsoleToken {
		t.Fatalf("access_token cookie = %+v; want B's freshly minted token replacing A's", access)
	}
	if refresh := oidcCallbackCookie(w, "refresh_token"); refresh == nil || refresh.Value != res.RefreshToken {
		t.Fatalf("refresh_token cookie = %+v; want B's refresh token replacing A's", refresh)
	}
	if stored := repo.byID[res.Session.ID]; stored == nil || stored.RevokedAt != nil {
		t.Fatalf("the session was revoked on the success path: %+v", stored)
	}
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(s, n) {
			return true
		}
	}
	return false
}
