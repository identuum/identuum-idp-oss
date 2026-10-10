package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// F5 (OSS-PRE-RELEASE-REVIEW-2026-10-10, OSS-REVIEW-FIXES-1; D-023 preserved,
// judge ruling (a)): an upstream sign-in establishes ONE credential family,
// chosen by the purpose the sign-in was started for, which the flow state
// carries as the stored return URL. A sign-in started from the console (a
// console return URL) sets only the console's access_token and refresh_token
// cookies; one started for an application's /authorize (a return URL at the
// authorize endpoint) sets only the IdP's own browser-session cookie. Before,
// the callback planted both families from the same session, so a console
// sign-in through a provider silently signed the person in to every
// application, and either sign-out cut the other's session (the operator
// guide's "Console and application sign-ins are separate").

const testAuthorizeReturnURL = "/api/v1/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Frp.example%2Fcb&response_type=code&scope=openid&state=s1"

func TestUpstreamSignInPurposeOf(t *testing.T) {
	for in, want := range map[string]upstreamSignInPurpose{
		"":                                  upstreamSignInForConsole,
		"/":                                 upstreamSignInForConsole,
		"/admin/users":                      upstreamSignInForConsole,
		"/api/v1/oauth/authorize":           upstreamSignInForApplication,
		testAuthorizeReturnURL:              upstreamSignInForApplication,
		"/api/v1/oauth/authorize/":          upstreamSignInForConsole,
		"/api/v1/oauth/authorize-not":       upstreamSignInForConsole,
		"/app?next=/api/v1/oauth/authorize": upstreamSignInForConsole,
	} {
		if got := upstreamSignInPurposeOf(in); got != want {
			t.Errorf("upstreamSignInPurposeOf(%q) = %v, want %v", in, got, want)
		}
	}
}

// A console sign-in: the console's two cookies, no browser-session cookie, and
// the browser-session token store is never consulted (a failing one does not
// refuse the sign-in).
func TestOIDCCallbackRoute_ConsoleSignInSetsOnlyTheConsoleCookies(t *testing.T) {
	res := okResult("/admin/users")
	failingBrowserTokens := service.NewBrowserSessionTokenService(nil, failingBrowserTokenRepo{}, service.BrowserSessionTokenServiceOptions{})
	r, rec, repo := newOIDCCallbackWorldWithMinter(t, &fakeCallbackHandler{result: res}, failingBrowserTokens, consoleMinter(t))
	seedCallbackSession(t, repo, res)

	w := oidcCbGET(r, cbPath(uuid.New())+"?state=s&code=c")

	if w.Code != http.StatusFound || w.Header().Get("Location") != "/admin/users" {
		t.Fatalf("status = %d to %q; want 302 to the console page", w.Code, w.Header().Get("Location"))
	}
	if oidcCallbackCookie(w, "access_token") == nil || oidcCallbackCookie(w, "refresh_token") == nil {
		t.Errorf("the console's access_token and refresh_token cookies were not both set")
	}
	if c := oidcCallbackCookie(w, "identuum_session"); c != nil {
		t.Errorf("a console sign-in planted the application browser-session cookie %+v; D-023: console sign-in never signs in to an application", c)
	}
	if stored := repo.byID[res.Session.ID]; stored == nil || stored.RevokedAt != nil {
		t.Fatalf("the session was revoked on the console path: %+v", stored)
	}
	for _, e := range rec.Events() {
		if e.Action == "auth.oidc_login.failure" {
			t.Fatalf("a failure was audited on the console path: %+v", e)
		}
	}
}

// An application sign-in (started for /authorize): the browser-session cookie
// alone, no console cookie, and the console minter is never consulted (a
// failing one does not refuse the sign-in).
func TestOIDCCallbackRoute_ApplicationSignInSetsOnlyTheBrowserSessionCookie(t *testing.T) {
	res := okResult(testAuthorizeReturnURL)
	bts := service.NewBrowserSessionTokenService(nil, newInMemoryBrowserTokenRepo(), service.BrowserSessionTokenServiceOptions{})
	r, rec, repo := newOIDCCallbackWorldWithMinter(t, &fakeCallbackHandler{result: res}, bts, failingConsoleMinter(t))
	seedCallbackSession(t, repo, res)

	w := oidcCbGET(r, cbPath(uuid.New())+"?state=s&code=c")

	if w.Code != http.StatusFound || w.Header().Get("Location") != testAuthorizeReturnURL {
		t.Fatalf("status = %d to %q; want 302 back to the authorize request", w.Code, w.Header().Get("Location"))
	}
	c := oidcCallbackCookie(w, "identuum_session")
	if c == nil || c.Value == "" || c.Value == res.RefreshToken {
		t.Fatalf("browser-session cookie = %+v; want the opaque token", c)
	}
	if resolved, err := bts.Resolve(context.Background(), c.Value); err != nil || resolved == nil {
		t.Fatalf("cookie value is not an opaque browser-session token (err=%v)", err)
	}
	if oidcCallbackCookie(w, "access_token") != nil || oidcCallbackCookie(w, "refresh_token") != nil {
		t.Errorf("an application sign-in planted the console's cookies; D-023: the console session is the console's own")
	}
	if stored := repo.byID[res.Session.ID]; stored == nil || stored.RevokedAt != nil {
		t.Fatalf("the session was revoked on the application path: %+v", stored)
	}
	for _, e := range rec.Events() {
		if e.Action == "auth.oidc_login.failure" {
			t.Fatalf("a failure was audited on the application path: %+v", e)
		}
	}
}
