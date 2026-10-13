package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Q-A1 (a), owner 2026-10-13: the upstream callback is a top-level browser
// navigation, so a refused sign-in never answers raw JSON. It redirects to
// the console sign-in page with ONE reason code from a closed list, and the
// console shows plain words for it. No cookie is set on any refusal.

// assertRefusalRedirect checks one refusal: 302 to /login?reason=<want>, no
// cookie, no body, not cached.
func assertRefusalRedirect(t *testing.T, label string, code int, header http.Header, body, want string) {
	t.Helper()
	if code != http.StatusFound {
		t.Errorf("%s: status = %d body=%q; want 302 to the console sign-in page", label, code, body)
		return
	}
	loc, err := url.Parse(header.Get("Location"))
	if err != nil || loc.Path != "/login" || loc.Host != "" || loc.Scheme != "" {
		t.Errorf("%s: Location = %q; want the relative console sign-in page /login", label, header.Get("Location"))
		return
	}
	if q := loc.Query(); len(q) != 1 || q.Get("reason") != want {
		t.Errorf("%s: Location query = %q; want only reason=%s", label, loc.RawQuery, want)
	}
	if sc := header.Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("%s: %d cookie(s) set on a refused sign-in", label, len(sc))
	}
	if strings.Contains(body, "{") {
		t.Errorf("%s: body = %q; want no JSON on a page load", label, body)
	}
	if cc := header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("%s: Cache-Control = %q; want no-store", label, cc)
	}
}

// oidcCbGETUnbound is a callback from a browser that does not carry the
// binding cookie planted at initiation.
func oidcCbGETUnbound(r http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// Every refusal the service can return maps to its reason code, with and
// without the console's minter wired.
// RULE: CALLBACK-REFUSAL-REDIRECT-1
func TestOIDCCallbackRoute_RefusalRedirectsWithReason(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{service.ErrCallbackValidationFailed, "sign_in_failed"},
		{service.ErrCallbackForbidden, "sign_in_not_permitted"},
		{service.ErrCallbackEmailNotShared, "email_not_shared"},
		{service.ErrCallbackInvitePending, "invitation_pending"},
		{service.ErrCallbackRegistrationPending, "registration_pending"},
		{service.ErrCallbackProvisionFailed, "sign_in_unavailable"},
		{service.ErrCallbackSessionFailed, "sign_in_unavailable"},
		{service.ErrCallbackDiscoveryFailed, "provider_unavailable"},
		{service.ErrCallbackExchangeFailed, "provider_unavailable"},
		{service.ErrCallbackStateInvalid, "sign_in_expired"},
	}
	for _, tc := range cases {
		for _, minter := range []*service.UserTokenService{nil, consoleMinter(t)} {
			cb := &fakeCallbackHandler{err: tc.err}
			rec := oidcCbGET(newOIDCCallbackEngineWith(t, cb, minter), cbPath(uuid.New())+"?state=s&code=c")
			assertRefusalRedirect(t, tc.err.Error(), rec.Code, rec.Header(), rec.Body.String(), tc.want)
		}
	}
}

// The refusals the handler decides before the service: a provider-reported
// error, missing parameters, a malformed provider id, and a callback in a
// browser that did not start the sign-in. The service is never called.
func TestOIDCCallbackRoute_EarlyRefusalRedirectsWithReason(t *testing.T) {
	cases := []struct {
		label, path, want string
		bound             bool
	}{
		{"provider error", cbPath(uuid.New()) + "?error=access_denied&state=s", "sign_in_failed", true},
		{"missing code", cbPath(uuid.New()) + "?state=s", "sign_in_expired", true},
		{"missing state", cbPath(uuid.New()) + "?code=c", "sign_in_expired", true},
		{"malformed provider id", "/api/v1/auth/idp/not-a-uuid/callback?state=s&code=c", "sign_in_failed", true},
		{"another browser", cbPath(uuid.New()) + "?state=s&code=c", "sign_in_expired", false},
	}
	for _, tc := range cases {
		cb := &fakeCallbackHandler{}
		r := newOIDCCallbackEngine(t, cb)
		var code int
		var header http.Header
		var body string
		if tc.bound {
			rec := oidcCbGET(r, tc.path)
			code, header, body = rec.Code, rec.Header(), rec.Body.String()
		} else {
			rec := oidcCbGETUnbound(r, tc.path)
			code, header, body = rec.Code, rec.Header(), rec.Body.String()
		}
		assertRefusalRedirect(t, tc.label, code, header, body, tc.want)
		if cb.calls != 0 {
			t.Errorf("%s: service called %d times; want 0", tc.label, cb.calls)
		}
	}
}

// The list is closed: these are every code the callback can send, and the
// documentation names the same set.
func TestOIDCCallbackRoute_RefusalReasonsAreAClosedList(t *testing.T) {
	want := []string{
		"email_not_shared",
		"invitation_pending",
		"provider_unavailable",
		"registration_pending",
		"sign_in_expired",
		"sign_in_failed",
		"sign_in_not_permitted",
		"sign_in_unavailable",
	}
	got := append([]string(nil), UpstreamSignInRefusalReasons...)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("UpstreamSignInRefusalReasons = %v; want %v", got, want)
	}
}
