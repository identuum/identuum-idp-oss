package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// An upstream sign-in is bound to the browser that started it. Without that, an
// attacker who begins a sign-in at the upstream provider can hand the victim the
// callback link and have the victim's browser finish the attacker's sign-in.
// Initiation plants a short-lived host-only cookie holding the state; the
// callback accepts only a request that carries it. Each sign-in has its own
// cookie, named from its state, so a second sign-in started in the same
// browser does not void the first.

func bindingCookie(rec *httptest.ResponseRecorder, state string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == upstreamLoginCookieName(state) {
			return c
		}
	}
	return nil
}

func TestOIDCLogin_InitiationBindsTheStateToTheBrowser(t *testing.T) {
	pid := uuid.New()
	init := &fakeOIDCLoginInitiator{url: "https://provider.example/authorize?client_id=x&state=abc123&nonce=n"}
	r := newOIDCLoginEngine(t, init)
	rec := idpLoginGET(r, "/api/v1/auth/idp/"+pid.String()+"/login")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	c := bindingCookie(rec, "abc123")
	if c == nil {
		t.Fatal("no binding cookie planted at initiation")
	}
	if c.Value != "abc123" {
		t.Errorf("cookie value does not carry the state: %q", c.Value)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.MaxAge <= 0 || c.Path != "/" {
		t.Errorf("cookie = %+v; want HttpOnly, SameSite=Lax, host-only, finite life, path /", c)
	}
}

func TestOIDCLogin_NoBindingWithoutAState(t *testing.T) {
	for _, url := range []string{"https://provider.example/authorize?client_id=x", "://bad"} {
		r := newOIDCLoginEngine(t, &fakeOIDCLoginInitiator{url: url})
		rec := idpLoginGET(r, "/api/v1/auth/idp/"+uuid.New().String()+"/login")
		if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" || len(rec.Result().Cookies()) != 0 {
			t.Errorf("authorize URL %q: status=%d location=%q; want 500, no redirect, no cookie", url, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestOIDCCallback_RequiresTheBrowserThatStartedTheLogin(t *testing.T) {
	pid := uuid.New()
	get := func(cb *fakeCallbackHandler, state string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := newOIDCCallbackEngine(t, cb)
		req := httptest.NewRequest(http.MethodGet, cbPath(pid)+"?state="+state+"&code=c", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	t.Run("no cookie: refused, the state is not consumed", func(t *testing.T) {
		cb := &fakeCallbackHandler{result: okResult("/dashboard")}
		rec := get(cb, "abc123")
		if rec.Code != http.StatusBadRequest || cb.calls != 0 || rec.Header().Get("Location") != "" {
			t.Errorf("= %d calls=%d location=%q; want 400, service not called, no redirect", rec.Code, cb.calls, rec.Header().Get("Location"))
		}
	})
	t.Run("a cookie for another state: refused", func(t *testing.T) {
		cb := &fakeCallbackHandler{result: okResult("/dashboard")}
		rec := get(cb, "abc123", &http.Cookie{Name: upstreamLoginCookieName("someone-elses-state"), Value: "someone-elses-state"})
		if rec.Code != http.StatusBadRequest || cb.calls != 0 {
			t.Errorf("= %d calls=%d; want 400 and service not called", rec.Code, cb.calls)
		}
	})
	t.Run("this state's cookie holding another value: refused", func(t *testing.T) {
		cb := &fakeCallbackHandler{result: okResult("/dashboard")}
		rec := get(cb, "abc123", &http.Cookie{Name: upstreamLoginCookieName("abc123"), Value: "forged"})
		if rec.Code != http.StatusBadRequest || cb.calls != 0 {
			t.Errorf("= %d calls=%d; want 400 and service not called", rec.Code, cb.calls)
		}
	})
	t.Run("the matching cookie: signed in, binding cleared", func(t *testing.T) {
		cb := &fakeCallbackHandler{result: okResult("/dashboard")}
		rec := get(cb, "abc123", &http.Cookie{Name: upstreamLoginCookieName("abc123"), Value: "abc123"})
		if rec.Code != http.StatusFound || cb.calls != 1 {
			t.Fatalf("= %d calls=%d; want 302 and one service call", rec.Code, cb.calls)
		}
		if c := bindingCookie(rec, "abc123"); c == nil || c.MaxAge >= 0 {
			t.Errorf("binding cookie after success = %+v; want it expired", c)
		}
	})
}

func TestOIDCLogin_TwoSignInsInOneBrowserBothFinish(t *testing.T) {
	pid := uuid.New()
	var jar []*http.Cookie
	for _, state := range []string{"first-state", "second-state"} {
		r := newOIDCLoginEngine(t, &fakeOIDCLoginInitiator{url: "https://provider.example/authorize?client_id=x&state=" + state})
		rec := idpLoginGET(r, "/api/v1/auth/idp/"+pid.String()+"/login")
		jar = append(jar, rec.Result().Cookies()...)
	}
	for _, state := range []string{"first-state", "second-state"} {
		cb := &fakeCallbackHandler{result: okResult("/dashboard")}
		r := newOIDCCallbackEngine(t, cb)
		req := httptest.NewRequest(http.MethodGet, cbPath(pid)+"?state="+state+"&code=c", nil)
		seen := map[string]bool{}
		for i := len(jar) - 1; i >= 0; i-- { // a browser holds the newest cookie of each name
			if !seen[jar[i].Name] {
				seen[jar[i].Name] = true
				req.AddCookie(jar[i])
			}
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound || cb.calls != 1 {
			t.Errorf("callback of %s = %d calls=%d; want 302: the other sign-in voided it", state, rec.Code, cb.calls)
		}
	}
}
