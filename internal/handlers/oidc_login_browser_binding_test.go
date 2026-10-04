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
// callback accepts only a request that carries it.

func bindingCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == upstreamLoginCookie {
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
	c := bindingCookie(rec)
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
		if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" || bindingCookie(rec) != nil {
			t.Errorf("authorize URL %q: status=%d location=%q; want 500, no redirect, no cookie", url, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestOIDCCallback_RequiresTheBrowserThatStartedTheLogin(t *testing.T) {
	pid := uuid.New()
	get := func(cb *fakeCallbackHandler, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := newOIDCCallbackEngine(t, cb)
		req := httptest.NewRequest(http.MethodGet, cbPath(pid)+"?state=abc123&code=c", nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	t.Run("no cookie: refused, the state is not consumed", func(t *testing.T) {
		cb := &fakeCallbackHandler{result: okResult("/dashboard")}
		rec := get(cb, nil)
		if rec.Code != http.StatusBadRequest || cb.calls != 0 || rec.Header().Get("Location") != "" {
			t.Errorf("= %d calls=%d location=%q; want 400, service not called, no redirect", rec.Code, cb.calls, rec.Header().Get("Location"))
		}
	})
	t.Run("a cookie for another state: refused", func(t *testing.T) {
		cb := &fakeCallbackHandler{result: okResult("/dashboard")}
		rec := get(cb, &http.Cookie{Name: upstreamLoginCookie, Value: "someone-elses-state"})
		if rec.Code != http.StatusBadRequest || cb.calls != 0 {
			t.Errorf("= %d calls=%d; want 400 and service not called", rec.Code, cb.calls)
		}
	})
	t.Run("the matching cookie: signed in, binding cleared", func(t *testing.T) {
		cb := &fakeCallbackHandler{result: okResult("/dashboard")}
		rec := get(cb, &http.Cookie{Name: upstreamLoginCookie, Value: "abc123"})
		if rec.Code != http.StatusFound || cb.calls != 1 {
			t.Fatalf("= %d calls=%d; want 302 and one service call", rec.Code, cb.calls)
		}
		if c := bindingCookie(rec); c == nil || c.MaxAge >= 0 {
			t.Errorf("binding cookie after success = %+v; want it expired", c)
		}
	})
}
