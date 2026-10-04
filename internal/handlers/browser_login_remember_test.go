package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func postBrowserLoginRemember(t *testing.T, r *gin.Engine, remember string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("email", "alice@example.com")
	form.Set("password", "correct")
	form.Set("return_to", "/dashboard")
	if remember != "" {
		form.Set("remember_me", remember)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// "Remember me" decides whether the browser keeps the session cookie after it
// closes. Unticked, the cookie has no expiry and ends with the browser session
// (the server-side session still ends at its own time); ticked, it is persistent.
func TestBrowserLogin_TheSessionCookieIsPersistentOnlyWhenRemembered(t *testing.T) {
	r, _ := newBrowserLoginEngine(t, nil)

	forgotten := sessionCookie(postBrowserLoginRemember(t, r, ""))
	if forgotten == nil {
		t.Fatal("no session cookie planted")
	}
	if forgotten.MaxAge != 0 || !forgotten.Expires.IsZero() {
		t.Errorf("unticked remember me: cookie Max-Age=%d Expires=%v; want a browser-session cookie with neither", forgotten.MaxAge, forgotten.Expires)
	}

	remembered := sessionCookie(postBrowserLoginRemember(t, r, "1"))
	if remembered == nil {
		t.Fatal("no session cookie planted")
	}
	if remembered.MaxAge <= 0 || remembered.Expires.IsZero() {
		t.Errorf("ticked remember me: cookie Max-Age=%d Expires=%v; want a persistent cookie", remembered.MaxAge, remembered.Expires)
	}
}
