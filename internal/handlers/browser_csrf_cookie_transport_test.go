package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// The browser-login CSRF cookie's Secure flag MUST follow the request
// transport (cookieSecureForRequest), matching the auth session cookies: true
// in production (ReleaseMode, non-localhost) so it is https-only, false over
// http://localhost so the double-submit cookie actually returns and the form
// works in local dev. Before THE-LAST-DEFECT the cookie was statically
// Secure=true (allowPlainHTTP wired to nothing), so it never returned over
// http and every submit 403'd csrf_failed (BROWSER-LOGIN-PLAINHTTP-1).
// Reverting the handler to write the cookie without the transport stamp makes
// the localhost case Secure=true and fails this test.
// RULE: CSRF-COOKIE-TRANSPORT-SECURE-1
func TestBrowserLoginCSRFCookie_SecureFollowsTransport(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	csrf := service.NewBrowserCSRFService(nil, service.BrowserCSRFServiceOptions{
		Secret: []byte("0123456789abcdef0123456789abcdef"),
	})
	deps := BrowserLoginHandlerDeps{CSRF: csrf}
	r := gin.New()
	r.GET("/api/v1/auth/browser-login", HandleBrowserLoginForm(deps))

	csrfSecure := func(host string) (bool, bool) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/browser-login", nil)
		req.Host = host
		r.ServeHTTP(w, req)
		for _, ck := range w.Result().Cookies() {
			if ck.Name == csrf.CookieName() {
				return ck.Secure, true
			}
		}
		return false, false
	}

	localSecure, localFound := csrfSecure("localhost:7113")
	if !localFound {
		t.Fatal("no CSRF cookie issued for the localhost request")
	}
	if localSecure {
		t.Fatal("CSRF cookie over http://localhost must be Secure=false so it returns on the form submit")
	}

	prodSecure, prodFound := csrfSecure("idp.example.com")
	if !prodFound {
		t.Fatal("no CSRF cookie issued for the production request")
	}
	if !prodSecure {
		t.Fatal("CSRF cookie in production (ReleaseMode, non-localhost) must be Secure=true")
	}
}
