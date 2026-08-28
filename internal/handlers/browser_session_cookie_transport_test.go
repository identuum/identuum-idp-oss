package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// The browser-login identuum_session cookie's Secure flag MUST follow the
// request transport (cookieSecureForRequest, via writeSessionCookie), matching
// the CSRF and auth cookies: false over http://localhost so the session
// actually returns on the next request — the interactive /oauth/consent and
// end_session flows depend on that — and true in production (ReleaseMode,
// non-localhost) so it stays https-only.
//
// CookieSessionService bakes a FAIL-SAFE Secure=true default (the runtime
// leaves AllowPlainHTTP unset — this test does too), so a plant site that skips
// the handler stamp ships a session cookie that never returns over http: that
// is the BROWSER-LOGIN-PLAINHTTP-1 defect, on the session cookie. Reverting
// HandleBrowserLoginSubmit's writeSessionCookie back to a raw http.SetCookie
// makes the localhost case Secure=true and fails this test.
// RULE: SESSION-COOKIE-TRANSPORT-SEC-1
func TestBrowserLoginSessionCookie_SecureFollowsTransport(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)

	users := &inMemoryUserLookupForHandlers{byEmail: map[string][]*domain.User{}}
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uuid.New(), Email: "alice@example.com",
		PasswordHash: hashPasswordForHandlers(t, "correct"), EmailVerified: true,
	}}
	sessions := service.NewUserSessionService(nil, newSessionRepoForHandlers(), service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	mfa := service.NewMFAVerifierService(nil, service.PlaintextTOTPSecretResolver{}, service.MFAVerifierOptions{})
	login := service.NewLocalLoginService(nil, users, sessions, mfa)
	// AllowPlainHTTP unset mirrors the runtime: the service bakes Secure=true;
	// the handler stamp is what makes the localhost transport work.
	cookieSvc := service.NewCookieSessionService(nil, sessions, nil, service.CookieSessionServiceOptions{})

	r := gin.New()
	RegisterBrowserLoginRoutes(r, BrowserLoginHandlerDeps{
		LocalLogin:    login,
		CookieSession: cookieSvc,
		Audit:         &audit.Recorder{},
	})

	sessionSecure := func(host string) (secure bool, found bool, status int) {
		form := url.Values{}
		form.Set("email", "alice@example.com")
		form.Set("password", "correct")
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/browser-login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = host
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		for _, ck := range w.Result().Cookies() {
			if ck.Name == "identuum_session" {
				return ck.Secure, true, w.Code
			}
		}
		return false, false, w.Code
	}

	localSecure, localFound, localStatus := sessionSecure("localhost:7113")
	if !localFound {
		t.Fatalf("no identuum_session cookie issued for the localhost login (status %d)", localStatus)
	}
	if localSecure {
		t.Fatal("identuum_session over http://localhost must be Secure=false so it returns on the next request")
	}

	prodSecure, prodFound, prodStatus := sessionSecure("idp.example.com")
	if !prodFound {
		t.Fatalf("no identuum_session cookie issued for the production login (status %d)", prodStatus)
	}
	if !prodSecure {
		t.Fatal("identuum_session in production (ReleaseMode, non-localhost) must be Secure=true")
	}
}
