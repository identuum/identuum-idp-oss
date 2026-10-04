package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Owner ruling (v0.9.5): the account-wide slow-down answers 429
// login_throttled with Retry-After on the JSON login, and the browser form
// says how to proceed. Known and unknown accounts get the same answer.

func TestLoginRoute_AccountSlowDownIs429WithRetryAfter(t *testing.T) {
	seed := func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["alice@example.com"] = []*domain.User{{
			ID: uuid.New(), Email: "alice@example.com",
			PasswordHash: hashPasswordForHandlers(t, "correct"), EmailVerified: true,
		}}
	}
	// 7 failures from any address: the next attempt waits 4 s after the last.
	r := newAuthEngineWithRisk(t, seed, scriptedLoginAttemptRepo{anyIP: 7})
	for _, email := range []string{"alice@example.com", "nobody@example.com"} {
		w := postLogin(t, r, email, "correct")
		if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"login_throttled"`) {
			t.Fatalf("%s: status = %d body = %s, want 429 login_throttled", email, w.Code, w.Body.String())
		}
		secs, err := strconv.Atoi(w.Header().Get("Retry-After"))
		if err != nil || secs < 1 || secs > 4 {
			t.Errorf("%s: Retry-After = %q, want 1..4 seconds", email, w.Header().Get("Retry-After"))
		}
	}
}

func TestBrowserLogin_AccountSlowDownSaysToWait(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	users := &inMemoryUserLookupForHandlers{byEmail: map[string][]*domain.User{}}
	sessions := service.NewUserSessionService(nil, newSessionRepoForHandlers(), service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	mfa := service.NewMFAVerifierService(nil, service.PlaintextTOTPSecretResolver{}, service.MFAVerifierOptions{Replay: testReplayGuardForHandlers()})
	risk := service.NewLoginRiskService(nil, scriptedLoginAttemptRepo{anyIP: 6}, service.LoginRiskServiceOptions{})
	login := service.NewLocalLoginService(nil, users, sessions, mfa).WithLoginRiskService(risk)
	RegisterBrowserLoginRoutes(r, BrowserLoginHandlerDeps{
		LocalLogin:    login,
		CookieSession: service.NewCookieSessionService(nil, sessions, nil, service.CookieSessionServiceOptions{AllowPlainHTTP: true}),
		Audit:         &audit.Recorder{},
	})

	w := postBrowserLogin(t, r, "alice@example.com", "whatever", "/dashboard")
	loc := w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || !strings.Contains(loc, "error=login_throttled") {
		t.Fatalf("status = %d location = %q, want a redirect with error=login_throttled", w.Code, loc)
	}
	page := httptest.NewRecorder()
	r.ServeHTTP(page, httptest.NewRequest(http.MethodGet, loc, nil))
	if !strings.Contains(page.Body.String(), "Too many failed sign-ins") {
		t.Errorf("the form does not say to wait: %s", page.Body.String())
	}
}
