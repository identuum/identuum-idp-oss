package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OSS-HARDENING-3 item 2: when the browser sign-in fails closed because the
// browser-session token cannot be issued (P2-8), the session LocalLogin had
// already created is revoked, as the upstream callback's refusal does since
// OSS-HARDENING-2 — a refused sign-in leaves nothing live — and the failure
// audit says so (session_revoked). Before, the session stayed live until it
// expired on its own (the handler's documented non-goal).

// newBrowserLoginWorld is newBrowserLoginEngine over the faithful in-memory
// session store (so the test can read the created session afterwards) with
// the session service wired for the revocation, as the router wires it.
func newBrowserLoginWorld(t *testing.T, browserTokens *service.BrowserSessionTokenService) (*gin.Engine, *audit.Recorder, *handlersSessionRepo) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	users := &inMemoryUserLookupForHandlers{byEmail: map[string][]*domain.User{}}
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uuid.New(), Email: "alice@example.com", OrganizationID: uuid.New(),
		PasswordHash: hashPasswordForHandlers(t, "correct"), EmailVerified: true,
	}}
	repo := newHandlersSessionRepo()
	sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	mfa := service.NewMFAVerifierService(nil, service.PlaintextTOTPSecretResolver{}, service.MFAVerifierOptions{Replay: testReplayGuardForHandlers()})
	login := service.NewLocalLoginService(nil, users, sessions, mfa)
	cookieSvc := service.NewCookieSessionService(nil, sessions, nil, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	rec := &audit.Recorder{}
	RegisterBrowserLoginRoutes(r, BrowserLoginHandlerDeps{
		LocalLogin:    login,
		CookieSession: cookieSvc,
		BrowserTokens: browserTokens,
		UserSession:   sessions,
		Audit:         rec,
	})
	return r, rec, repo
}

func TestBrowserLogin_TokenIssueError_RevokesTheCreatedSession(t *testing.T) {
	bts := service.NewBrowserSessionTokenService(nil, failingBrowserTokenRepo{}, service.BrowserSessionTokenServiceOptions{})
	r, rec, repo := newBrowserLoginWorld(t, bts)

	w := postBrowserLogin(t, r, "alice@example.com", "correct", "/dashboard")

	if w.Code != http.StatusServiceUnavailable || sessionCookie(w) != nil {
		t.Fatalf("status = %d cookie=%v; want the 503 refusal with no session cookie", w.Code, sessionCookie(w))
	}
	var failure *audit.Event
	for _, e := range rec.Events() {
		if e.Action == "user_session.browser_login.failure" {
			ev := e
			failure = &ev
		}
	}
	if failure == nil {
		t.Fatalf("user_session.browser_login.failure not recorded; events = %+v", rec.Events())
	}
	sid, err := uuid.Parse(failure.Metadata["session_id"].(string))
	if err != nil {
		t.Fatalf("failure session_id = %v", failure.Metadata["session_id"])
	}
	stored := repo.byID[sid]
	if stored == nil || stored.RevokedAt == nil || stored.IsValid {
		t.Fatalf("the session the sign-in created was left live after the refusal: %+v", stored)
	}
	if stored.RevokedReason == nil || *stored.RevokedReason != "browser_session_token_issue_failed" {
		t.Errorf("revoked reason = %v; want browser_session_token_issue_failed", stored.RevokedReason)
	}
	if failure.Metadata["reason"] != "browser_session_token_issue_failed" || failure.Metadata["session_revoked"] != true {
		t.Errorf("failure metadata = %+v; want reason browser_session_token_issue_failed and session_revoked true", failure.Metadata)
	}
}

func TestBrowserLogin_TokenIssueSuccess_SessionStaysLive(t *testing.T) {
	// Control: a working token store signs the person in and revokes nothing.
	bts := service.NewBrowserSessionTokenService(nil, newInMemoryBrowserTokenRepo(), service.BrowserSessionTokenServiceOptions{})
	r, rec, repo := newBrowserLoginWorld(t, bts)

	w := postBrowserLogin(t, r, "alice@example.com", "correct", "/dashboard")

	if w.Code != http.StatusSeeOther || sessionCookie(w) == nil {
		t.Fatalf("status = %d; want 303 with the session cookie", w.Code)
	}
	for _, e := range rec.Events() {
		if e.Action == "user_session.browser_login.failure" {
			t.Fatalf("a failure was audited on the success path: %+v", e.Metadata)
		}
	}
	if len(repo.byID) != 1 {
		t.Fatalf("sessions in the store = %d; want the one the sign-in created", len(repo.byID))
	}
	for _, s := range repo.byID {
		if s.RevokedAt != nil || !s.IsValid {
			t.Fatalf("the session was revoked on the success path: %+v", s)
		}
	}
}
