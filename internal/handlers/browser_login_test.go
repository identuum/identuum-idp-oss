package handlers

import (
	"context"
	"errors"
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
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// ---------- BrowserSessionTokenRepository test doubles ----------

// failingBrowserTokenRepo makes Issue fail: Insert returns an error, so
// BrowserSessionTokenService.Issue returns (nil, err) — driving the P2-8
// fail-closed path.
type failingBrowserTokenRepo struct{}

func (failingBrowserTokenRepo) Insert(context.Context, *domain.BrowserSessionToken) error {
	return errors.New("simulated browser_session_tokens insert outage")
}
func (failingBrowserTokenRepo) GetByTokenHash(context.Context, string, time.Time) (*domain.BrowserSessionToken, error) {
	return nil, nil
}
func (failingBrowserTokenRepo) RevokeByTokenHash(context.Context, string, time.Time) error {
	return nil
}
func (failingBrowserTokenRepo) RevokeBySessionID(context.Context, uuid.UUID, time.Time) error {
	return nil
}
func (failingBrowserTokenRepo) DeleteExpiredBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}

var _ repository.BrowserSessionTokenRepository = failingBrowserTokenRepo{}

// inMemoryBrowserTokenRepo is a minimal working store: Insert keeps the
// row keyed by token_hash, GetByTokenHash returns it while active. Enough
// for Issue to succeed and Resolve to round-trip the opaque cookie.
type inMemoryBrowserTokenRepo struct {
	rows map[string]*domain.BrowserSessionToken
}

func newInMemoryBrowserTokenRepo() *inMemoryBrowserTokenRepo {
	return &inMemoryBrowserTokenRepo{rows: map[string]*domain.BrowserSessionToken{}}
}
func (r *inMemoryBrowserTokenRepo) Insert(_ context.Context, t *domain.BrowserSessionToken) error {
	cp := *t
	r.rows[t.TokenHash] = &cp
	return nil
}
func (r *inMemoryBrowserTokenRepo) GetByTokenHash(_ context.Context, hash string, now time.Time) (*domain.BrowserSessionToken, error) {
	row, ok := r.rows[hash]
	if !ok || row.RevokedAt != nil || !row.ExpiresAt.After(now) {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}
func (r *inMemoryBrowserTokenRepo) RevokeByTokenHash(context.Context, string, time.Time) error {
	return nil
}
func (r *inMemoryBrowserTokenRepo) RevokeBySessionID(context.Context, uuid.UUID, time.Time) error {
	return nil
}
func (r *inMemoryBrowserTokenRepo) DeleteExpiredBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}

var _ repository.BrowserSessionTokenRepository = (*inMemoryBrowserTokenRepo)(nil)

// ---------- harness ----------

// newBrowserLoginEngine wires a full browser-login handler with a
// configurable BrowserTokens (may be nil). Returns the engine + the audit
// recorder so tests can inspect the emitted event.
func newBrowserLoginEngine(t *testing.T, browserTokens *service.BrowserSessionTokenService) (*gin.Engine, *audit.Recorder) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	users := &inMemoryUserLookupForHandlers{byEmail: map[string][]*domain.User{}}
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uuid.New(), Email: "alice@example.com",
		PasswordHash: hashPasswordForHandlers(t, "correct"), EmailVerified: true,
	}}
	sessions := service.NewUserSessionService(nil, newSessionRepoForHandlers(), service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	mfa := service.NewMFAVerifierService(nil, service.PlaintextTOTPSecretResolver{}, service.MFAVerifierOptions{})
	login := service.NewLocalLoginService(nil, users, sessions, mfa)
	cookieSvc := service.NewCookieSessionService(nil, sessions, nil, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	rec := &audit.Recorder{}
	RegisterBrowserLoginRoutes(r, BrowserLoginHandlerDeps{
		LocalLogin:    login,
		CookieSession: cookieSvc,
		BrowserTokens: browserTokens,
		Audit:         rec,
	})
	return r, rec
}

func postBrowserLogin(t *testing.T, r *gin.Engine, email, password, returnTo string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)
	form.Set("return_to", returnTo)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func sessionCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == "identuum_session" {
			return c
		}
	}
	return nil
}

// ---------- P2-8: fail closed on token issuance failure ----------

// TestBrowserLogin_TokenIssueError_FailsClosed is the core P2-8 test:
// with BrowserTokens wired and Issue erroring, the handler MUST NOT plant
// a session cookie, MUST NOT redirect to return_to as a success, and MUST
// audit a failure (not success). TEETH: restore the fall-through
// (cookieValue stays result.RefreshToken) and this fails — a success
// redirect + session cookie reappear.
func TestBrowserLogin_TokenIssueError_FailsClosed(t *testing.T) {
	bts := service.NewBrowserSessionTokenService(nil, failingBrowserTokenRepo{}, service.BrowserSessionTokenServiceOptions{})
	r, rec := newBrowserLoginEngine(t, bts)

	w := postBrowserLogin(t, r, "alice@example.com", "correct", "/dashboard")

	if c := sessionCookie(w); c != nil {
		t.Fatalf("fail-closed VIOLATED: a session cookie was planted (value len=%d)", len(c.Value))
	}
	if w.Code == http.StatusSeeOther || w.Header().Get("Location") != "" {
		t.Fatalf("fail-closed VIOLATED: got success redirect (code=%d, location=%q)", w.Code, w.Header().Get("Location"))
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "temporarily unavailable") {
		t.Fatalf("body = %q, want temporarily-unavailable message", w.Body.String())
	}
	// Audit must record a failure, never a success.
	var sawFailure, sawSuccess bool
	for _, e := range rec.Events() {
		if strings.Contains(e.Action, "browser_login") {
			if e.Outcome == "success" {
				sawSuccess = true
			} else {
				sawFailure = true
			}
		}
	}
	if sawSuccess {
		t.Fatal("audit recorded a SUCCESS on the fail-closed path")
	}
	if !sawFailure {
		t.Fatal("audit did not record a failure event on the fail-closed path")
	}
}

// TestBrowserLogin_TokenIssueSuccess_OpaqueCookie pins the unchanged
// success path: Issue succeeds → the cookie carries the OPAQUE
// browser-session token (it resolves via BrowserTokens.Resolve, which a
// raw refresh token would not) and the browser is redirected to
// return_to.
func TestBrowserLogin_TokenIssueSuccess_OpaqueCookie(t *testing.T) {
	repo := newInMemoryBrowserTokenRepo()
	bts := service.NewBrowserSessionTokenService(nil, repo, service.BrowserSessionTokenServiceOptions{})
	r, _ := newBrowserLoginEngine(t, bts)

	w := postBrowserLogin(t, r, "alice@example.com", "correct", "/dashboard")

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%q", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/dashboard" {
		t.Fatalf("Location = %q, want /dashboard", loc)
	}
	c := sessionCookie(w)
	if c == nil || c.Value == "" {
		t.Fatal("success path must plant a non-empty session cookie")
	}
	// The cookie value must be the opaque browser-session token: it
	// resolves via BrowserTokens.Resolve. A raw refresh token would not.
	resolved, err := bts.Resolve(context.Background(), c.Value)
	if err != nil || resolved == nil {
		t.Fatalf("cookie value is NOT an opaque browser-session token (resolve err=%v, resolved=%v)", err, resolved)
	}
}

// TestBrowserLogin_NilBrowserTokens_RawRefreshCookieUnchanged pins the
// unchanged BrowserTokens-nil path: the cookie carries the raw refresh
// token and the browser is redirected to return_to.
func TestBrowserLogin_NilBrowserTokens_RawRefreshCookieUnchanged(t *testing.T) {
	r, _ := newBrowserLoginEngine(t, nil)

	w := postBrowserLogin(t, r, "alice@example.com", "correct", "/dashboard")

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%q", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/dashboard" {
		t.Fatalf("Location = %q, want /dashboard", loc)
	}
	if c := sessionCookie(w); c == nil || c.Value == "" {
		t.Fatal("nil-BrowserTokens path must still plant the raw refresh-token cookie")
	}
}
