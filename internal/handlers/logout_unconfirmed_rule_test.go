package handlers

// logout_unconfirmed_rule_test.go — THE-LOGOUT-THAT-CANNOT-REVOKE (2026-09-02).
//
// A store error during logout never passes silently: the AUTH-503 log line
// (through the sink, with the request's correlation id) and the audit event
// user_session.logout.revocation_unconfirmed both exist, the response is
// marked, and the cookie is STILL cleared — on both the OIDC end-session
// endpoint and the front-channel iframe endpoint. RP-initiated end-session
// still completes its redirect with state. A healthy-store logout emits
// neither the log line nor the event (it emits the success audit instead).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// failingSessionRepo wraps the in-memory session repo: lookups by selector
// (the cookie's legacy resolution path) and/or revocations fail with a
// store error, everything else works — so a session can be issued and a
// cookie minted before the store "goes away".
type failingSessionRepo struct {
	*handlersSessionRepo
	selectorErr error
	revokeErr   error
}

func (f *failingSessionRepo) GetByTokenSelector(ctx context.Context, selector uuid.UUID) (*domain.Session, error) {
	if f.selectorErr != nil {
		return nil, f.selectorErr
	}
	return f.handlersSessionRepo.GetByTokenSelector(ctx, selector)
}

func (f *failingSessionRepo) Revoke(ctx context.Context, id uuid.UUID, by uuid.UUID, reason string) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	return f.handlersSessionRepo.Revoke(ctx, id, by, reason)
}

type unconfirmedHarness struct {
	sessions *service.UserSessionService
	cookies  *service.CookieSessionService
	audit    *audit.Recorder
}

func newUnconfirmedHarness(t *testing.T, repo *failingSessionRepo) unconfirmedHarness {
	t.Helper()
	sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	return unconfirmedHarness{sessions: sessions, cookies: cookies, audit: &audit.Recorder{}}
}

func (h unconfirmedHarness) cookieFor(t *testing.T) *http.Cookie {
	t.Helper()
	issued, err := h.sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: uuid.New()})
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	return h.cookies.Issue(issued.RefreshToken, issued.ExpiresAt)
}

func (h unconfirmedHarness) endSessionEngine(client *domain.Client) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	deps := EndSessionHandlerDeps{CookieSession: h.cookies, UserSession: h.sessions, Audit: h.audit}
	if client != nil {
		deps.Clients = &fakeLogoutClientLookup{client: client}
	}
	RegisterEndSessionRoutes(r, deps)
	return r
}

func (h unconfirmedHarness) frontchannelEngine() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterFrontchannelLogoutRoutes(r, FrontchannelLogoutHandlerDeps{CookieSession: h.cookies, UserSession: h.sessions, Audit: h.audit})
	return r
}

func (h unconfirmedHarness) auditActions() []string {
	out := []string{}
	for _, e := range h.audit.Events() {
		out = append(out, e.Action)
	}
	return out
}

func (h unconfirmedHarness) unconfirmedEvent() *audit.Event {
	for _, e := range h.audit.Events() {
		if e.Action == AuditActionLogoutRevocationUnconfirmed {
			ev := e
			return &ev
		}
	}
	return nil
}

func assertCookieCleared(t *testing.T, label string, w *httptest.ResponseRecorder) {
	t.Helper()
	setCookie := strings.Join(w.Header().Values("Set-Cookie"), "\n")
	if !strings.Contains(setCookie, "identuum_session=") || !(strings.Contains(setCookie, "Max-Age=0") || strings.Contains(setCookie, "Max-Age=-1")) {
		t.Errorf("%s: the cookie must still be cleared, Set-Cookie = %q", label, setCookie)
	}
}

// assertUnconfirmedTriple: log-sink call with the correlation id, audit event
// with the same id and safe metadata, the response marker, the cookie clear.
func assertUnconfirmedTriple(t *testing.T, label string, h unconfirmedHarness, calls []sinkCall, w *httptest.ResponseRecorder, cid, where string) {
	t.Helper()
	if len(calls) != 1 || calls[0].cid != cid || calls[0].where != "logout."+where || calls[0].err == nil {
		t.Errorf("%s: log sink calls = %+v, want exactly one with cid=%q where=%q", label, calls, cid, "logout."+where)
	}
	ev := h.unconfirmedEvent()
	if ev == nil {
		t.Fatalf("%s: audit event %s missing; actions = %v", label, AuditActionLogoutRevocationUnconfirmed, h.auditActions())
	}
	if ev.CorrelationID != cid || ev.Metadata["correlation_id"] != cid || ev.Metadata["where"] != where || ev.Metadata["reason"] != "auth_store_error" {
		t.Errorf("%s: audit event = %+v, want correlation_id=%q where=%q reason=auth_store_error", label, ev, cid, where)
	}
	for k, v := range ev.Metadata {
		if s, ok := v.(string); ok && strings.Contains(s, "identuum_session=") {
			t.Errorf("%s: audit metadata %q leaks a cookie value", label, k)
		}
	}
	if got := w.Header().Get(LogoutUnconfirmedHeader); got != "revocation_unconfirmed" {
		t.Errorf("%s: %s header = %q, want revocation_unconfirmed", label, LogoutUnconfirmedHeader, got)
	}
	assertCookieCleared(t, label, w)
}

// RULE: LOGOUT-UNCONFIRMED-1
func TestRuleLogoutUnconfirmed1_StoreErrorNeverSilent_CookieStillCleared_HealthyEmitsNeither(t *testing.T) {
	storeDown := errors.New("pgx: connection reset by peer")

	t.Run("end-session: cookie-session store error → logged, audited, marked, cookie cleared, 204", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		repo := &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()}
		h := newUnconfirmedHarness(t, repo)
		cookie := h.cookieFor(t) // issued while the store was healthy
		repo.selectorErr = storeDown
		req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout", nil)
		req.AddCookie(cookie)
		req.Header.Set(mw.CorrelationIDHeader, "cid-logout-1")
		w := httptest.NewRecorder()
		h.endSessionEngine(nil).ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (the logout still completes for the user)", w.Code)
		}
		assertUnconfirmedTriple(t, "end-session resolve", h, *calls, w, "cid-logout-1", "cookie-session")
	})

	t.Run("end-session: revocation store error → logged, audited, marked, cookie cleared", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		repo := &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()}
		h := newUnconfirmedHarness(t, repo)
		cookie := h.cookieFor(t)
		repo.revokeErr = storeDown
		req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout", nil)
		req.AddCookie(cookie)
		req.Header.Set(mw.CorrelationIDHeader, "cid-logout-2")
		w := httptest.NewRecorder()
		h.endSessionEngine(nil).ServeHTTP(w, req)
		assertUnconfirmedTriple(t, "end-session revoke", h, *calls, w, "cid-logout-2", "revoke-session")
		for _, a := range h.auditActions() {
			if a == "user_session.logout.cookie_revoked" {
				t.Errorf("an unconfirmed revocation must not also audit cookie_revoked; actions = %v", h.auditActions())
			}
		}
	})

	t.Run("end-session: RP-initiated flow still completes — 302 with state, marked", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		repo := &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()}
		h := newUnconfirmedHarness(t, repo)
		cookie := h.cookieFor(t)
		repo.selectorErr = storeDown
		client := &domain.Client{ClientID: "cli-1", PostLogoutRedirectURIs: []string{"https://app.example.com/after"}}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout?client_id=cli-1&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fafter&state=xyz", nil)
		req.AddCookie(cookie)
		req.Header.Set(mw.CorrelationIDHeader, "cid-logout-3")
		w := httptest.NewRecorder()
		h.endSessionEngine(client).ServeHTTP(w, req)
		if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "https://app.example.com/after") || !strings.Contains(w.Header().Get("Location"), "state=xyz") {
			t.Fatalf("RP flow must complete with state: status=%d location=%q", w.Code, w.Header().Get("Location"))
		}
		assertUnconfirmedTriple(t, "end-session RP", h, *calls, w, "cid-logout-3", "cookie-session")
		redirected := false
		for _, e := range h.audit.Events() {
			if e.Action == "user_session.logout.redirected" {
				redirected = true
				if e.Metadata["revocation_unconfirmed"] != true {
					t.Errorf("redirected audit must carry revocation_unconfirmed=true, got %+v", e.Metadata)
				}
			}
		}
		if !redirected {
			t.Errorf("redirected audit missing; actions = %v", h.auditActions())
		}
	})

	t.Run("frontchannel: cookie-session store error → logged, audited, marked, cookie cleared, 200 body carries the reference", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		repo := &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()}
		h := newUnconfirmedHarness(t, repo)
		cookie := h.cookieFor(t)
		repo.selectorErr = storeDown
		req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout", nil)
		req.AddCookie(cookie)
		req.Header.Set(mw.CorrelationIDHeader, "cid-fc-1")
		w := httptest.NewRecorder()
		h.frontchannelEngine().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (the iframe answer stays passive)", w.Code)
		}
		assertUnconfirmedTriple(t, "frontchannel resolve", h, *calls, w, "cid-fc-1", "cookie-session")
		if !strings.Contains(w.Body.String(), "cid-fc-1") {
			t.Errorf("the passive page must carry the reference id; body = %q", w.Body.String())
		}
		if strings.Contains(strings.ToLower(w.Body.String()), "<script") {
			t.Errorf("body contains <script>")
		}
	})

	t.Run("healthy store: neither the log line nor the unconfirmed event — the success audit instead", func(t *testing.T) {
		calls := recordAuthStoreSink(t)
		repo := &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()}
		h := newUnconfirmedHarness(t, repo)
		cookie := h.cookieFor(t)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout", nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.endSessionEngine(nil).ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", w.Code)
		}
		if len(*calls) != 0 || h.unconfirmedEvent() != nil || w.Header().Get(LogoutUnconfirmedHeader) != "" {
			t.Errorf("healthy logout must emit no store-error log, no unconfirmed event, no marker: sink=%d actions=%v header=%q", len(*calls), h.auditActions(), w.Header().Get(LogoutUnconfirmedHeader))
		}
		revoked := false
		for _, a := range h.auditActions() {
			if a == "user_session.logout.cookie_revoked" {
				revoked = true
			}
		}
		if !revoked {
			t.Errorf("healthy logout must audit cookie_revoked; actions = %v", h.auditActions())
		}
		assertCookieCleared(t, "healthy", w)

		fc := httptest.NewRecorder()
		h2 := newUnconfirmedHarness(t, &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()})
		req2 := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout", nil)
		req2.AddCookie(h2.cookieFor(t))
		h2.frontchannelEngine().ServeHTTP(fc, req2)
		if fc.Code != http.StatusOK || fc.Header().Get(LogoutUnconfirmedHeader) != "" || h2.unconfirmedEvent() != nil || len(*calls) != 0 {
			t.Errorf("healthy frontchannel logout must emit no marker/event/log: status=%d header=%q actions=%v sink=%d", fc.Code, fc.Header().Get(LogoutUnconfirmedHeader), h2.auditActions(), len(*calls))
		}
	})
}
