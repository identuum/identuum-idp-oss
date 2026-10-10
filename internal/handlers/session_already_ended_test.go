package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OSS-HARDENING-3 item 3: the pgx store answers domain.ErrSessionNotFound for
// a session already revoked (its UPDATE ... WHERE revoked_at IS NULL matches
// no row). A caller that found the session live a moment earlier — a cookie
// resolved, a row listed, a bearer verified — and then reads that answer from
// its own revocation is looking at a session another sign-out or an admin
// ended meanwhile: the state it asked for, not a store failure. Each handler
// below answered a store failure (503 revocation_unconfirmed and an AUTH-503
// line, or 500 internal_error) for it; every OTHER store error still refuses.

// endedMeanwhileRepo is the faithful fixture where the sessions in `lost` are
// ended by another writer between the caller's lookup and its revocation: the
// row is revoked, and the caller's own UPDATE matches nothing.
type endedMeanwhileRepo struct {
	*handlersSessionRepo
	lost map[uuid.UUID]bool
	// revokeErr, when set, is every revocation's answer: the control for a
	// store failure that is not "not found".
	revokeErr error
}

func newEndedMeanwhileRepo() *endedMeanwhileRepo {
	return &endedMeanwhileRepo{handlersSessionRepo: newHandlersSessionRepo(), lost: map[uuid.UUID]bool{}}
}

func (r *endedMeanwhileRepo) Revoke(ctx context.Context, id, by uuid.UUID, reason string) error {
	if r.revokeErr != nil {
		return r.revokeErr
	}
	if r.lost[id] {
		_ = r.handlersSessionRepo.Revoke(ctx, id, by, "ended_meanwhile")
		return domain.ErrSessionNotFound
	}
	return r.handlersSessionRepo.Revoke(ctx, id, by, reason)
}

// ListActiveByUserID lists the live sessions of the user (the shared fixture
// answers none), so the other-sessions revocation has sessions to walk.
func (r *endedMeanwhileRepo) ListActiveByUserID(_ context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	var out []*domain.Session
	for _, s := range r.byID {
		if s.UserID == userID && s.RevokedAt == nil {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

func assertNoUnconfirmed(t *testing.T, label string, rec *audit.Recorder, calls []sinkCall, w *httptest.ResponseRecorder) {
	t.Helper()
	if len(calls) != 0 {
		t.Errorf("%s: AUTH-503 log sink calls = %+v; want none, the session is ended", label, calls)
	}
	for _, e := range rec.Events() {
		if e.Action == AuditActionLogoutRevocationUnconfirmed {
			t.Errorf("%s: %s audited (%+v); want none", label, e.Action, e.Metadata)
		}
	}
	if got := w.Header().Get(LogoutUnconfirmedHeader); got != "" {
		t.Errorf("%s: %s = %q; want the header absent", label, LogoutUnconfirmedHeader, got)
	}
}

func auditedAction(rec *audit.Recorder, action string) *audit.Event {
	for _, e := range rec.Events() {
		if e.Action == action {
			ev := e
			return &ev
		}
	}
	return nil
}

// ---------- HandleEndSession, the cookie session (logout.go phase 1) ----------

func TestEndSession_ACookieSessionEndedMeanwhileIsNotAStoreError(t *testing.T) {
	calls := recordAuthStoreSink(t)
	repo := newEndedMeanwhileRepo()
	w := newHintWorldOver(t, repo, nil, nil)
	cookie, sid := w.signIn(t, w.user.ID)
	repo.lost[sid] = true

	req := httptest.NewRequest(http.MethodGet, confirmedLogoutURL("/api/v1/oidc/logout", cookie), nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.r.ServeHTTP(rec, req)

	if !signedOut(rec) {
		t.Fatalf("confirmed logout of a session ended meanwhile = %d; want the signed-out page", rec.Code)
	}
	if w.alive(cookie) {
		t.Error("the browser's session is still alive")
	}
	assertNoUnconfirmed(t, "cookie session ended meanwhile", w.audit, *calls, rec)
	if auditedAction(w.audit, "user_session.logout.cookie_revoked") == nil {
		t.Error("the sign-out of this browser was not audited as user_session.logout.cookie_revoked")
	}
}

func TestEndSession_ACookieSessionStoreFailureStillRefuses(t *testing.T) {
	// Control: any other store error on the same revocation is still a
	// revocation the logout cannot confirm.
	calls := recordAuthStoreSink(t)
	repo := &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()}
	w := newHintWorldOver(t, repo, nil, nil)
	cookie, _ := w.signIn(t, w.user.ID)
	repo.revokeErr = errors.New("store unavailable")

	req := httptest.NewRequest(http.MethodGet, confirmedLogoutURL("/api/v1/oidc/logout", cookie), nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.r.ServeHTTP(rec, req)

	if len(*calls) == 0 || auditedAction(w.audit, AuditActionLogoutRevocationUnconfirmed) == nil || rec.Header().Get(LogoutUnconfirmedHeader) == "" {
		t.Fatalf("a store failure was not reported: sink calls %d, unconfirmed event %v, header %q", len(*calls), auditedAction(w.audit, AuditActionLogoutRevocationUnconfirmed) != nil, rec.Header().Get(LogoutUnconfirmedHeader))
	}
}

// ---------- HandleEndSession, the bearer session (logout.go phase 3) ----------

func TestEndSession_ABearerOfAnEndedSessionIsNotAStoreError(t *testing.T) {
	calls := recordAuthStoreSink(t)
	bearer := &domain.Principal{UserID: uuid.New(), Role: domain.RoleOrgUser}
	w := newHintWorldOver(t, newHandlersSessionRepo(), nil, bearer)
	_, sid := w.signIn(t, bearer.UserID)
	bearer.SessionID = sid
	if err := w.sessions.RevokeSession(context.Background(), sid, "user_requested"); err != nil {
		t.Fatalf("end the session first: %v", err)
	}

	// A closed browser: no cookie, no hint, the access token alone.
	rec := httptest.NewRecorder()
	w.r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout", nil))

	if !signedOut(rec) {
		t.Fatalf("bearer logout of an ended session = %d; want the signed-out page", rec.Code)
	}
	assertNoUnconfirmed(t, "bearer of an ended session", w.audit, *calls, rec)
}

// ---------- HandleFrontchannelLogout ----------

func TestFrontchannelLogout_ACookieSessionEndedMeanwhileIsNotAStoreError(t *testing.T) {
	calls := recordAuthStoreSink(t)
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	repo := newEndedMeanwhileRepo()
	sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})
	user := &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: user}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	rec := &audit.Recorder{}
	RegisterFrontchannelLogoutRoutes(r, FrontchannelLogoutHandlerDeps{CookieSession: cookies, UserSession: sessions, Audit: rec})
	issued, err := sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: user.ID})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	repo.lost[issued.Session.ID] = true

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout", nil)
	req.AddCookie(cookies.Issue(issued.RefreshToken, issued.ExpiresAt))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	assertNoUnconfirmed(t, "frontchannel cookie session ended meanwhile", rec, *calls, w)
	if auditedAction(rec, "user_session.frontchannel_logout") == nil {
		t.Error("the sign-out was not audited as user_session.frontchannel_logout")
	}
}

// ---------- the self-service session routes ----------

type endedMeanwhileEngine struct {
	r        *gin.Engine
	repo     *endedMeanwhileRepo
	sessions *service.UserSessionService
	rec      *audit.Recorder
}

func newEndedMeanwhileAuthEngine(t *testing.T, principal *domain.Principal) endedMeanwhileEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(principal))
	users := newRecoveryStubUserRepo()
	users.byID[principal.UserID] = &domain.User{ID: principal.UserID, OrganizationID: principal.OrganizationID, Email: "self@example.com", Role: domain.RoleOrgUser, EmailVerified: true}
	repo := newEndedMeanwhileRepo()
	sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	rec := &audit.Recorder{}
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		UserLookup:          users,
		UserSession:         sessions,
		SessionLookup:       repo,
		SessionRevoker:      &service.RecorderSessionRevoker{},
		RefreshTokenRevoker: &service.RecorderRefreshTokenRevoker{},
		Audit:               rec,
	})
	return endedMeanwhileEngine{r: r, repo: repo, sessions: sessions, rec: rec}
}

func (e endedMeanwhileEngine) signIn(t *testing.T, userID uuid.UUID) uuid.UUID {
	t.Helper()
	issued, err := e.sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: userID})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	return issued.Session.ID
}

func (e endedMeanwhileEngine) post(path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
	return w
}

func TestRevokeCurrentOwnSession_EndedMeanwhileIsUnauthorizedNotAnError(t *testing.T) {
	// The route's contract: a principal whose session row is revoked answers
	// 401 unauthorized. A session ended between the lookup and the
	// revocation is that same state, not 500 internal_error.
	principal := &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser}
	eng := newEndedMeanwhileAuthEngine(t, principal)
	principal.SessionID = eng.signIn(t, principal.UserID)
	eng.repo.lost[principal.SessionID] = true

	w := eng.post("/api/v1/me/sessions/revoke-current")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%q; want 401 unauthorized, the answer for an ended session", w.Code, w.Body.String())
	}
	if auditedAction(eng.rec, string(domain.AuditSessionRevoked)) != nil {
		t.Error("a revocation this request did not perform was audited as its success")
	}
}

func TestRevokeOtherOwnSessions_OneEndedMeanwhileDoesNotAbortTheRest(t *testing.T) {
	principal := &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser}
	eng := newEndedMeanwhileAuthEngine(t, principal)
	principal.SessionID = eng.signIn(t, principal.UserID)
	endedMeanwhile := eng.signIn(t, principal.UserID)
	stillLive := eng.signIn(t, principal.UserID)
	eng.repo.lost[endedMeanwhile] = true

	w := eng.post("/api/v1/me/sessions/revoke-others")

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%q; want 204", w.Code, w.Body.String())
	}
	if s := eng.repo.byID[stillLive]; s == nil || s.RevokedAt == nil {
		t.Fatalf("the other live session was not revoked after one ended meanwhile: %+v", s)
	}
	if s := eng.repo.byID[principal.SessionID]; s == nil || s.RevokedAt != nil {
		t.Fatalf("the current session was revoked: %+v", s)
	}
	ev := auditedAction(eng.rec, string(domain.AuditSelfSessionsRevoked))
	if ev == nil {
		t.Fatalf("%s not audited", domain.AuditSelfSessionsRevoked)
	}
	if ev.Metadata["sessions_revoked_count"] != 1 {
		t.Errorf("sessions_revoked_count = %v; want 1, the session this request ended (not the one ended meanwhile)", ev.Metadata["sessions_revoked_count"])
	}
}

func TestRevokeOtherOwnSessions_AStoreFailureStillRefuses(t *testing.T) {
	// Control: any other store error on a revocation still refuses.
	principal := &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser}
	eng := newEndedMeanwhileAuthEngine(t, principal)
	principal.SessionID = eng.signIn(t, principal.UserID)
	eng.signIn(t, principal.UserID)
	eng.repo.revokeErr = errors.New("store unavailable")

	w := eng.post("/api/v1/me/sessions/revoke-others")

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%q; want 500 internal_error for a store failure", w.Code, w.Body.String())
	}
}

func TestRevokeOwnSession_EndedMeanwhileIsTheIdempotentSuccess(t *testing.T) {
	// The route already answers an already-revoked target with the opaque
	// success body; a target ended between its lookup and the revocation is
	// the same state, not 500 internal_error.
	repo := newFakeSessionRepoForHandlerTests()
	me := uuid.New()
	target := makeSession(t, me)
	repo.addSession(target)
	rev := &fakeSessionRevoker{revokeFn: func(uuid.UUID, string) error { return domain.ErrSessionNotFound }}
	r := newSessionsEngine(t, sessionsTestPrincipal(me, uuid.New(), domain.RoleOrgUser), SessionsHandlerDeps{
		SessionList: repo, SessionRepo: repo, UserSession: rev, Audit: &captureAudit{},
	})

	rec := sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": target.ID.String()})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q; want 200, the idempotent success", rec.Code, rec.Body.String())
	}
}
