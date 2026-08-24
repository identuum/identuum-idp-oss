package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// spySessionRepoRevoke is a repository.SessionRepository that records the
// session ids handed to Revoke and serves a controlled active-session list.
// Only the two methods the sibling handlers reach through the real
// UserSessionService are overridden; the rest are promoted from the embedded
// nil interface and must never be called on this path.
type spySessionRepoRevoke struct {
	repository.SessionRepository
	mu      sync.Mutex
	revoked []uuid.UUID
	active  []*domain.Session
}

func (s *spySessionRepoRevoke) Revoke(_ context.Context, id, _ uuid.UUID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = append(s.revoked, id)
	return nil
}

func (s *spySessionRepoRevoke) ListActiveByUserID(_ context.Context, _ uuid.UUID) ([]*domain.Session, error) {
	return s.active, nil
}

func (s *spySessionRepoRevoke) didRevoke(id uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.revoked {
		if r == id {
			return true
		}
	}
	return false
}

// spySelfRevoker records the user ids handed to RevokeUserSessions.
type spySelfRevoker struct {
	mu    sync.Mutex
	users []uuid.UUID
}

func (s *spySelfRevoker) RevokeUserSessions(_ context.Context, userID uuid.UUID, _ string, _ map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = append(s.users, userID)
	return nil
}

func (s *spySelfRevoker) calls() []uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uuid.UUID(nil), s.users...)
}

// The self-service sibling session-revocation endpoints (revoke-all,
// revoke-current, revoke-others) derive the acting identity only from the
// authenticated principal — a user_id query or a request body is refused 400,
// never used as a target — and act only on the principal's own sessions:
// another user's session is never revoked, and revoke-others preserves the
// current session. Driven through the ROUTED handlers via
// RegisterAuthSessionRoutes over a real UserSessionService on a spy repo; the
// assertion is which session/user id (if any) actually reached the revoker.
// RULE: SESSION-SIBLING-PRINCIPAL-1
func TestSiblingSelfRevoke_PrincipalScopeOnly(t *testing.T) {
	me, myCurrent, org := uuid.New(), uuid.New(), uuid.New()
	principal := &domain.Principal{UserID: me, SessionID: myCurrent, Role: domain.RoleOrgUser}
	liveUser := &domain.User{ID: me, Email: "me@example.test", Role: domain.RoleOrgUser, OrganizationID: org}
	usable := func(id, owner uuid.UUID) *domain.Session {
		return &domain.Session{ID: id, UserID: owner, IsValid: true, ExpiresAt: time.Now().Add(time.Hour)}
	}
	myCurrentSession := usable(myCurrent, me)

	build := func(repo *spySessionRepoRevoke, rev *spySelfRevoker, currentLookup *domain.Session) *gin.Engine {
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.Use(mw.InjectPrincipalForTest(principal))
		us := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})
		RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
			UserLookup:     fakeUserByID{u: liveUser},
			SessionLookup:  fakeSessionByID{s: currentLookup},
			UserSession:    us,
			SessionRevoker: rev,
		})
		return r
	}
	post := func(r *gin.Engine, target, body string) int {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req := httptest.NewRequest(http.MethodPost, target, rdr)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	// ---------- revoke-all: identity is the principal, target refused ----------
	rev := &spySelfRevoker{}
	rAll := build(&spySessionRepoRevoke{}, rev, myCurrentSession)
	if code := post(rAll, "/api/v1/me/sessions/revoke-all", ""); code != http.StatusNoContent {
		t.Fatalf("PREMISE FAILED: a clean revoke-all must be 204, got %d", code)
	}
	got := rev.calls()
	if len(got) != 1 || got[0] != me {
		t.Fatalf("revoke-all must revoke exactly the principal's own user, got %v (me=%s)", got, me)
	}
	// A user_id query target is refused before any revoke.
	victimUser := uuid.New()
	revQ := &spySelfRevoker{}
	if code := post(build(&spySessionRepoRevoke{}, revQ, myCurrentSession),
		"/api/v1/me/sessions/revoke-all?user_id="+victimUser.String(), ""); code != http.StatusBadRequest {
		t.Errorf("a user_id query on revoke-all must be 400, got %d", code)
	}
	if len(revQ.calls()) != 0 {
		t.Errorf("a rejected revoke-all must never reach the revoker, got %v", revQ.calls())
	}
	// A request body is refused before any revoke.
	revB := &spySelfRevoker{}
	if code := post(build(&spySessionRepoRevoke{}, revB, myCurrentSession),
		"/api/v1/me/sessions/revoke-all", `{"user_id":"`+victimUser.String()+`"}`); code != http.StatusBadRequest {
		t.Errorf("a body on revoke-all must be 400, got %d", code)
	}
	if len(revB.calls()) != 0 {
		t.Errorf("a rejected revoke-all must never reach the revoker, got %v", revB.calls())
	}

	// ---------- revoke-current: only the principal's own current session ----------
	repoCur := &spySessionRepoRevoke{}
	if code := post(build(repoCur, &spySelfRevoker{}, myCurrentSession),
		"/api/v1/me/sessions/revoke-current", ""); code != http.StatusNoContent {
		t.Fatalf("PREMISE FAILED: a clean revoke-current must be 204, got %d", code)
	}
	if !repoCur.didRevoke(myCurrent) {
		t.Errorf("revoke-current must revoke the principal's current session %s", myCurrent)
	}
	// Any query is refused.
	repoCurQ := &spySessionRepoRevoke{}
	if code := post(build(repoCurQ, &spySelfRevoker{}, myCurrentSession),
		"/api/v1/me/sessions/revoke-current?x=1", ""); code != http.StatusBadRequest {
		t.Errorf("a query on revoke-current must be 400, got %d", code)
	}
	if len(repoCurQ.revoked) != 0 {
		t.Errorf("a rejected revoke-current must never reach the repository")
	}
	// The bound session, if owned by another user, is never revoked.
	otherUser := uuid.New()
	repoForeign := &spySessionRepoRevoke{}
	foreignCurrent := usable(myCurrent, otherUser)
	if code := post(build(repoForeign, &spySelfRevoker{}, foreignCurrent),
		"/api/v1/me/sessions/revoke-current", ""); code != http.StatusUnauthorized {
		t.Errorf("revoke-current on a session owned by another user must be 401, got %d", code)
	}
	if repoForeign.didRevoke(myCurrent) {
		t.Errorf("revoke-current must never revoke a session owned by another user")
	}

	// ---------- revoke-others: preserve current, never touch a foreign session ----------
	sOther, sVictim := uuid.New(), uuid.New()
	repoOthers := &spySessionRepoRevoke{active: []*domain.Session{
		usable(myCurrent, me),      // current — must be PRESERVED
		usable(sOther, me),         // another own session — must be revoked
		usable(sVictim, otherUser), // a foreign session (buggy list) — must be SKIPPED
	}}
	if code := post(build(repoOthers, &spySelfRevoker{}, myCurrentSession),
		"/api/v1/me/sessions/revoke-others", ""); code != http.StatusNoContent {
		t.Fatalf("PREMISE FAILED: a clean revoke-others must be 204, got %d", code)
	}
	if !repoOthers.didRevoke(sOther) {
		t.Errorf("revoke-others must revoke the principal's other session %s", sOther)
	}
	if repoOthers.didRevoke(myCurrent) {
		t.Errorf("revoke-others must PRESERVE the current session %s", myCurrent)
	}
	if repoOthers.didRevoke(sVictim) {
		t.Errorf("revoke-others must never revoke another user's session %s", sVictim)
	}
	// Any query is refused.
	repoOthersQ := &spySessionRepoRevoke{active: []*domain.Session{usable(sOther, me)}}
	if code := post(build(repoOthersQ, &spySelfRevoker{}, myCurrentSession),
		"/api/v1/me/sessions/revoke-others?x=1", ""); code != http.StatusBadRequest {
		t.Errorf("a query on revoke-others must be 400, got %d", code)
	}
	if len(repoOthersQ.revoked) != 0 {
		t.Errorf("a rejected revoke-others must never reach the repository")
	}
}
