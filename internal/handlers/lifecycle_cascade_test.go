package handlers

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// cascadeSessionStore is a shared in-memory session store that satisfies
// BOTH the lifecycle revoke seams (service.SessionRevoker via
// RevokeUserSessions, handlers.OrgSessionRevoker via RevokeByOrganizationID)
// AND the bearer-path lookup seam (mw.SessionRevocationLookup via
// GetSessionWithUserAndOrgStatus). Revoking through the lifecycle path makes
// the SAME session the bearer path then reads, so the Stage-1 check rejects
// it — exactly the production wiring.
type cascadeSessionStore struct {
	mu       sync.Mutex
	sessions map[uuid.UUID]*domain.Session // sessionID -> session
	byUser   map[uuid.UUID][]uuid.UUID     // userID -> sessionIDs
	userOrg  map[uuid.UUID]uuid.UUID       // userID -> orgID
}

func newCascadeSessionStore() *cascadeSessionStore {
	return &cascadeSessionStore{
		sessions: map[uuid.UUID]*domain.Session{},
		byUser:   map[uuid.UUID][]uuid.UUID{},
		userOrg:  map[uuid.UUID]uuid.UUID{},
	}
}

// addLiveSession registers a live (usable) session for a user in an org.
func (s *cascadeSessionStore) addLiveSession(userID, orgID uuid.UUID) uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	sid := uuid.New()
	s.sessions[sid] = &domain.Session{ID: sid, IsValid: true, ExpiresAt: time.Now().Add(time.Hour)}
	s.byUser[userID] = append(s.byUser[userID], sid)
	s.userOrg[userID] = orgID
	return sid
}

func (s *cascadeSessionStore) revokeUser(userID uuid.UUID) {
	now := time.Now().UTC()
	for _, sid := range s.byUser[userID] {
		if sess := s.sessions[sid]; sess != nil {
			sess.IsValid = false
			sess.RevokedAt = &now
		}
	}
}

// --- service.SessionRevoker ---
func (s *cascadeSessionStore) RevokeUserSessions(_ context.Context, userID uuid.UUID, _ string, _ map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeUser(userID)
	return nil
}

// --- handlers.OrgSessionRevoker (the previously dead-wired primitive) ---
func (s *cascadeSessionStore) RevokeByOrganizationID(_ context.Context, orgID uuid.UUID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for userID, oid := range s.userOrg {
		if oid == orgID {
			s.revokeUser(userID)
		}
	}
	return nil
}

// --- mw.SessionRevocationLookup (bearer-path Stage-1 + R3 read) ---
// The cascade tests exercise the session-REVOCATION path (revoke via the
// lifecycle seam → bearer rejects), so the user/org status is reported
// fully-active here; a revoked session is still rejected by the session-
// usability check inside CanBeUsedForAuth.
func (s *cascadeSessionStore) GetSessionWithUserAndOrgStatus(_ context.Context, id uuid.UUID) (*domain.SessionValidationInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[id]
	if sess == nil {
		return nil, nil
	}
	return &domain.SessionValidationInfo{Session: sess, UserActive: true, OrgActive: true}, nil
}

// cascadeRefreshStub records per-user refresh revokes and can be made to error.
type cascadeRefreshStub struct {
	mu    sync.Mutex
	calls []uuid.UUID
	err   error
}

func (r *cascadeRefreshStub) RevokeAllForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, userID)
	return int64(1), r.err
}

// cascadeMemberStub enumerates org members for the refresh fan-out.
type cascadeMemberStub struct{ members []*domain.User }

func (m cascadeMemberStub) ListByOrganization(_ context.Context, _ uuid.UUID, _ repository.ListUserOptions) ([]*domain.User, int, error) {
	return m.members, len(m.members), nil
}

// erroringSessionRevoker fails the session revoke (scenario e).
type erroringSessionRevoker struct{}

func (erroringSessionRevoker) RevokeUserSessions(_ context.Context, _ uuid.UUID, _ string, _ map[string]any) error {
	return errors.New("simulated session-store outage")
}

// cascadeVerifier returns a fixed principal (bearer-path verifier stub).
type cascadeVerifier struct{ p *domain.Principal }

func (v cascadeVerifier) VerifyBearerToken(_ context.Context, _ string) (*domain.Principal, error) {
	return v.p, nil
}

// bearerStatus runs a request through the REAL mw.BearerPrincipal Stage-1
// path with the given verifier + session store and returns the status code
// (401 = session rejected; 200 = admitted).
func bearerStatus(verifier mw.TokenVerifier, store mw.SessionRevocationLookup) int {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.BearerPrincipal(nil, verifier, store, nil))
	r.GET("/probe", func(c *gin.Context) {
		if _, ok := mw.PrincipalFromContext(c); !ok {
			c.Status(http.StatusUnauthorized)
			return
		}
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

func siteAdminActor() *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), Role: domain.RoleSiteAdmin}
}

// runUserUpdate / runUserDelete / runOrgUpdate / runOrgDelete drive the real
// handlers with an injected site_admin principal.
func runHandler(t *testing.T, method, route, path string, body string, h gin.HandlerFunc) int {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(siteAdminActor()))
	r.Handle(method, route, h)
	var rdr *bytes.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

// (a) USER BAN → prior session rejected at the bearer path.
func TestCascade_UserBan_RevokesSession(t *testing.T) {
	orgID := uuid.New()
	user := &domain.User{ID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser, Email: "u@x.test"}
	repo := newMemUserRepo()
	_, _ = repo.Create(context.Background(), user)
	store := newCascadeSessionStore()
	sid := store.addLiveSession(user.ID, orgID)
	refresh := &cascadeRefreshStub{}
	deps := UsersHandlerDeps{Audit: audit.NoopService{}, UserService: service.NewUserService(nil, repo), SessionRevoker: store, RefreshTokenRevoker: refresh}

	verifier := cascadeVerifier{p: &domain.Principal{UserID: user.ID, Role: domain.RoleOrgUser, SessionID: sid}}
	if before := bearerStatus(verifier, store); before != http.StatusOK {
		t.Fatalf("control: live session should be admitted, got %d", before)
	}

	code := runHandler(t, http.MethodPut, "/u/:id", "/u/"+user.ID.String(), `{"banned":true}`, HandleUpdateUser(deps))
	if code != http.StatusOK {
		t.Fatalf("ban update status = %d, want 200", code)
	}
	after := bearerStatus(verifier, store)
	t.Logf("EVIDENCE (a) user ban: bearer before=200 after=%d; refresh revokes=%v", after, refresh.calls)
	if after != http.StatusUnauthorized {
		t.Errorf("after ban: bearer status = %d, want 401 (session revoked)", after)
	}
	if len(refresh.calls) != 1 || refresh.calls[0] != user.ID {
		t.Errorf("refresh revoke not called for banned user: %v", refresh.calls)
	}
}

// (b) USER DELETE → prior session rejected at the bearer path.
func TestCascade_UserDelete_RevokesSession(t *testing.T) {
	orgID := uuid.New()
	user := &domain.User{ID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser, Email: "d@x.test"}
	repo := newMemUserRepo()
	_, _ = repo.Create(context.Background(), user)
	store := newCascadeSessionStore()
	sid := store.addLiveSession(user.ID, orgID)
	refresh := &cascadeRefreshStub{}
	deps := UsersHandlerDeps{Audit: audit.NoopService{}, UserService: service.NewUserService(nil, repo), SessionRevoker: store, RefreshTokenRevoker: refresh}

	verifier := cascadeVerifier{p: &domain.Principal{UserID: user.ID, Role: domain.RoleOrgUser, SessionID: sid}}
	code := runHandler(t, http.MethodDelete, "/u/:id", "/u/"+user.ID.String(), "", HandleDeleteUser(deps))
	if code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", code)
	}
	after := bearerStatus(verifier, store)
	t.Logf("EVIDENCE (b) user delete: bearer after=%d; refresh revokes=%v", after, refresh.calls)
	if after != http.StatusUnauthorized {
		t.Errorf("after delete: bearer status = %d, want 401", after)
	}
}

// (c) ORG DEACTIVATE → a member's live session rejected at the bearer path.
func TestCascade_OrgDeactivate_RevokesMemberSession(t *testing.T) {
	orgID := uuid.New()
	orgRepo := newMemOrgRepo()
	_, _ = orgRepo.Create(context.Background(), &domain.Organization{ID: orgID, Active: true})
	member := &domain.User{ID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser}
	store := newCascadeSessionStore()
	sid := store.addLiveSession(member.ID, orgID)
	refresh := &cascadeRefreshStub{}
	deps := OrganizationsHandlerDeps{
		Audit:               audit.NoopService{},
		OrganizationService: service.NewOrganizationService(nil, orgRepo),
		SessionRevoker:      store,
		RefreshTokenRevoker: refresh,
		MemberLister:        cascadeMemberStub{members: []*domain.User{member}},
	}

	verifier := cascadeVerifier{p: &domain.Principal{UserID: member.ID, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: sid}}
	code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+orgID.String(), `{"active":false}`, HandleUpdateOrganization(deps))
	if code != http.StatusOK {
		t.Fatalf("org deactivate status = %d, want 200", code)
	}
	after := bearerStatus(verifier, store)
	t.Logf("EVIDENCE (c) org deactivate: bearer after=%d; member refresh revokes=%v", after, refresh.calls)
	if after != http.StatusUnauthorized {
		t.Errorf("after org deactivate: member bearer status = %d, want 401", after)
	}
	if len(refresh.calls) != 1 || refresh.calls[0] != member.ID {
		t.Errorf("member refresh revoke not called: %v", refresh.calls)
	}
}

// (d) ORG DELETE → a member's live session rejected at the bearer path.
func TestCascade_OrgDelete_RevokesMemberSession(t *testing.T) {
	orgID := uuid.New()
	orgRepo := newMemOrgRepo()
	_, _ = orgRepo.Create(context.Background(), &domain.Organization{ID: orgID, Active: true})
	member := &domain.User{ID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser}
	store := newCascadeSessionStore()
	sid := store.addLiveSession(member.ID, orgID)
	refresh := &cascadeRefreshStub{}
	deps := OrganizationsHandlerDeps{
		Audit:               audit.NoopService{},
		OrganizationService: service.NewOrganizationService(nil, orgRepo),
		SessionRevoker:      store,
		RefreshTokenRevoker: refresh,
		MemberLister:        cascadeMemberStub{members: []*domain.User{member}},
	}

	verifier := cascadeVerifier{p: &domain.Principal{UserID: member.ID, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: sid}}
	code := runHandler(t, http.MethodDelete, "/o/:id", "/o/"+orgID.String(), "", HandleDeleteOrganization(deps))
	if code != http.StatusOK {
		t.Fatalf("org delete status = %d, want 200", code)
	}
	after := bearerStatus(verifier, store)
	t.Logf("EVIDENCE (d) org delete: bearer after=%d; member refresh revokes=%v", after, refresh.calls)
	if after != http.StatusUnauthorized {
		t.Errorf("after org delete: member bearer status = %d, want 401", after)
	}
}

// (e) The lifecycle op still SUCCEEDS when a revoke sub-step errors —
// the lifecycle change persisted, the error is best-effort (logged), no panic.
func TestCascade_RevokeError_DoesNotBreakLifecycle(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("revoke error caused a panic: %v", r)
		}
	}()
	orgID := uuid.New()
	user := &domain.User{ID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser}
	repo := newMemUserRepo()
	_, _ = repo.Create(context.Background(), user)
	// SessionRevoker errors; RefreshTokenRevoker nil. Ban must still 200.
	deps := UsersHandlerDeps{Audit: audit.NoopService{}, UserService: service.NewUserService(nil, repo), SessionRevoker: erroringSessionRevoker{}}

	code := runHandler(t, http.MethodPut, "/u/:id", "/u/"+user.ID.String(), `{"banned":true}`, HandleUpdateUser(deps))
	if code != http.StatusOK {
		t.Fatalf("ban with erroring revoker: status = %d, want 200 (lifecycle is source of truth)", code)
	}
	if got, _ := repo.GetByID(context.Background(), user.ID); got == nil || !got.Banned {
		t.Errorf("lifecycle change must persist despite revoke error; banned=%v", got)
	}
	t.Logf("EVIDENCE (e) revoke error: ban persisted (banned=true), op returned 200, no panic")
}
