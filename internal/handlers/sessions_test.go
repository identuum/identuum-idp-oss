package handlers

// sessions_test.go — handler-level unit tests for the OSS session
// list/revoke routes.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// ---------- shared test fakes ----------

type fakeSessionRepoForHandlerTests struct {
	mu       sync.Mutex
	byID     map[uuid.UUID]*domain.Session
	listByID map[uuid.UUID][]*domain.Session
	getErr   error
	listErr  error
}

func newFakeSessionRepoForHandlerTests() *fakeSessionRepoForHandlerTests {
	return &fakeSessionRepoForHandlerTests{
		byID:     make(map[uuid.UUID]*domain.Session),
		listByID: make(map[uuid.UUID][]*domain.Session),
	}
}

func (r *fakeSessionRepoForHandlerTests) GetByID(_ context.Context, id uuid.UUID) (*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	if s, ok := r.byID[id]; ok {
		return s, nil
	}
	return nil, domain.ErrSessionNotFound
}

func (r *fakeSessionRepoForHandlerTests) ListByUserID(_ context.Context, userID uuid.UUID, _ bool) ([]*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listErr != nil {
		return nil, r.listErr
	}
	out := r.listByID[userID]
	cp := make([]*domain.Session, len(out))
	copy(cp, out)
	return cp, nil
}

func (r *fakeSessionRepoForHandlerTests) addSession(s *domain.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[s.ID] = s
	r.listByID[s.UserID] = append(r.listByID[s.UserID], s)
}

type fakeSessionRevoker struct {
	mu       sync.Mutex
	calls    []uuid.UUID
	reasons  []string
	revokeFn func(uuid.UUID, string) error
}

func (r *fakeSessionRevoker) RevokeSession(_ context.Context, id uuid.UUID, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, id)
	r.reasons = append(r.reasons, reason)
	if r.revokeFn != nil {
		return r.revokeFn(id, reason)
	}
	return nil
}

type captureAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *captureAudit) Record(_ context.Context, e audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func (a *captureAudit) snapshot() []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]audit.Event, len(a.events))
	copy(out, a.events)
	return out
}

// ---------- helpers ----------

func sessionsTestPrincipal(userID, sessionID uuid.UUID, role domain.UserRole) *domain.Principal {
	return &domain.Principal{
		UserID:         userID,
		SessionID:      sessionID,
		Role:           role,
		OrganizationID: uuid.New(),
		Email:          "user@example.test",
	}
}

func newSessionsEngine(t *testing.T, principal *domain.Principal, deps SessionsHandlerDeps) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	RegisterSessionsRoutes(r, deps)
	return r
}

func sessionsDoJSON(t *testing.T, r http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func makeSession(t *testing.T, userID uuid.UUID, opts ...func(*domain.Session)) *domain.Session {
	t.Helper()
	id, err := uuid.NewV7()
	require.NoError(t, err)
	now := time.Now().UTC()
	s := &domain.Session{
		ID:        id,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		IsValid:   true,
	}
	for _, fn := range opts {
		fn(s)
	}
	return s
}

// ---------- registration / nil-service tests ----------

func TestSessionsRoutes_NoDepsDoesNotMount(t *testing.T) {
	r := newSessionsEngine(t, nil, SessionsHandlerDeps{})
	rec := sessionsDoJSON(t, r, http.MethodGet, "/api/v1/sessions", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": uuid.New().String()})
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestSessionsRoutes_ListMountsButRevokeRequiresRevoker(t *testing.T) {
	repo := newFakeSessionRepoForHandlerTests()
	r := newSessionsEngine(t, nil, SessionsHandlerDeps{
		SessionList: repo,
		SessionRepo: repo,
	})
	// List route mounts (the 401 below comes from the auth gate).
	rec := sessionsDoJSON(t, r, http.MethodGet, "/api/v1/sessions", nil)
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
	// Revoke is unmounted when UserSession is nil.
	rec = sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": uuid.New().String()})
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------- auth gate ----------

func TestList_AuthRequired(t *testing.T) {
	repo := newFakeSessionRepoForHandlerTests()
	r := newSessionsEngine(t, nil, SessionsHandlerDeps{SessionList: repo, SessionRepo: repo})
	rec := sessionsDoJSON(t, r, http.MethodGet, "/api/v1/sessions", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRevoke_AuthRequired(t *testing.T) {
	repo := newFakeSessionRepoForHandlerTests()
	rev := &fakeSessionRevoker{}
	r := newSessionsEngine(t, nil, SessionsHandlerDeps{SessionList: repo, SessionRepo: repo, UserSession: rev})
	rec := sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": uuid.New().String()})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestList_SiteAdminGets403(t *testing.T) {
	repo := newFakeSessionRepoForHandlerTests()
	principal := sessionsTestPrincipal(uuid.New(), uuid.New(), domain.RoleSiteAdmin)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{SessionList: repo, SessionRepo: repo})
	rec := sessionsDoJSON(t, r, http.MethodGet, "/api/v1/sessions", nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRevoke_SiteAdminGets403(t *testing.T) {
	repo := newFakeSessionRepoForHandlerTests()
	principal := sessionsTestPrincipal(uuid.New(), uuid.New(), domain.RoleSiteAdmin)
	rev := &fakeSessionRevoker{}
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{SessionList: repo, SessionRepo: repo, UserSession: rev})
	rec := sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": uuid.New().String()})
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------- list shape + safety ----------

func TestList_ReturnsOwnSessionsOnly(t *testing.T) {
	userA := uuid.New()
	userB := uuid.New()
	currentSessionID, _ := uuid.NewV7()
	repo := newFakeSessionRepoForHandlerTests()

	currentSess := makeSession(t, userA, func(s *domain.Session) {
		s.ID = currentSessionID
		ip := "10.0.0.1"
		ua := "Mozilla/5.0"
		s.IPAddress = &ip
		s.UserAgent = &ua
		lu := time.Now()
		s.LastUsedAt = &lu
	})
	otherSess := makeSession(t, userA)
	foreignSess := makeSession(t, userB)
	repo.addSession(currentSess)
	repo.addSession(otherSess)
	repo.addSession(foreignSess)

	principal := sessionsTestPrincipal(userA, currentSessionID, domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{SessionList: repo, SessionRepo: repo})
	rec := sessionsDoJSON(t, r, http.MethodGet, "/api/v1/sessions", nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var body listSessionsResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.True(t, body.Success)
	require.Len(t, body.Sessions, 2, "list must not include foreign sessions")

	// Exactly one entry is the current session.
	currentCount := 0
	for _, s := range body.Sessions {
		if s.IsCurrent {
			currentCount++
			assert.Equal(t, currentSessionID.String(), s.ID)
			require.NotNil(t, s.IPAddress)
			require.NotNil(t, s.UserAgent)
			assert.Equal(t, "10.0.0.1", *s.IPAddress)
			assert.Equal(t, "Mozilla/5.0", *s.UserAgent)
			require.NotNil(t, s.LastUsedAt)
		}
	}
	assert.Equal(t, 1, currentCount, "exactly one session must be is_current")
}

func TestSessions_NoCredentialMaterial(t *testing.T) {
	// Defensive scan: serialise an arbitrary set of sessions and
	// confirm the response body never contains keys for token,
	// token_selector, token_validator_hash, refresh_token, cookie,
	// validator, hash, or remember_me.
	userID := uuid.New()
	currentSessionID, _ := uuid.NewV7()
	repo := newFakeSessionRepoForHandlerTests()
	sess := makeSession(t, userID, func(s *domain.Session) {
		// Populate every credential-shaped field to make sure
		// the safe projection drops them.
		s.ID = currentSessionID
		tokenSel := uuid.New()
		tokenHash := "credential-shaped-string-should-not-leak"
		s.TokenSelector = &tokenSel
		s.TokenValidatorHash = &tokenHash
		s.Token = "raw-token-value-must-not-leak"
		s.RememberMe = true
	})
	repo.addSession(sess)
	principal := sessionsTestPrincipal(userID, currentSessionID, domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{SessionList: repo, SessionRepo: repo})
	rec := sessionsDoJSON(t, r, http.MethodGet, "/api/v1/sessions", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	for _, banned := range []string{
		"token_selector",
		"token_validator_hash",
		"validator",
		"refresh_token",
		"\"token\"",
		"remember_me",
		"raw-token-value-must-not-leak",
		"credential-shaped-string-should-not-leak",
	} {
		assert.False(t, strings.Contains(body, banned),
			"list response body must not contain %q", banned)
	}
}

func TestList_EmptyResultsReturnArray(t *testing.T) {
	userID := uuid.New()
	repo := newFakeSessionRepoForHandlerTests()
	principal := sessionsTestPrincipal(userID, uuid.New(), domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{SessionList: repo, SessionRepo: repo})
	rec := sessionsDoJSON(t, r, http.MethodGet, "/api/v1/sessions", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	// JSON sessions field MUST be an array, not null — the UI
	// iterates over it unconditionally.
	body := rec.Body.String()
	assert.Contains(t, body, `"sessions":[]`)
}

func TestList_RepoErrorIs500(t *testing.T) {
	userID := uuid.New()
	repo := newFakeSessionRepoForHandlerTests()
	repo.listErr = errors.New("db down")
	principal := sessionsTestPrincipal(userID, uuid.New(), domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{SessionList: repo, SessionRepo: repo})
	rec := sessionsDoJSON(t, r, http.MethodGet, "/api/v1/sessions", nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------- revoke ----------

func TestRevoke_OwnSessionSuccess(t *testing.T) {
	userID := uuid.New()
	currentSessionID, _ := uuid.NewV7()
	otherSessionID, _ := uuid.NewV7()
	repo := newFakeSessionRepoForHandlerTests()
	current := makeSession(t, userID, func(s *domain.Session) { s.ID = currentSessionID })
	other := makeSession(t, userID, func(s *domain.Session) { s.ID = otherSessionID })
	repo.addSession(current)
	repo.addSession(other)
	rev := &fakeSessionRevoker{}
	rec := &captureAudit{}
	principal := sessionsTestPrincipal(userID, currentSessionID, domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{
		SessionList: repo, SessionRepo: repo, UserSession: rev, Audit: rec,
	})

	resp := sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": otherSessionID.String()})
	require.Equal(t, http.StatusOK, resp.Code)

	var body revokeSessionResponse
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	assert.True(t, body.Success)
	assert.False(t, body.CurrentRevoked)

	// Revoker called once with the right id + reason.
	require.Len(t, rev.calls, 1)
	assert.Equal(t, otherSessionID, rev.calls[0])
	assert.Equal(t, "user_requested", rev.reasons[0])

	// Audit event emitted with safe metadata only.
	events := rec.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, "user_session.revoke.success", events[0].Action)
	assert.Equal(t, "success", events[0].Outcome)
	assert.Equal(t, otherSessionID, events[0].SubjectID)
	// No credential material in audit metadata.
	for k, v := range events[0].Metadata {
		if s, ok := v.(string); ok {
			assert.False(t, strings.Contains(s, "token"),
				"audit metadata key %q must not contain token material", k)
		}
	}
}

func TestRevoke_CurrentSessionSignalsCurrentRevoked(t *testing.T) {
	userID := uuid.New()
	currentSessionID, _ := uuid.NewV7()
	repo := newFakeSessionRepoForHandlerTests()
	repo.addSession(makeSession(t, userID, func(s *domain.Session) { s.ID = currentSessionID }))
	rev := &fakeSessionRevoker{}
	principal := sessionsTestPrincipal(userID, currentSessionID, domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{
		SessionList: repo, SessionRepo: repo, UserSession: rev, Audit: audit.NoopService{},
	})

	resp := sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": currentSessionID.String()})
	require.Equal(t, http.StatusOK, resp.Code)
	var body revokeSessionResponse
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	assert.True(t, body.Success)
	assert.True(t, body.CurrentRevoked, "current-session revocation must signal current_revoked:true")
}

func TestRevoke_CrossUserSilentlyRejected(t *testing.T) {
	userA := uuid.New()
	userB := uuid.New()
	foreignSession := makeSession(t, userB)
	repo := newFakeSessionRepoForHandlerTests()
	repo.addSession(foreignSession)
	rev := &fakeSessionRevoker{}
	principal := sessionsTestPrincipal(userA, uuid.New(), domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{
		SessionList: repo, SessionRepo: repo, UserSession: rev, Audit: audit.NoopService{},
	})

	resp := sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": foreignSession.ID.String()})
	require.Equal(t, http.StatusOK, resp.Code, "cross-user revocation must return opaque 200 (anti-enumeration)")

	var body revokeSessionResponse
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	assert.True(t, body.Success)
	assert.False(t, body.CurrentRevoked)
	// Revoker NOT called.
	assert.Empty(t, rev.calls, "cross-user revocation must not reach the revoker")
}

func TestRevoke_UnknownSessionReturns200(t *testing.T) {
	userID := uuid.New()
	repo := newFakeSessionRepoForHandlerTests()
	rev := &fakeSessionRevoker{}
	principal := sessionsTestPrincipal(userID, uuid.New(), domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{
		SessionList: repo, SessionRepo: repo, UserSession: rev, Audit: audit.NoopService{},
	})

	resp := sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": uuid.New().String()})
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Empty(t, rev.calls)
}

func TestRevoke_AlreadyRevokedIsIdempotent(t *testing.T) {
	userID := uuid.New()
	repo := newFakeSessionRepoForHandlerTests()
	revokedAt := time.Now().Add(-time.Minute)
	reason := "earlier"
	repo.addSession(makeSession(t, userID, func(s *domain.Session) {
		s.RevokedAt = &revokedAt
		s.RevokedReason = &reason
	}))
	// The session id of the seeded session:
	var seededID uuid.UUID
	for id := range repo.byID {
		seededID = id
	}
	rev := &fakeSessionRevoker{}
	principal := sessionsTestPrincipal(userID, uuid.New(), domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{
		SessionList: repo, SessionRepo: repo, UserSession: rev, Audit: audit.NoopService{},
	})

	resp := sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": seededID.String()})
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Empty(t, rev.calls, "already-revoked session must NOT re-call the revoker")
}

func TestRevoke_MalformedUUIDIs200(t *testing.T) {
	// Wire-indistinguishable from a real success — a hostile
	// caller cannot probe with garbage UUIDs.
	userID := uuid.New()
	repo := newFakeSessionRepoForHandlerTests()
	rev := &fakeSessionRevoker{}
	principal := sessionsTestPrincipal(userID, uuid.New(), domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{
		SessionList: repo, SessionRepo: repo, UserSession: rev, Audit: audit.NoopService{},
	})
	resp := sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": "not-a-uuid"})
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Empty(t, rev.calls)
}

func TestRevoke_MalformedJSONIs400(t *testing.T) {
	userID := uuid.New()
	repo := newFakeSessionRepoForHandlerTests()
	rev := &fakeSessionRevoker{}
	principal := sessionsTestPrincipal(userID, uuid.New(), domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{
		SessionList: repo, SessionRepo: repo, UserSession: rev, Audit: audit.NoopService{},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/revoke", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRevoke_RevokerErrorIs500(t *testing.T) {
	userID := uuid.New()
	sessionID, _ := uuid.NewV7()
	repo := newFakeSessionRepoForHandlerTests()
	repo.addSession(makeSession(t, userID, func(s *domain.Session) { s.ID = sessionID }))
	rev := &fakeSessionRevoker{
		revokeFn: func(uuid.UUID, string) error { return errors.New("db down") },
	}
	principal := sessionsTestPrincipal(userID, uuid.New(), domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{
		SessionList: repo, SessionRepo: repo, UserSession: rev, Audit: audit.NoopService{},
	})
	rec := sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke", map[string]any{"session_id": sessionID.String()})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------- shape pin for monolith compatibility ----------

func TestSessionItemView_FieldNames(t *testing.T) {
	// Sanity pin: serialise an empty sessionItemView and verify
	// the JSON shape exactly matches the UI's SessionItem typescript
	// interface (idp-admin-client.ts).
	view := sessionItemView{
		ID:        "id",
		CreatedAt: "now",
		ExpiresAt: "later",
		IsActive:  true,
		IsCurrent: true,
	}
	raw, err := json.Marshal(view)
	require.NoError(t, err)
	// Required field names:
	for _, k := range []string{
		"\"id\":", "\"created_at\":", "\"expires_at\":",
		"\"last_used_at\":", "\"ip_address\":", "\"user_agent\":",
		"\"is_active\":", "\"is_current\":",
	} {
		assert.Contains(t, string(raw), k, "JSON key %q missing", k)
	}
}
