package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type revokeAllSessionsTestEngine struct {
	r              *gin.Engine
	userRepo       *recoveryStubUserRepo
	sessionRepo    *inMemorySessionRepoForHandlers
	userSession    *service.UserSessionService
	rec            *audit.Recorder
	sessionRevoker *service.RecorderSessionRevoker
	refreshRevoker *service.RecorderRefreshTokenRevoker
}

func newRevokeAllSessionsEngine(t *testing.T, principal *domain.Principal) revokeAllSessionsTestEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	userRepo := newRecoveryStubUserRepo()
	sessionRepo := newSessionRepoForHandlers()
	userSession := service.NewUserSessionService(nil, sessionRepo, service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	rec := &audit.Recorder{}
	sessionRevoker := &service.RecorderSessionRevoker{}
	refreshRevoker := &service.RecorderRefreshTokenRevoker{CountToReturn: 3}
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		UserLookup:          userRepo,
		UserSession:         userSession,
		SessionLookup:       sessionRepo,
		SessionRevoker:      sessionRevoker,
		RefreshTokenRevoker: refreshRevoker,
		Audit:               rec,
	})
	return revokeAllSessionsTestEngine{
		r:              r,
		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		userSession:    userSession,
		rec:            rec,
		sessionRevoker: sessionRevoker,
		refreshRevoker: refreshRevoker,
	}
}

func revokeAllSessionsReq(t *testing.T, eng revokeAllSessionsTestEngine, target string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	eng.r.ServeHTTP(w, req)
	return w
}

func revokeCurrentSessionReq(t *testing.T, eng revokeAllSessionsTestEngine, target string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	eng.r.ServeHTTP(w, req)
	return w
}

func listOwnSessionsReq(t *testing.T, eng revokeAllSessionsTestEngine, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	eng.r.ServeHTTP(w, req)
	return w
}

func seedRevokeAllUser(eng revokeAllSessionsTestEngine, id, orgID uuid.UUID) *domain.User {
	secret := "MFA-SECRET-MUST-NOT-LEAK"
	u := &domain.User{
		ID:               id,
		OrganizationID:   orgID,
		Email:            "self@example.com",
		Role:             domain.RoleOrgUser,
		AuthSource:       domain.AuthSourceLocal,
		EmailVerified:    true,
		PasswordHash:     "PASSWORD-HASH-MUST-NOT-LEAK",
		MFAEnabled:       true,
		MFASecret:        &secret,
		MFARecoveryCodes: []string{"RECOVERY-CODE-MUST-NOT-LEAK"},
	}
	eng.userRepo.byID[id] = u
	return u
}

func seedSelfSession(t *testing.T, eng revokeAllSessionsTestEngine, userID uuid.UUID, mutate func(*domain.Session)) *domain.Session {
	t.Helper()
	now := time.Now().UTC()
	selector := uuid.New()
	hash := "TOKEN-HASH-MUST-NOT-LEAK"
	ip := "203.0.113.7"
	ua := "Identuum Test Browser"
	lastSeen := now.Add(3 * time.Minute)
	s := &domain.Session{
		ID:                 uuid.New(),
		UserID:             userID,
		TokenSelector:      &selector,
		TokenValidatorHash: &hash,
		IsValid:            true,
		CreatedAt:          now,
		LastUsedAt:         &lastSeen,
		ExpiresAt:          now.Add(time.Hour),
		IPAddress:          &ip,
		UserAgent:          &ua,
	}
	if mutate != nil {
		mutate(s)
	}
	created, err := eng.sessionRepo.Create(context.Background(), s)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return created
}

func TestListOwnActiveSessions_Unauthenticated401(t *testing.T) {
	eng := newRevokeAllSessionsEngine(t, nil)
	w := listOwnSessionsReq(t, eng, http.MethodGet, "/api/v1/me/sessions", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", w.Code)
	}
}

func TestListOwnActiveSessions_ReturnsOnlyOwnSafeActiveMetadata(t *testing.T) {
	uid := uuid.New()
	other := uuid.New()
	orgID := uuid.New()
	currentID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: currentID})
	seedRevokeAllUser(eng, uid, orgID)
	seedRevokeAllUser(eng, other, uuid.New())
	current := seedSelfSession(t, eng, uid, func(s *domain.Session) { s.ID = currentID })
	seedSelfSession(t, eng, uid, func(s *domain.Session) {
		s.ID = uuid.New()
		s.ExpiresAt = time.Now().Add(-time.Hour)
	})
	seedSelfSession(t, eng, other, nil)

	w := listOwnSessionsReq(t, eng, http.MethodGet, "/api/v1/me/sessions", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q; want 200", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q; want no-cache", got)
	}
	var body struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v; body=%q", err, w.Body.String())
	}
	if len(body.Sessions) != 1 {
		t.Fatalf("sessions len = %d; want 1 own active session: %#v", len(body.Sessions), body.Sessions)
	}
	got := body.Sessions[0]
	if got["created_at"] != current.CreatedAt.UTC().Format(time.RFC3339) {
		t.Errorf("created_at = %v; want %s", got["created_at"], current.CreatedAt.UTC().Format(time.RFC3339))
	}
	if got["expires_at"] != current.ExpiresAt.UTC().Format(time.RFC3339) {
		t.Errorf("expires_at = %v; want %s", got["expires_at"], current.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if got["last_seen_at"] == "" {
		t.Errorf("last_seen_at missing")
	}
	if got["user_agent"] != "Identuum Test Browser" {
		t.Errorf("user_agent = %v; want stored user agent", got["user_agent"])
	}
	if got["ip_address"] != "203.0.113.7" {
		t.Errorf("ip_address = %v; want stored IP", got["ip_address"])
	}
	if got["current_session"] != true {
		t.Errorf("current_session = %v; want true", got["current_session"])
	}
}

func TestListOwnActiveSessions_UserIDInputRejectedAndNotHonored(t *testing.T) {
	uid := uuid.New()
	other := uuid.New()
	orgID := uuid.New()
	for _, tc := range []struct {
		name   string
		target string
		body   string
	}{
		{name: "query", target: "/api/v1/me/sessions?user_id=" + other.String()},
		{name: "body", target: "/api/v1/me/sessions", body: `{"user_id":"` + other.String() + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
			seedRevokeAllUser(eng, uid, orgID)
			seedRevokeAllUser(eng, other, uuid.New())
			seedSelfSession(t, eng, uid, nil)
			seedSelfSession(t, eng, other, nil)

			w := listOwnSessionsReq(t, eng, http.MethodGet, tc.target, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d; want 400 invalid_request", w.Code)
			}
			if strings.Contains(w.Body.String(), other.String()) {
				t.Fatalf("response honored other user input: %q", w.Body.String())
			}
		})
	}
}

func TestListOwnActiveSessions_StaleBannedDeletedRejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*domain.User)
		seed   bool
	}{
		{name: "missing"},
		{name: "banned", seed: true, mutate: func(u *domain.User) { u.Banned = true }},
		{name: "deleted", seed: true, mutate: func(u *domain.User) {
			now := time.Now().UTC()
			u.DeletedAt = &now
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid := uuid.New()
			orgID := uuid.New()
			eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
			if tc.seed {
				u := seedRevokeAllUser(eng, uid, orgID)
				tc.mutate(u)
			}
			seedSelfSession(t, eng, uid, nil)
			w := listOwnSessionsReq(t, eng, http.MethodGet, "/api/v1/me/sessions", "")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d; want 401", w.Code)
			}
			if !strings.Contains(w.Body.String(), `"error":"unauthorized"`) {
				t.Fatalf("body = %q; want opaque unauthorized", w.Body.String())
			}
		})
	}
}

func TestListOwnActiveSessions_ResponseDoesNotLeakCredentialMaterial(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: uuid.New()})
	seedRevokeAllUser(eng, uid, orgID)
	s := seedSelfSession(t, eng, uid, nil)

	w := listOwnSessionsReq(t, eng, http.MethodGet, "/api/v1/me/sessions", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	combined := w.Body.String() + "\n" + w.Header().Get("Set-Cookie") + "\n" + w.Header().Get("Authorization")
	for _, forbidden := range []string{
		s.ID.String(),
		"session_id",
		"cookie",
		"access_token",
		"refresh_token",
		"token_selector",
		"token_hash",
		"validator_hash",
		"TOKEN-HASH-MUST-NOT-LEAK",
		"PASSWORD-HASH-MUST-NOT-LEAK",
		"MFA-SECRET-MUST-NOT-LEAK",
		"RECOVERY-CODE-MUST-NOT-LEAK",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("response leaked %q: %q", forbidden, combined)
		}
	}
}

func TestListOwnActiveSessions_RouteIsGETOnly(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	seedRevokeAllUser(eng, uid, orgID)
	// POSITIVE CONTROL — the route must EXIST, or the fence below passes against
	// an unmounted path: a 404 to every verb satisfies "not 200" exactly as a
	// correct method rejection does.
	//
	// THIS ONE WAS MISSED. The last slice claimed five fences fixed and its own
	// red-proof reported four controls firing; the two numbers disagreed and the
	// smaller one was right. This function shares a FILE with
	// TestRevokeAllOwnSessions_RouteIsPOSTOnly, a control landed there, and the
	// FILE counted as done while this function stayed bare. That is why the V2
	// filter is now run per FUNCTION, never per file.
	{
		ctlW := listOwnSessionsReq(t, eng, http.MethodGet, "/api/v1/me/sessions", "")
		if ctlW.Code == http.StatusNotFound {
			t.Fatalf("CONTROL FAILED: GET /api/v1/me/sessions is not mounted (404); the method " +
				"fence below would pass against a route that does not exist")
		}
	}

	for _, verb := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := listOwnSessionsReq(t, eng, verb, "/api/v1/me/sessions", "")
		if w.Code == http.StatusOK {
			t.Fatalf("%s /api/v1/me/sessions returned 200; route must be GET-only", verb)
		}
	}
}

func TestRevokeAllOwnSessions_Unauthenticated401(t *testing.T) {
	eng := newRevokeAllSessionsEngine(t, nil)
	w := revokeAllSessionsReq(t, eng, "/api/v1/me/sessions/revoke-all", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", w.Code)
	}
	if len(eng.sessionRevoker.Calls()) != 0 {
		t.Fatalf("session revoker called unauthenticated: %+v", eng.sessionRevoker.Calls())
	}
	if len(eng.refreshRevoker.Calls()) != 0 {
		t.Fatalf("refresh revoker called unauthenticated: %+v", eng.refreshRevoker.Calls())
	}
}

func TestRevokeCurrentOwnSession_UnauthenticatedOrMissingSession401(t *testing.T) {
	eng := newRevokeAllSessionsEngine(t, nil)
	w := revokeCurrentSessionReq(t, eng, "/api/v1/me/sessions/revoke-current", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d; want 401", w.Code)
	}

	uid := uuid.New()
	orgID := uuid.New()
	eng = newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	seedRevokeAllUser(eng, uid, orgID)
	w = revokeCurrentSessionReq(t, eng, "/api/v1/me/sessions/revoke-current", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing SessionID status = %d; want 401", w.Code)
	}
}

func TestRevokeCurrentOwnSession_RevokesOnlyCurrentSession(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	currentID := uuid.New()
	otherID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: currentID})
	seedRevokeAllUser(eng, uid, orgID)
	current := seedSelfSession(t, eng, uid, func(s *domain.Session) { s.ID = currentID })
	other := seedSelfSession(t, eng, uid, func(s *domain.Session) { s.ID = otherID })

	w := revokeCurrentSessionReq(t, eng, "/api/v1/me/sessions/revoke-current", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; body=%q; want 204", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q; want no-cache", got)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("body = %q; want empty 204 body", w.Body.String())
	}
	if got := eng.sessionRepo.byID[current.ID]; got == nil || got.RevokedAt == nil {
		t.Fatalf("current session was not revoked")
	}
	if got := eng.sessionRepo.byID[current.ID].RevokedReason; got == nil || *got != selfRevokeCurrentSessionReason {
		t.Fatalf("current session reason = %v; want %q", got, selfRevokeCurrentSessionReason)
	}
	if got := eng.sessionRepo.byID[other.ID]; got == nil || got.RevokedAt != nil {
		t.Fatalf("non-current session was revoked")
	}
	if len(eng.refreshRevoker.Calls()) != 0 {
		t.Fatalf("refresh revoker called for current-session-only revoke: %+v", eng.refreshRevoker.Calls())
	}
}

func TestRevokeCurrentOwnSession_RejectsTargetInputAndDoesNotRevoke(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	currentID := uuid.New()
	otherID := uuid.New()
	for _, tc := range []struct {
		name   string
		target string
		body   string
	}{
		{name: "session_id query", target: "/api/v1/me/sessions/revoke-current?session_id=" + otherID.String()},
		{name: "user_id query", target: "/api/v1/me/sessions/revoke-current?user_id=" + uuid.New().String()},
		{name: "subject query", target: "/api/v1/me/sessions/revoke-current?subject=x"},
		{name: "organization_id query", target: "/api/v1/me/sessions/revoke-current?organization_id=" + orgID.String()},
		{name: "body", target: "/api/v1/me/sessions/revoke-current", body: `{"session_id":"` + otherID.String() + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: currentID})
			seedRevokeAllUser(eng, uid, orgID)
			current := seedSelfSession(t, eng, uid, func(s *domain.Session) { s.ID = currentID })
			other := seedSelfSession(t, eng, uid, func(s *domain.Session) { s.ID = otherID })

			w := revokeCurrentSessionReq(t, eng, tc.target, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d; want 400 invalid_request", w.Code)
			}
			if eng.sessionRepo.byID[current.ID].RevokedAt != nil {
				t.Fatalf("current session revoked despite target input")
			}
			if eng.sessionRepo.byID[other.ID].RevokedAt != nil {
				t.Fatalf("other session revoked from target input")
			}
		})
	}
}

func TestRevokeCurrentOwnSession_StaleUserOrSessionRejected(t *testing.T) {
	for _, tc := range []struct {
		name          string
		seedUser      bool
		mutateUser    func(*domain.User)
		mutateSession func(*domain.Session)
	}{
		{name: "missing user"},
		{name: "banned user", seedUser: true, mutateUser: func(u *domain.User) { u.Banned = true }},
		{name: "deleted user", seedUser: true, mutateUser: func(u *domain.User) {
			now := time.Now().UTC()
			u.DeletedAt = &now
		}},
		{name: "revoked session", seedUser: true, mutateSession: func(s *domain.Session) {
			now := time.Now().UTC()
			s.RevokedAt = &now
		}},
		{name: "expired session", seedUser: true, mutateSession: func(s *domain.Session) {
			s.ExpiresAt = time.Now().UTC().Add(-time.Minute)
		}},
		{name: "wrong user session", seedUser: true, mutateSession: func(s *domain.Session) {
			s.UserID = uuid.New()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid := uuid.New()
			orgID := uuid.New()
			currentID := uuid.New()
			eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: currentID})
			if tc.seedUser {
				u := seedRevokeAllUser(eng, uid, orgID)
				if tc.mutateUser != nil {
					tc.mutateUser(u)
				}
			}
			session := seedSelfSession(t, eng, uid, func(s *domain.Session) {
				s.ID = currentID
				if tc.mutateSession != nil {
					tc.mutateSession(s)
				}
			})

			w := revokeCurrentSessionReq(t, eng, "/api/v1/me/sessions/revoke-current", "")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d; want 401", w.Code)
			}
			if tc.mutateSession == nil && eng.sessionRepo.byID[session.ID].RevokedAt != nil {
				t.Fatalf("session was revoked on stale-user rejection")
			}
		})
	}
}

func TestRevokeCurrentOwnSession_ResponseAndAuditDoNotLeakSensitiveMaterial(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	currentID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: currentID})
	seedRevokeAllUser(eng, uid, orgID)
	seedSelfSession(t, eng, uid, func(s *domain.Session) { s.ID = currentID })

	w := revokeCurrentSessionReq(t, eng, "/api/v1/me/sessions/revoke-current", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", w.Code)
	}
	combined := w.Body.String() + "\n" + w.Header().Get("Set-Cookie") + "\n" + w.Header().Get("Authorization")
	for _, forbidden := range []string{
		currentID.String(),
		"session_id",
		"cookie",
		"access_token",
		"refresh_token",
		"token_hash",
		"validator_hash",
		"PASSWORD-HASH-MUST-NOT-LEAK",
		"MFA-SECRET-MUST-NOT-LEAK",
		"RECOVERY-CODE-MUST-NOT-LEAK",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("response leaked %q: %q", forbidden, combined)
		}
	}
	events := eng.rec.Events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d; want 1", len(events))
	}
	e := events[0]
	if e.Action != string(domain.AuditSessionRevoked) {
		t.Fatalf("audit action = %q; want %q", e.Action, domain.AuditSessionRevoked)
	}
	if e.ActorID != uid || e.SubjectID != uid || e.OrganizationID != orgID {
		t.Fatalf("audit identifiers not bound to authenticated user/org: %+v", e)
	}
	for k, v := range e.Metadata {
		ks := strings.ToLower(k)
		if strings.Contains(ks, "session_id") || strings.Contains(ks, "token_hash") || strings.Contains(ks, "password") || strings.Contains(ks, "secret") {
			t.Fatalf("audit metadata leaked sensitive key %q", k)
		}
		if s, ok := v.(string); ok && strings.Contains(s, currentID.String()) {
			t.Fatalf("audit metadata leaked current session id in %s", k)
		}
	}
}

func TestRevokeAllOwnSessions_RevokesOwnSessionsAndRefreshTokens(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	seedRevokeAllUser(eng, uid, orgID)

	w := revokeAllSessionsReq(t, eng, "/api/v1/me/sessions/revoke-all", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; body=%q; want 204", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q; want no-cache", got)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("body = %q; want empty 204 body", w.Body.String())
	}

	sessionCalls := eng.sessionRevoker.Calls()
	if len(sessionCalls) != 1 {
		t.Fatalf("session revoker calls = %+v; want one", sessionCalls)
	}
	if sessionCalls[0].UserID != uid {
		t.Errorf("session revoker user = %s; want authenticated user %s", sessionCalls[0].UserID, uid)
	}
	if sessionCalls[0].Reason != selfRevokeAllSessionsReason {
		t.Errorf("session revoker reason = %q; want %q", sessionCalls[0].Reason, selfRevokeAllSessionsReason)
	}
	if got, _ := sessionCalls[0].Metadata["organization_id"].(string); got != orgID.String() {
		t.Errorf("session revoker organization_id = %q; want %s", got, orgID)
	}

	refreshCalls := eng.refreshRevoker.Calls()
	if len(refreshCalls) != 1 || refreshCalls[0].UserID != uid {
		t.Fatalf("refresh revoker calls = %+v; want authenticated user", refreshCalls)
	}
}

func TestRevokeAllOwnSessions_StaleBannedDeletedRejectedWithoutRevokers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*domain.User)
		seed   bool
	}{
		{name: "missing"},
		{name: "banned", seed: true, mutate: func(u *domain.User) { u.Banned = true }},
		{name: "deleted", seed: true, mutate: func(u *domain.User) {
			now := time.Now().UTC()
			u.DeletedAt = &now
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid := uuid.New()
			orgID := uuid.New()
			eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
			if tc.seed {
				u := seedRevokeAllUser(eng, uid, orgID)
				tc.mutate(u)
			}
			w := revokeAllSessionsReq(t, eng, "/api/v1/me/sessions/revoke-all", "")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d; want 401", w.Code)
			}
			if !strings.Contains(w.Body.String(), `"error":"unauthorized"`) {
				t.Fatalf("body = %q; want opaque unauthorized", w.Body.String())
			}
			if len(eng.sessionRevoker.Calls()) != 0 {
				t.Fatalf("session revoker called: %+v", eng.sessionRevoker.Calls())
			}
			if len(eng.refreshRevoker.Calls()) != 0 {
				t.Fatalf("refresh revoker called: %+v", eng.refreshRevoker.Calls())
			}
		})
	}
}

func TestRevokeAllOwnSessions_UserIDInputRejectedAndNotHonored(t *testing.T) {
	uid := uuid.New()
	other := uuid.New()
	orgID := uuid.New()
	for _, tc := range []struct {
		name   string
		target string
		body   string
	}{
		{name: "query", target: "/api/v1/me/sessions/revoke-all?user_id=" + other.String()},
		{name: "body", target: "/api/v1/me/sessions/revoke-all", body: `{"user_id":"` + other.String() + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
			seedRevokeAllUser(eng, uid, orgID)
			seedRevokeAllUser(eng, other, uuid.New())

			w := revokeAllSessionsReq(t, eng, tc.target, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d; want 400 invalid_request", w.Code)
			}
			if len(eng.sessionRevoker.Calls()) != 0 {
				t.Fatalf("session revoker honored user input: %+v", eng.sessionRevoker.Calls())
			}
			if len(eng.refreshRevoker.Calls()) != 0 {
				t.Fatalf("refresh revoker honored user input: %+v", eng.refreshRevoker.Calls())
			}
		})
	}
}

func TestRevokeAllOwnSessions_OtherUserStateNotTouched(t *testing.T) {
	uid := uuid.New()
	other := uuid.New()
	orgID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	seedRevokeAllUser(eng, uid, orgID)
	otherUser := seedRevokeAllUser(eng, other, uuid.New())
	otherHash := otherUser.PasswordHash

	w := revokeAllSessionsReq(t, eng, "/api/v1/me/sessions/revoke-all", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", w.Code)
	}
	if got := eng.userRepo.byID[other].PasswordHash; got != otherHash {
		t.Fatalf("other user mutated: password hash %q -> %q", otherHash, got)
	}
	for _, call := range eng.sessionRevoker.Calls() {
		if call.UserID == other {
			t.Fatalf("session revoker touched other user: %+v", call)
		}
	}
	for _, call := range eng.refreshRevoker.Calls() {
		if call.UserID == other {
			t.Fatalf("refresh revoker touched other user: %+v", call)
		}
	}
}

func TestRevokeAllOwnSessions_RevokerFailuresAreBestEffort(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	eng.sessionRevoker.Err = errors.New("session revoker outage")
	eng.refreshRevoker.Err = errors.New("refresh revoker outage")
	seedRevokeAllUser(eng, uid, orgID)

	w := revokeAllSessionsReq(t, eng, "/api/v1/me/sessions/revoke-all", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204 best-effort", w.Code)
	}
	if len(eng.sessionRevoker.Calls()) != 1 {
		t.Fatalf("session revoker calls = %+v; want one", eng.sessionRevoker.Calls())
	}
	if len(eng.refreshRevoker.Calls()) != 1 {
		t.Fatalf("refresh revoker calls = %+v; want one", eng.refreshRevoker.Calls())
	}
}

func TestRevokeAllOwnSessions_ResponseAndAuditDoNotLeakSensitiveMaterial(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	seedRevokeAllUser(eng, uid, orgID)

	w := revokeAllSessionsReq(t, eng, "/api/v1/me/sessions/revoke-all", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", w.Code)
	}
	combined := w.Body.String() + "\n" + w.Header().Get("Set-Cookie") + "\n" + w.Header().Get("Authorization")
	for _, forbidden := range []string{
		"session_id",
		"cookie",
		"access_token",
		"refresh_token",
		"token_hash",
		"validator_hash",
		"PASSWORD-HASH-MUST-NOT-LEAK",
		"MFA-SECRET-MUST-NOT-LEAK",
		"RECOVERY-CODE-MUST-NOT-LEAK",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("response leaked %q: %q", forbidden, combined)
		}
	}

	events := eng.rec.Events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d; want 1: %+v", len(events), events)
	}
	e := events[0]
	if e.Action != string(domain.AuditSelfSessionsRevoked) {
		t.Fatalf("audit action = %q; want %q", e.Action, domain.AuditSelfSessionsRevoked)
	}
	if e.ActorID != uid || e.SubjectID != uid || e.OrganizationID != orgID {
		t.Fatalf("audit identifiers not bound to authenticated user/org: %+v", e)
	}
	if got, _ := e.Metadata["user_id"].(string); got != uid.String() {
		t.Errorf("audit user_id = %q; want %s", got, uid)
	}
	if got, _ := e.Metadata["organization_id"].(string); got != orgID.String() {
		t.Errorf("audit organization_id = %q; want %s", got, orgID)
	}
	if got, _ := e.Metadata["sessions_revoked"].(bool); !got {
		t.Errorf("audit sessions_revoked = %v; want true", e.Metadata["sessions_revoked"])
	}
	if got, _ := e.Metadata["refresh_tokens_revoked_count"].(int64); got != 3 {
		t.Errorf("audit refresh_tokens_revoked_count = %v; want 3", e.Metadata["refresh_tokens_revoked_count"])
	}
	for k, v := range e.Metadata {
		ks := strings.ToLower(k)
		if strings.Contains(ks, "session_id") || strings.Contains(ks, "token_hash") || strings.Contains(ks, "password") || strings.Contains(ks, "secret") {
			t.Fatalf("audit metadata leaked sensitive key %q", k)
		}
		if s, ok := v.(string); ok {
			for _, forbidden := range []string{"PASSWORD-HASH-MUST-NOT-LEAK", "MFA-SECRET-MUST-NOT-LEAK", "RECOVERY-CODE-MUST-NOT-LEAK"} {
				if strings.Contains(s, forbidden) {
					t.Fatalf("audit metadata leaked %q in %s=%q", forbidden, k, s)
				}
			}
		}
	}
}

func TestRevokeAllOwnSessions_RouteIsPOSTOnly(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	seedRevokeAllUser(eng, uid, orgID)
	// POSITIVE CONTROL FIRST — the route must EXIST for the method fence below
	// to mean anything. Without this, an unmounted route answers 404 to every
	// verb and this test passes green while the POST endpoint it protects does
	// not exist at all.
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/me/sessions/revoke-all", nil)
	postW := httptest.NewRecorder()
	eng.r.ServeHTTP(postW, postReq)
	if postW.Code == http.StatusNotFound {
		t.Fatalf("CONTROL FAILED: POST /api/v1/me/sessions/revoke-all is not mounted (404), so " +
			"the method fence below would pass against a route that does not exist")
	}

	for _, verb := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(verb, "/api/v1/me/sessions/revoke-all", nil)
		w := httptest.NewRecorder()
		eng.r.ServeHTTP(w, req)
		if w.Code == http.StatusNoContent {
			t.Fatalf("%s returned 204; route must be POST-only", verb)
		}
	}
}
