package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func revokeOtherSessionsReq(t *testing.T, eng revokeAllSessionsTestEngine, target string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	eng.r.ServeHTTP(w, req)
	return w
}

func TestRevokeOtherOwnSessions_UnauthenticatedOrMissingSession401(t *testing.T) {
	eng := newRevokeAllSessionsEngine(t, nil)
	w := revokeOtherSessionsReq(t, eng, "/api/v1/me/sessions/revoke-others", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d; want 401", w.Code)
	}

	uid := uuid.New()
	orgID := uuid.New()
	eng = newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	seedRevokeAllUser(eng, uid, orgID)
	w = revokeOtherSessionsReq(t, eng, "/api/v1/me/sessions/revoke-others", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing SessionID status = %d; want 401", w.Code)
	}
}

func TestRevokeOtherOwnSessions_RevokesOthersAndPreservesCurrent(t *testing.T) {
	uid := uuid.New()
	otherUserID := uuid.New()
	orgID := uuid.New()
	currentID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: currentID})
	seedRevokeAllUser(eng, uid, orgID)
	seedRevokeAllUser(eng, otherUserID, uuid.New())
	current := seedSelfSession(t, eng, uid, func(s *domain.Session) { s.ID = currentID })
	otherOne := seedSelfSession(t, eng, uid, nil)
	otherTwo := seedSelfSession(t, eng, uid, nil)
	otherUser := seedSelfSession(t, eng, otherUserID, nil)

	w := revokeOtherSessionsReq(t, eng, "/api/v1/me/sessions/revoke-others", "")
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
	if got := eng.sessionRepo.byID[current.ID]; got == nil || got.RevokedAt != nil {
		t.Fatalf("current session was revoked")
	}
	for _, session := range []*domain.Session{otherOne, otherTwo} {
		got := eng.sessionRepo.byID[session.ID]
		if got == nil || got.RevokedAt == nil {
			t.Fatalf("other session %s was not revoked", session.ID)
		}
		if got.RevokedReason == nil || *got.RevokedReason != selfRevokeOtherSessionsReason {
			t.Fatalf("other session reason = %v; want %q", got.RevokedReason, selfRevokeOtherSessionsReason)
		}
	}
	if got := eng.sessionRepo.byID[otherUser.ID]; got == nil || got.RevokedAt != nil {
		t.Fatalf("different user's session was revoked")
	}
	if len(eng.refreshRevoker.Calls()) != 0 {
		t.Fatalf("refresh revoker called for other-session revoke: %+v", eng.refreshRevoker.Calls())
	}
}

func TestRevokeOtherOwnSessions_RejectsTargetInputAndDoesNotRevoke(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	currentID := uuid.New()
	otherID := uuid.New()
	for _, tc := range []struct {
		name   string
		target string
		body   string
	}{
		{name: "session_id query", target: "/api/v1/me/sessions/revoke-others?session_id=" + otherID.String()},
		{name: "user_id query", target: "/api/v1/me/sessions/revoke-others?user_id=" + uuid.New().String()},
		{name: "subject query", target: "/api/v1/me/sessions/revoke-others?subject=x"},
		{name: "organization_id query", target: "/api/v1/me/sessions/revoke-others?organization_id=" + orgID.String()},
		{name: "body", target: "/api/v1/me/sessions/revoke-others", body: `{"session_id":"` + otherID.String() + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: currentID})
			seedRevokeAllUser(eng, uid, orgID)
			current := seedSelfSession(t, eng, uid, func(s *domain.Session) { s.ID = currentID })
			other := seedSelfSession(t, eng, uid, func(s *domain.Session) { s.ID = otherID })

			w := revokeOtherSessionsReq(t, eng, tc.target, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d; want 400 invalid_request", w.Code)
			}
			if eng.sessionRepo.byID[current.ID].RevokedAt != nil {
				t.Fatalf("current session revoked despite target input")
			}
			if eng.sessionRepo.byID[other.ID].RevokedAt != nil {
				t.Fatalf("other session revoked despite target input")
			}
		})
	}
}

func TestRevokeOtherOwnSessions_StaleUserOrSessionRejected(t *testing.T) {
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
		{name: "revoked current session", seedUser: true, mutateSession: func(s *domain.Session) {
			now := time.Now().UTC()
			s.RevokedAt = &now
		}},
		{name: "expired current session", seedUser: true, mutateSession: func(s *domain.Session) {
			s.ExpiresAt = time.Now().UTC().Add(-time.Minute)
		}},
		{name: "wrong user current session", seedUser: true, mutateSession: func(s *domain.Session) {
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
			current := seedSelfSession(t, eng, uid, func(s *domain.Session) {
				s.ID = currentID
				if tc.mutateSession != nil {
					tc.mutateSession(s)
				}
			})
			other := seedSelfSession(t, eng, uid, nil)

			w := revokeOtherSessionsReq(t, eng, "/api/v1/me/sessions/revoke-others", "")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d; want 401", w.Code)
			}
			if eng.sessionRepo.byID[current.ID].RevokedAt != nil && tc.mutateSession == nil {
				t.Fatalf("current session was revoked on stale-user rejection")
			}
			if eng.sessionRepo.byID[other.ID].RevokedAt != nil {
				t.Fatalf("other session was revoked on rejection")
			}
		})
	}
}

func TestRevokeOtherOwnSessions_ResponseAndAuditDoNotLeakSensitiveMaterial(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	currentID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: currentID})
	seedRevokeAllUser(eng, uid, orgID)
	current := seedSelfSession(t, eng, uid, func(s *domain.Session) { s.ID = currentID })
	other := seedSelfSession(t, eng, uid, nil)

	w := revokeOtherSessionsReq(t, eng, "/api/v1/me/sessions/revoke-others", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", w.Code)
	}
	combined := w.Body.String() + "\n" + w.Header().Get("Set-Cookie") + "\n" + w.Header().Get("Authorization")
	for _, forbidden := range []string{
		current.ID.String(),
		other.ID.String(),
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
	if got, _ := e.Metadata["scope"].(string); got != "other_sessions" {
		t.Errorf("audit scope = %q; want other_sessions", got)
	}
	if got, _ := e.Metadata["sessions_revoked_count"].(int); got != 1 {
		t.Errorf("audit sessions_revoked_count = %v; want 1", e.Metadata["sessions_revoked_count"])
	}
	for k, v := range e.Metadata {
		ks := strings.ToLower(k)
		if strings.Contains(ks, "session_id") || strings.Contains(ks, "token_hash") || strings.Contains(ks, "password") || strings.Contains(ks, "secret") {
			t.Fatalf("audit metadata leaked sensitive key %q", k)
		}
		if s, ok := v.(string); ok && (strings.Contains(s, current.ID.String()) || strings.Contains(s, other.ID.String())) {
			t.Fatalf("audit metadata leaked session id in %s", k)
		}
	}
}

func TestRevokeOtherOwnSessions_RouteIsPOSTOnly(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	currentID := uuid.New()
	eng := newRevokeAllSessionsEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser, SessionID: currentID})
	seedRevokeAllUser(eng, uid, orgID)
	seedSelfSession(t, eng, uid, func(s *domain.Session) { s.ID = currentID })
	// POSITIVE CONTROL — the route must EXIST, or the method fence below passes
	// against an unmounted path: a 404 to every verb satisfies "not 204" just as
	// well as a correct method rejection does.
	{
		ctlReq := httptest.NewRequest(http.MethodPost, "/api/v1/me/sessions/revoke-others", nil)
		ctlW := httptest.NewRecorder()
		eng.r.ServeHTTP(ctlW, ctlReq)
		if ctlW.Code == http.StatusNotFound {
			t.Fatalf("CONTROL FAILED: POST /api/v1/me/sessions/revoke-others is not mounted (404); the method fence " +
				"below would pass against a route that does not exist")
		}
	}

	for _, verb := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(verb, "/api/v1/me/sessions/revoke-others", nil)
		w := httptest.NewRecorder()
		eng.r.ServeHTTP(w, req)
		if w.Code == http.StatusNoContent {
			t.Fatalf("%s returned 204; route must be POST-only", verb)
		}
	}
}
