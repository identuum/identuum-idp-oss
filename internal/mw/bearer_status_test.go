package mw

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// R3 — bearer-path COMBINED session+user+org live-status check.
//
// These tests exercise the defense-in-depth gate added to BearerPrincipal:
// a USER-SESSION token (non-nil SessionID) is accepted only when the session
// is usable AND the user is active+not-deleted AND the org is active+not-
// deleted. They reuse the package helpers (revocationEngine, doProbe,
// usableSession, stubVerifier, stubSessionLookup) from bearer_revocation_test.go;
// the stub's `info` field returns a verbatim SessionValidationInfo so the
// user/org dimensions can be driven without a DB. The single combined lookup
// (GetSessionWithUserAndOrgStatus) means no extra per-request round-trip.

// sessionPrincipalVerifier returns a verifier for a user-session token
// (non-nil SessionID) — the shape minted by IssueForSession.
func sessionPrincipalVerifier() *stubVerifier {
	return &stubVerifier{principal: &domain.Principal{
		UserID: uuid.New(), Role: domain.RoleOrgUser, SessionID: uuid.New(),
	}}
}

// liveStatus is a healthy combined status backing a usable session.
func liveStatus() *domain.SessionValidationInfo {
	return &domain.SessionValidationInfo{Session: usableSession(), UserActive: true, OrgActive: true}
}

// (a) HAPPY PATH — active user, active org, live session → 200 (unchanged).
func TestBearerStatus_ActiveUserActiveOrgLiveSession_Admitted(t *testing.T) {
	sessions := &stubSessionLookup{info: liveStatus()}
	code := doProbe(revocationEngine(sessionPrincipalVerifier(), sessions))
	t.Logf("EVIDENCE (a) active/active/live: status=%d calls=%d", code, sessions.calls)
	if code != http.StatusOK {
		t.Fatalf("active user + active org + live session: status=%d, want 200", code)
	}
	if sessions.calls != 1 {
		t.Errorf("expected exactly one combined lookup, got %d", sessions.calls)
	}
}

// (b) USER BAN / DELETE — an otherwise-live user-session token is rejected
// when the user is banned (UserActive=false) or deleted (UserDeleted=true).
func TestBearerStatus_BannedOrDeletedUserRejected(t *testing.T) {
	cases := []struct {
		name string
		info *domain.SessionValidationInfo
	}{
		{"banned user (UserActive=false)", &domain.SessionValidationInfo{Session: usableSession(), UserActive: false, OrgActive: true}},
		{"deleted user (UserDeleted=true)", &domain.SessionValidationInfo{Session: usableSession(), UserActive: true, UserDeleted: true, OrgActive: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessions := &stubSessionLookup{info: tc.info}
			code := doProbe(revocationEngine(sessionPrincipalVerifier(), sessions))
			t.Logf("EVIDENCE (b) %s: status=%d", tc.name, code)
			if code != http.StatusUnauthorized {
				t.Fatalf("%s: status=%d, want 401", tc.name, code)
			}
		})
	}
}

// (c) ORG INACTIVE / DELETED — a member of a deactivated (OrgActive=false) or
// deleted (OrgDeleted=true) org is rejected even with a live session.
func TestBearerStatus_InactiveOrDeletedOrgRejected(t *testing.T) {
	cases := []struct {
		name string
		info *domain.SessionValidationInfo
	}{
		{"inactive org (OrgActive=false)", &domain.SessionValidationInfo{Session: usableSession(), UserActive: true, OrgActive: false}},
		{"deleted org (OrgDeleted=true)", &domain.SessionValidationInfo{Session: usableSession(), UserActive: true, OrgActive: true, OrgDeleted: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessions := &stubSessionLookup{info: tc.info}
			code := doProbe(revocationEngine(sessionPrincipalVerifier(), sessions))
			t.Logf("EVIDENCE (c) %s: status=%d", tc.name, code)
			if code != http.StatusUnauthorized {
				t.Fatalf("%s: status=%d, want 401", tc.name, code)
			}
		})
	}
}

// (d) M2M EXEMPTION — a client token (nil SessionID) is admitted and triggers
// NO session/user/org lookup, even when the store would report a banned user.
func TestBearerStatus_M2MTokenExemptNoStatusLookup(t *testing.T) {
	v := &stubVerifier{principal: &domain.Principal{ClientID: "svc-1", Scope: "m2m:read"}}
	// A status that WOULD reject (banned user) must never be consulted.
	sessions := &stubSessionLookup{info: &domain.SessionValidationInfo{Session: usableSession(), UserActive: false, OrgActive: false}}
	code := doProbe(revocationEngine(v, sessions))
	t.Logf("EVIDENCE (d) M2M: status=%d calls=%d", code, sessions.calls)
	if code != http.StatusOK {
		t.Fatalf("M2M token: status=%d, want 200 (exempt)", code)
	}
	if sessions.calls != 0 {
		t.Errorf("M2M token must NOT trigger a user/org status lookup, got %d call(s)", sessions.calls)
	}
}

// (e) FAIL-CLOSED — a combined-lookup error rejects the user-session request.
// AUTH-503: as a 503 (store error), never the 401 verdict.
func TestBearerStatus_LookupErrorFailsClosed(t *testing.T) {
	sessions := &stubSessionLookup{err: errors.New("status store unavailable")}
	code := doProbe(revocationEngine(sessionPrincipalVerifier(), sessions))
	t.Logf("EVIDENCE (e) lookup error: status=%d", code)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status-store error: status=%d, want 503 (fail-closed as a store error, not a verdict)", code)
	}
}

// Guard: the org-less case (LEFT JOIN miss) is NOT a lockout. The production
// GetSessionWithUserAndOrgStatus defaults OrgActive=true when a user has no
// org; a healthy user with that default is admitted.
func TestBearerStatus_NoOrgDefaultsActiveAdmitted(t *testing.T) {
	info := &domain.SessionValidationInfo{Session: usableSession(), UserActive: true, OrgActive: true, OrganizationID: uuid.Nil}
	// sanity: CanBeUsedForAuth agrees at the domain layer.
	if ok, reason := info.CanBeUsedForAuth(time.Now().UTC()); !ok {
		t.Fatalf("org-less healthy principal should be usable, got reject: %s", reason)
	}
	sessions := &stubSessionLookup{info: info}
	code := doProbe(revocationEngine(sessionPrincipalVerifier(), sessions))
	t.Logf("EVIDENCE (org-less default-active): status=%d", code)
	if code != http.StatusOK {
		t.Fatalf("org-less healthy principal: status=%d, want 200", code)
	}
}
