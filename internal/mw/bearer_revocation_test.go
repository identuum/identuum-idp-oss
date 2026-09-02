package mw

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// stubSessionLookup is the in-test SessionRevocationLookup. It records how
// many times the combined lookup was invoked so the M2M-exemption test can
// prove NO session lookup happens for nil-SessionID (machine) tokens.
//
//   - err set        → lookup fails (fail-closed path).
//   - info set        → returned verbatim (drives the R3 user/org-status cases).
//   - else session set → wrapped as a fully-ACTIVE user+org SessionValidationInfo
//     (so a live session is admitted and a revoked one is rejected by the
//     session-usability check, exactly as the pre-R3 GetByID stub did).
//   - else (nil)      → not found.
type stubSessionLookup struct {
	session *domain.Session
	info    *domain.SessionValidationInfo
	err     error
	calls   int
}

func (s *stubSessionLookup) GetSessionWithUserAndOrgStatus(_ context.Context, _ uuid.UUID) (*domain.SessionValidationInfo, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if s.info != nil {
		return s.info, nil
	}
	if s.session == nil {
		return nil, nil
	}
	return &domain.SessionValidationInfo{Session: s.session, UserActive: true, OrgActive: true}, nil
}

// revocationEngine wires BearerPrincipal(verifier, sessions) in front of a
// bare 200 probe (NO downstream authz guard) so the response code reflects
// ONLY the bearer-path decision: 200 = token accepted (c.Next reached),
// 401 = rejected by BearerPrincipal itself.
func revocationEngine(verifier TokenVerifier, sessions SessionRevocationLookup) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BearerPrincipal(nil, verifier, sessions, nil))
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func doProbe(r *gin.Engine) int {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

func usableSession() *domain.Session {
	return &domain.Session{ID: uuid.New(), IsValid: true, ExpiresAt: time.Now().Add(time.Hour)}
}

func revokedSession() *domain.Session {
	now := time.Now().UTC()
	reason := "logout"
	return &domain.Session{
		ID:            uuid.New(),
		IsValid:       true, // exercise the RevokedAt branch specifically, not IsValid
		RevokedAt:     &now,
		RevokedReason: &reason,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
}

// stubRevocation is the in-test BearerRevocationLookup. err set → store failure
// (fail-closed path); otherwise a jti in `revoked` reports revoked.
type stubRevocation struct {
	revoked map[string]bool
	err     error
}

func (s *stubRevocation) IsRevoked(_ context.Context, jti string) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.revoked[jti], nil
}

func revocationEngineWithJTI(verifier TokenVerifier, sessions SessionRevocationLookup, revocations BearerRevocationLookup) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BearerPrincipal(nil, verifier, sessions, revocations))
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

// P0-6 (THE regression that matters): a revoked M2M / service-account token —
// jti set, NO session_id — is REJECTED on a protected route. This PASSED with
// the bug: the SessionID gate skipped M2M tokens entirely AND the verifier
// dropped the jti from the principal, so the revocation could never take
// effect. No session lookup is consulted for an M2M token.
func TestBearerRevocation_RevokedM2MTokenRejected(t *testing.T) {
	v := &stubVerifier{principal: &domain.Principal{ClientID: "svc-1", Scope: "m2m:read", TokenID: "JTI-M2M-REVOKED"}}
	sessions := &stubSessionLookup{}
	revs := &stubRevocation{revoked: map[string]bool{"JTI-M2M-REVOKED": true}}
	code := doProbe(revocationEngineWithJTI(v, sessions, revs))
	if code != http.StatusUnauthorized {
		t.Fatalf("revoked M2M token: status = %d, want 401", code)
	}
	if sessions.calls != 0 {
		t.Errorf("M2M token must not trigger a session lookup, got %d", sessions.calls)
	}
}

// Control: a non-revoked M2M token is still accepted (revocation does not break
// machine auth).
func TestBearerRevocation_LiveM2MTokenAccepted(t *testing.T) {
	v := &stubVerifier{principal: &domain.Principal{ClientID: "svc-1", Scope: "m2m:read", TokenID: "JTI-M2M-LIVE"}}
	revs := &stubRevocation{revoked: map[string]bool{}}
	code := doProbe(revocationEngineWithJTI(v, &stubSessionLookup{}, revs))
	if code != http.StatusOK {
		t.Fatalf("live M2M token: status = %d, want 200", code)
	}
}

// P0-6: a SESSION token whose jti is revoked is rejected via the jti gate even
// when the session store reports the session LIVE — the jti check runs first.
func TestBearerRevocation_RevokedJTISessionTokenRejected(t *testing.T) {
	v := &stubVerifier{principal: &domain.Principal{
		UserID: uuid.New(), Role: domain.RoleSiteAdmin, SessionID: uuid.New(), TokenID: "JTI-SESS-REVOKED",
	}}
	revs := &stubRevocation{revoked: map[string]bool{"JTI-SESS-REVOKED": true}}
	code := doProbe(revocationEngineWithJTI(v, &stubSessionLookup{session: usableSession()}, revs))
	if code != http.StatusUnauthorized {
		t.Fatalf("revoked-jti session token: status = %d, want 401", code)
	}
}

// P0-6 fail-closed: a revocation-store ERROR rejects the token, never admits it.
// AUTH-503 (THE-SESSION-REJECTION-ROOT-CAUSE): the rejection is a 503 — the
// store erred, the token was NOT judged revoked — never the 401 verdict.
func TestBearerRevocation_StoreErrorFailsClosed(t *testing.T) {
	v := &stubVerifier{principal: &domain.Principal{ClientID: "svc-1", TokenID: "JTI-ANY"}}
	revs := &stubRevocation{err: errors.New("revocation store down")}
	code := doProbe(revocationEngineWithJTI(v, &stubSessionLookup{}, revs))
	if code != http.StatusServiceUnavailable {
		t.Fatalf("revocation-store error: status = %d, want 503 (fail-closed as a store error, not a verdict)", code)
	}
}

// Property (1): a user-session token whose session has been revoked
// server-side now receives 401 on a route that previously accepted it.
func TestBearerRevocation_RevokedUserSessionRejected(t *testing.T) {
	v := &stubVerifier{principal: &domain.Principal{
		UserID: uuid.New(), Role: domain.RoleSiteAdmin, SessionID: uuid.New(),
	}}
	sessions := &stubSessionLookup{session: revokedSession()}
	code := doProbe(revocationEngine(v, sessions))
	if code != http.StatusUnauthorized {
		t.Fatalf("revoked user-session token: status = %d, want 401", code)
	}
	if sessions.calls != 1 {
		t.Errorf("expected exactly one session lookup, got %d", sessions.calls)
	}
}

// Control: an otherwise-identical user-session token backed by a LIVE
// session is accepted — proving the rejection above is due to revocation,
// not the check rejecting every session token.
func TestBearerRevocation_LiveUserSessionAccepted(t *testing.T) {
	v := &stubVerifier{principal: &domain.Principal{
		UserID: uuid.New(), Role: domain.RoleSiteAdmin, SessionID: uuid.New(),
	}}
	sessions := &stubSessionLookup{session: usableSession()}
	code := doProbe(revocationEngine(v, sessions))
	if code != http.StatusOK {
		t.Fatalf("live user-session token: status = %d, want 200", code)
	}
}

// Property (2): a valid M2M / client-credentials token (no session_id ->
// nil SessionID) is still accepted, and NO session lookup is performed —
// the exemption does not break machine auth.
func TestBearerRevocation_M2MTokenExemptAndNoLookup(t *testing.T) {
	// M2M token shape: client_id present, SessionID nil.
	v := &stubVerifier{principal: &domain.Principal{ClientID: "svc-client-1", Scope: "m2m:read"}}
	// Even a revoked session must NOT be consulted for an M2M token.
	sessions := &stubSessionLookup{session: revokedSession()}
	code := doProbe(revocationEngine(v, sessions))
	if code != http.StatusOK {
		t.Fatalf("M2M token: status = %d, want 200 (exempt)", code)
	}
	if sessions.calls != 0 {
		t.Errorf("M2M token must NOT trigger a session lookup, got %d call(s)", sessions.calls)
	}
}

// Property (3): when the session-store lookup itself errors, a
// user-session request is rejected (fail-closed) — a transient store
// failure must not admit a possibly-revoked token. AUTH-503: the rejection
// is a 503 (store error, ERROR-logged), never the 401 verdict.
// RULE: P0-JTI-1
func TestBearerRevocation_LookupErrorFailsClosed(t *testing.T) {
	v := &stubVerifier{principal: &domain.Principal{
		UserID: uuid.New(), Role: domain.RoleSiteAdmin, SessionID: uuid.New(),
	}}
	sessions := &stubSessionLookup{err: errors.New("session store unavailable")}
	code := doProbe(revocationEngine(v, sessions))
	if code != http.StatusServiceUnavailable {
		t.Fatalf("session-store error: status = %d, want 503 (fail-closed as a store error, not a verdict)", code)
	}
}

// Property (4): an authorization_code-grant user access token carries a
// session_id (minted via IssueForSession), so it is CHECKED like an
// interactive session — when the underlying login session is revoked the
// token is rejected (coupled decision).
func TestBearerRevocation_AuthCodeGrantTokenCoupledToSession(t *testing.T) {
	// authorization_code-grant user token: sub=user + session_id present.
	v := &stubVerifier{principal: &domain.Principal{
		UserID: uuid.New(), Role: domain.RoleSiteAdmin, SessionID: uuid.New(),
	}}
	sessions := &stubSessionLookup{session: revokedSession()}
	code := doProbe(revocationEngine(v, sessions))
	if code != http.StatusUnauthorized {
		t.Fatalf("authorization_code-grant token after session revoke: status = %d, want 401 (coupled)", code)
	}
}

// Fail-closed also covers a missing (deleted / pruned) session row.
func TestBearerRevocation_SessionNotFoundRejected(t *testing.T) {
	v := &stubVerifier{principal: &domain.Principal{
		UserID: uuid.New(), Role: domain.RoleSiteAdmin, SessionID: uuid.New(),
	}}
	sessions := &stubSessionLookup{session: nil} // not found, no error
	code := doProbe(revocationEngine(v, sessions))
	if code != http.StatusUnauthorized {
		t.Fatalf("missing session row: status = %d, want 401", code)
	}
}

// When no session store is wired (nil), the check is skipped (no panic) —
// preserving the no-DB scaffold behaviour.
func TestBearerRevocation_NilStoreSkipsCheck(t *testing.T) {
	v := &stubVerifier{principal: &domain.Principal{
		UserID: uuid.New(), Role: domain.RoleSiteAdmin, SessionID: uuid.New(),
	}}
	code := doProbe(revocationEngine(v, nil))
	if code != http.StatusOK {
		t.Fatalf("nil session store: status = %d, want 200 (check skipped)", code)
	}
}
