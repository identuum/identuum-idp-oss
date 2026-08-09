package mw

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// A-4 Phase 6a teeth: the session+user+org liveness verdict now runs behind
// pkg/oidc.SubjectResolver. Every test here is written to FAIL if the seam is
// reverted (BearerPrincipal calling `sessions` directly again): the stub
// resolver's verdict must be able to OVERRIDE what the real session path
// would decide, and its call count must prove when the seam is (not)
// consulted. The behaviour-identical half — every pre-seam rejection path
// still rejecting through the DEFAULT resolver — lives in the existing
// bearer_revocation_test.go suite plus the user/org status cases below.

// stubSubjectResolver is the in-test pkg/oidc.SubjectResolver.
type stubSubjectResolver struct {
	ok      bool
	err     error
	calls   int
	lastRef oidc.PrincipalRef
}

func (s *stubSubjectResolver) ResolveSubject(_ context.Context, ref oidc.PrincipalRef) (bool, error) {
	s.calls++
	s.lastRef = ref
	return s.ok, s.err
}

func resolverEngine(verifier TokenVerifier, sessions SessionRevocationLookup, opts ...BearerOption) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BearerPrincipal(nil, verifier, sessions, nil, opts...))
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

// sessionPrincipal models what OSS actually mints for an interactive session:
// UserTokenService.IssueForSession sets Subject: user.ID.String() and adds no
// `user_id` claim, so a real session principal has Sub == UserID.String()
// (internal/service/user_token_service.go). Sub is set explicitly rather than
// left zero because CONF-11 made it the field oidc.PrincipalRef.Subject is
// built from — a fixture without it models a sub-less monolith token, which is
// the exception, not the case these tests are about.
func sessionPrincipal() *domain.Principal {
	id := uuid.New()
	return &domain.Principal{Sub: id.String(), UserID: id, Role: domain.RoleSiteAdmin, SessionID: uuid.New()}
}

// ── (a) user/org status rejections through the DEFAULT resolver ─────────────
// (Session-usability rejections — revoked, expired, missing, store error —
// and the live-200 control are already pinned by bearer_revocation_test.go,
// which now runs through the default resolver.)

func statusInfo(mutate func(*domain.SessionValidationInfo)) *domain.SessionValidationInfo {
	info := &domain.SessionValidationInfo{Session: usableSession(), UserActive: true, OrgActive: true}
	mutate(info)
	return info
}

func TestSubjectResolver_DefaultPath_UserOrgStatusRejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*domain.SessionValidationInfo)
	}{
		{"banned_user", func(i *domain.SessionValidationInfo) { i.UserActive = false }},
		{"deleted_user", func(i *domain.SessionValidationInfo) { i.UserDeleted = true }},
		{"inactive_org", func(i *domain.SessionValidationInfo) { i.OrgActive = false }},
		{"deleted_org", func(i *domain.SessionValidationInfo) { i.OrgDeleted = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := &stubVerifier{principal: sessionPrincipal()}
			sessions := &stubSessionLookup{info: statusInfo(tc.mutate)}
			if code := doProbe(resolverEngine(v, sessions)); code != http.StatusUnauthorized {
				t.Fatalf("%s: status = %d, want 401 through the default resolver", tc.name, code)
			}
		})
	}
	// Control: the same info with nothing mutated is admitted — proving the
	// rejections above are the status checks, not the resolver rejecting all.
	v := &stubVerifier{principal: sessionPrincipal()}
	sessions := &stubSessionLookup{info: statusInfo(func(*domain.SessionValidationInfo) {})}
	if code := doProbe(resolverEngine(v, sessions)); code != http.StatusOK {
		t.Fatalf("all-live control: status = %d, want 200", code)
	}
}

// ── (b) revert-proof: the injected resolver's verdict OVERRIDES the real path ──

// A stub returning (true, nil) ADMITS a request the real session path would
// reject (the store holds a REVOKED session). If the seam is reverted —
// BearerPrincipal consulting `sessions` directly — this gets 401 and fails.
func TestSubjectResolver_StubTrueOverridesRevokedSession(t *testing.T) {
	v := &stubVerifier{principal: sessionPrincipal()}
	sessions := &stubSessionLookup{session: revokedSession()}
	stub := &stubSubjectResolver{ok: true}
	code := doProbe(resolverEngine(v, sessions, WithSubjectResolver(stub)))
	if code != http.StatusOK {
		t.Fatalf("stub (true,nil) over revoked session: status = %d, want 200 (seam verdict must win)", code)
	}
	if stub.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", stub.calls)
	}
	if sessions.calls != 0 {
		t.Fatalf("session store consulted %d time(s) despite injected resolver — seam bypassed", sessions.calls)
	}
	if stub.lastRef.SessionID == "" || stub.lastRef.Subject == "" {
		t.Fatalf("resolver must receive the principal's subject+session ref, got %+v", stub.lastRef)
	}
}

// A stub returning (false, nil) REJECTS a request the real session path would
// admit (the store holds a LIVE session). Reverting the seam gets 200 here.
func TestSubjectResolver_StubFalseOverridesLiveSession(t *testing.T) {
	v := &stubVerifier{principal: sessionPrincipal()}
	sessions := &stubSessionLookup{session: usableSession()}
	stub := &stubSubjectResolver{ok: false}
	code := doProbe(resolverEngine(v, sessions, WithSubjectResolver(stub)))
	if code != http.StatusUnauthorized {
		t.Fatalf("stub (false,nil) over live session: status = %d, want 401 (seam verdict must win)", code)
	}
}

// ── (c) fail-closed: an error rejects even alongside ok == true ─────────────

func TestSubjectResolver_ErrorFailsClosedDespiteTrue(t *testing.T) {
	v := &stubVerifier{principal: sessionPrincipal()}
	stub := &stubSubjectResolver{ok: true, err: errors.New("resolver backend down")}
	code := doProbe(resolverEngine(v, &stubSessionLookup{session: usableSession()}, WithSubjectResolver(stub)))
	if code != http.StatusUnauthorized {
		t.Fatalf("stub (true, err): status = %d, want 401 (fail-closed)", code)
	}
}

// ── (d) M2M exemption: the resolver is never consulted without a session ────

func TestSubjectResolver_M2MPrincipalNeverResolved(t *testing.T) {
	v := &stubVerifier{principal: &domain.Principal{ClientID: "svc-1", Scope: "m2m:read"}} // nil SessionID
	stub := &stubSubjectResolver{ok: false}                                                // would reject if (wrongly) consulted
	code := doProbe(resolverEngine(v, &stubSessionLookup{}, WithSubjectResolver(stub)))
	if code != http.StatusOK {
		t.Fatalf("M2M principal: status = %d, want 200 (exempt)", code)
	}
	if stub.calls != 0 {
		t.Fatalf("resolver consulted %d time(s) for a nil-SessionID principal, want 0", stub.calls)
	}
}

// ── (e) sessions == nil: no default resolver, gate skipped as today ─────────

func TestSubjectResolver_NilSessionsMeansNoResolver(t *testing.T) {
	v := &stubVerifier{principal: sessionPrincipal()}
	code := doProbe(resolverEngine(v, nil))
	if code != http.StatusOK {
		t.Fatalf("nil sessions, no resolver: status = %d, want 200 (gate skipped)", code)
	}
}

// ── sessionSubjectResolver unit posture ─────────────────────────────────────

// The OSS resolver itself is fail-closed on an unparsable session id — the
// seam is public-shaped, so it defends itself even though BearerPrincipal
// always passes a canonical uuid string.
func TestSessionSubjectResolver_UnparsableSessionIDFailsClosed(t *testing.T) {
	r := sessionSubjectResolver{sessions: &stubSessionLookup{session: usableSession()}}
	ok, err := r.ResolveSubject(context.Background(), oidc.PrincipalRef{Subject: "u", SessionID: "not-a-uuid"})
	if ok || err == nil {
		t.Fatalf("unparsable session id: got (%v, %v), want (false, non-nil error)", ok, err)
	}
}

func TestSessionSubjectResolver_VerdictMatchesCanBeUsedForAuth(t *testing.T) {
	now := time.Now().UTC()
	live := &stubSessionLookup{session: &domain.Session{ID: uuid.New(), IsValid: true, ExpiresAt: now.Add(time.Hour)}}
	r := sessionSubjectResolver{sessions: live}
	ok, err := r.ResolveSubject(context.Background(), oidc.PrincipalRef{Subject: "u", SessionID: uuid.NewString()})
	if !ok || err != nil {
		t.Fatalf("live session: got (%v, %v), want (true, nil)", ok, err)
	}
	r = sessionSubjectResolver{sessions: &stubSessionLookup{session: revokedSession()}}
	ok, err = r.ResolveSubject(context.Background(), oidc.PrincipalRef{Subject: "u", SessionID: uuid.NewString()})
	if ok || err != nil {
		t.Fatalf("revoked session: got (%v, %v), want (false, nil)", ok, err)
	}
	r = sessionSubjectResolver{sessions: &stubSessionLookup{err: errors.New("store down")}}
	ok, err = r.ResolveSubject(context.Background(), oidc.PrincipalRef{Subject: "u", SessionID: uuid.NewString()})
	if ok || err == nil {
		t.Fatalf("store error: got (%v, %v), want (false, non-nil error)", ok, err)
	}
	r = sessionSubjectResolver{sessions: &stubSessionLookup{}} // not found
	ok, err = r.ResolveSubject(context.Background(), oidc.PrincipalRef{Subject: "u", SessionID: uuid.NewString()})
	if ok || err != nil {
		t.Fatalf("session not found: got (%v, %v), want (false, nil)", ok, err)
	}
}
