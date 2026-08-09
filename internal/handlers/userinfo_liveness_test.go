package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// CONF-10 teeth: userinfo must apply the SAME liveness verdict on BOTH doors.
//
// The hole: BearerPrincipal is mounted globally and gates the Authorization
// header path fully — signature, jti revocation, and session/user/org liveness
// via the pkg/oidc.SubjectResolver seam. But with NO Authorization header it
// calls c.Next() immediately (by design), and readUserinfoBearerToken then
// picks the token out of the `access_token` FORM FIELD (RFC 6750 §2.2, which
// permits exactly that). That path reaches IntrospectActiveClaims alone —
// signature + jti, and NO liveness. So a BANNED user was refused as a header
// and admitted as a form field.
//
// The fix reuses the EXISTING verdict rather than inventing a second one: the
// handler consults the same SubjectResolver the middleware does.

// userinfoStubResolver is the in-test pkg/oidc.SubjectResolver.
type userinfoStubResolver struct {
	ok      bool
	err     error
	calls   int
	lastRef oidc.PrincipalRef
}

func (s *userinfoStubResolver) ResolveSubject(_ context.Context, ref oidc.PrincipalRef) (bool, error) {
	s.calls++
	s.lastRef = ref
	return s.ok, s.err
}

func newUserinfoLivenessEngine(t *testing.T, claims *service.IntrospectionClaims, resolver oidc.SubjectResolver) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterUserinfoRoutes(r, UserinfoHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &userinfoFakeVerifier{claims: claims}, nil),
		Audit:                &audit.Recorder{},
		SubjectResolver:      resolver,
	})
	return r
}

// postUserinfoFormToken presents the token in the access_token FORM FIELD with
// NO Authorization header — the door that bypassed the middleware.
func postUserinfoFormToken(t *testing.T, r *gin.Engine, token string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oidc/userinfo",
		strings.NewReader("access_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

// getUserinfoHeaderToken presents the same token in the Authorization header.
func getUserinfoHeaderToken(t *testing.T, r *gin.Engine, token string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

func livenessClaims(sessionID uuid.UUID) *service.IntrospectionClaims {
	return &service.IntrospectionClaims{
		Sub:       uuid.NewString(),
		UserID:    uuid.New(),
		SessionID: sessionID,
		Exp:       1 << 40,
	}
}

// TestUserinfo_FormFieldTokenIsLivenessGated is the CONF-10 pin: a banned user
// (resolver says not-live) is refused on the FORM-FIELD door, exactly as on the
// header door. Before the fix this returned 200 — the hole.
func TestUserinfo_FormFieldTokenIsLivenessGated(t *testing.T) {
	resolver := &userinfoStubResolver{ok: false} // banned / deleted / inactive org
	r := newUserinfoLivenessEngine(t, livenessClaims(uuid.New()), resolver)

	if code := postUserinfoFormToken(t, r, "tok"); code != http.StatusUnauthorized {
		t.Errorf("banned user via access_token FORM field: status = %d, want 401 — the form-field door must carry the same liveness gate as the header", code)
	}
	if resolver.calls == 0 {
		t.Errorf("the subject resolver was never consulted on the form-field path — the liveness verdict is not being applied at all")
	}
}

// TestUserinfo_HeaderTokenIsLivenessGated pins the other door. The handler now
// resolves UNCONDITIONALLY, not only on the form path, so a not-live principal
// is refused here too even though the middleware is absent from this test's
// engine. Belt and braces on purpose: the handler must not depend on being
// mounted behind the middleware to be safe.
func TestUserinfo_HeaderTokenIsLivenessGated(t *testing.T) {
	resolver := &userinfoStubResolver{ok: false}
	r := newUserinfoLivenessEngine(t, livenessClaims(uuid.New()), resolver)

	if code := getUserinfoHeaderToken(t, r, "tok"); code != http.StatusUnauthorized {
		t.Errorf("banned user via Authorization header: status = %d, want 401", code)
	}
}

// TestUserinfo_LivePrincipalStillAdmitted is the over-correction guard: a live
// verdict must still return 200 on both doors, or the gate is just an outage.
func TestUserinfo_LivePrincipalStillAdmitted(t *testing.T) {
	sid := uuid.New()
	for _, tc := range []struct {
		name string
		call func(*testing.T, *gin.Engine, string) int
	}{
		{"form_field", postUserinfoFormToken},
		{"header", getUserinfoHeaderToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &userinfoStubResolver{ok: true}
			r := newUserinfoLivenessEngine(t, livenessClaims(sid), resolver)
			if code := tc.call(t, r, "tok"); code != http.StatusOK {
				t.Errorf("live principal via %s: status = %d, want 200", tc.name, code)
			}
		})
	}
}

// TestUserinfo_M2MTokenExemptFromLiveness pins the POLICY boundary: a token
// with NO session (uuid.Nil SessionID — client-credentials / service-account)
// has no session to check, so the gate must not fire and must not reject it.
// This mirrors the M2M discriminator the bearer middleware already applies.
func TestUserinfo_M2MTokenExemptFromLiveness(t *testing.T) {
	// A resolver that would REJECT if consulted, proving it is not consulted.
	resolver := &userinfoStubResolver{ok: false}
	r := newUserinfoLivenessEngine(t, livenessClaims(uuid.Nil), resolver)

	if code := postUserinfoFormToken(t, r, "tok"); code != http.StatusOK {
		t.Errorf("M2M token (nil SessionID) via form field: status = %d, want 200 — a token with no session has no liveness to check", code)
	}
	if resolver.calls != 0 {
		t.Errorf("resolver consulted for an M2M token: calls = %d, want 0", resolver.calls)
	}
}

// TestUserinfo_NilResolverUnchanged pins nil-safety: with no resolver wired the
// handler behaves exactly as before, so an operator/test that never supplies
// one sees no change.
func TestUserinfo_NilResolverUnchanged(t *testing.T) {
	r := newUserinfoLivenessEngine(t, livenessClaims(uuid.New()), nil)
	if code := postUserinfoFormToken(t, r, "tok"); code != http.StatusOK {
		t.Errorf("nil resolver: status = %d, want 200 (unchanged behaviour)", code)
	}
}

// TestUserinfo_ResolverErrorFailsClosed pins the fail-closed contract from the
// seam doc: a non-nil error is treated exactly like not-live.
func TestUserinfo_ResolverErrorFailsClosed(t *testing.T) {
	resolver := &userinfoStubResolver{ok: true, err: context.DeadlineExceeded}
	r := newUserinfoLivenessEngine(t, livenessClaims(uuid.New()), resolver)
	if code := postUserinfoFormToken(t, r, "tok"); code != http.StatusUnauthorized {
		t.Errorf("resolver error: status = %d, want 401 (fail-closed even with ok=true)", code)
	}
}
