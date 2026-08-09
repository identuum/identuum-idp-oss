package mw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// Paradox-route revocation coverage.
//
// Verifies the HIGHEST-severity "session/MFA self-sabotage paradox" routes
// from docs/audit/auth-surface/session-binding-blast-radius.md — where a
// revoked token must not be able to act — now reject a revoked user-session
// token after the Stage-1 bearer-path revocation fix.
//
// Each route is reproduced as its REAL guard chain between the shared
// BearerPrincipal (which carries the Stage-1 session check) and its handler:
//   - me/sessions/* and me/mfa/* are gated by mw.RequireAuthenticated
//     (internal/handlers/auth_sessions.go:175,196,228).
//   - POST /api/v1/revoke and the WebAuthn management routes have NO group
//     guard; their handlers derive identity from mw.PrincipalFromContext
//     (internal/handlers/sessions.go:165,245;
//      internal/handlers/webauthn.go:163 authenticatedUserID -> PrincipalFromContext).
//     Confirmed: none of these handlers read the access_token cookie, so the
//     shared BearerPrincipal is the sole identity source.
// principalProbe is set as the route handler; it admits (200) iff a principal
// is present in context. BearerPrincipal rejects a revoked-session token (401)
// BEFORE the probe/guard runs.

func okProbe(c *gin.Context) { c.Status(http.StatusOK) }

func principalProbe(c *gin.Context) {
	if _, ok := PrincipalFromContext(c); !ok {
		respondUnauthenticated(c)
		return
	}
	c.Status(http.StatusOK)
}

type paradoxRoute struct {
	name   string
	guards []gin.HandlerFunc // real downstream guard(s); nil = in-handler principal
	probe  gin.HandlerFunc
}

func paradoxRoutes() []paradoxRoute {
	return []paradoxRoute{
		{name: "POST /api/v1/me/sessions/revoke-current", guards: []gin.HandlerFunc{RequireAuthenticated()}, probe: okProbe},
		{name: "POST /api/v1/me/sessions/revoke-others", guards: []gin.HandlerFunc{RequireAuthenticated()}, probe: okProbe},
		{name: "POST /api/v1/me/sessions/revoke-all", guards: []gin.HandlerFunc{RequireAuthenticated()}, probe: okProbe},
		{name: "POST /api/v1/revoke", guards: nil, probe: principalProbe},
		{name: "POST /api/v1/me/mfa/disable", guards: []gin.HandlerFunc{RequireAuthenticated()}, probe: okProbe},
		{name: "POST /api/v1/me/mfa/recovery-codes/regenerate", guards: []gin.HandlerFunc{RequireAuthenticated()}, probe: okProbe},
		{name: "POST /api/v1/webauthn/register/finish", guards: nil, probe: principalProbe},
		{name: "DELETE /api/v1/webauthn/credentials/:id", guards: nil, probe: principalProbe},
	}
}

func paradoxEngine(rt paradoxRoute, lookup SessionRevocationLookup) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// A user-session token: non-nil SessionID (set only by IssueForSession),
	// site_admin so RequireAuthenticated admits when the session is live.
	v := &stubVerifier{principal: &domain.Principal{
		UserID: uuid.New(), Role: domain.RoleSiteAdmin, SessionID: uuid.New(),
	}}
	r.Use(BearerPrincipal(nil, v, lookup, nil))
	for _, g := range rt.guards {
		r.Use(g)
	}
	r.Any("/probe", rt.probe)
	return r
}

func hitParadox(r *gin.Engine) int {
	req := httptest.NewRequest(http.MethodPost, "/probe", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

// TestParadoxRoutes_BeforeAfterRevocation proves, per route, the before/after:
// a valid user-session token is ADMITTED with a live session (control) and the
// SAME token is REJECTED (401) once its session is revoked server-side. Uses
// t.Errorf (never Fatal) so EVERY paradox route is evaluated + reported in one
// run.
func TestParadoxRoutes_BeforeAfterRevocation(t *testing.T) {
	for _, rt := range paradoxRoutes() {
		before := hitParadox(paradoxEngine(rt, &stubSessionLookup{session: usableSession()}))
		after := hitParadox(paradoxEngine(rt, &stubSessionLookup{session: revokedSession()}))

		classification := "REJECTS-REVOKED"
		if before == http.StatusUnauthorized || after != http.StatusUnauthorized {
			classification = "COVERAGE-GAP"
		}
		t.Logf("%-48s before(live)=%d  after(revoked)=%d  => %s", rt.name, before, after, classification)

		if before == http.StatusUnauthorized {
			t.Errorf("%s: control (live session) rejected with %d — the bearer gate must admit a live session", rt.name, before)
		}
		if after != http.StatusUnauthorized {
			t.Errorf("%s: COVERAGE-GAP — revoked-session token accepted (status %d, want 401)", rt.name, after)
		}
	}
}
