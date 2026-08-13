package mw

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// stubVerifier lets a test inject a specific verifier result
// without standing up the full JWT verification path.
type stubVerifier struct {
	want      string
	principal *domain.Principal
	err       error
	calls     int
}

func (s *stubVerifier) VerifyBearerToken(_ context.Context, token string) (*domain.Principal, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if s.want != "" && token != s.want {
		return nil, errors.New("stub: token mismatch")
	}
	return s.principal, nil
}

func bearerEngine(t *testing.T, verifier TokenVerifier) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// nil session store: these cases exercise header/scheme/verifier
	// behaviour, not session revocation (the revocation path has its own
	// suite in bearer_revocation_test.go).
	r.Use(BearerPrincipal(nil, verifier, nil, nil))
	r.Use(RequireSiteAdmin())
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

// RULE: P0-BEARER-1
func TestBearerPrincipal_NoHeaderFallsThroughTo401(t *testing.T) {
	v := &stubVerifier{}
	r := bearerEngine(t, v)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (downstream guard)", rec.Code)
	}
	if v.calls != 0 {
		t.Errorf("verifier was called with no header: calls = %d", v.calls)
	}
}

// TestBearerPrincipal_WrongSchemePassesThrough is the CONF-1 (option A)
// contract, and it REPLACES TestBearerPrincipal_WrongSchemeIs401.
//
// The old test asserted that BearerPrincipal itself 401s a non-Bearer scheme.
// That pinned a real defect: this middleware is mounted globally
// (one mount, via mountBearerAuth in internal/api/router.go) ahead of the
// OAuth client-auth routes, so the 401 ate every
// `Authorization: Basic` presentation before mw.RequireOAuthClient could see
// it — and client_secret_basic is ADVERTISED in discovery for those
// endpoints. A test can pin a bug as firmly as it pins a feature; this one
// did, which is why it is rewritten rather than deleted.
//
// What must hold now: BearerPrincipal does not consume the header, does not
// call the verifier, and plants NO principal — the decision belongs to the
// route's own guard.
func TestBearerPrincipal_WrongSchemePassesThrough(t *testing.T) {
	v := &stubVerifier{}
	var reached bool
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BearerPrincipal(nil, v, nil, nil))
	r.GET("/probe", func(c *gin.Context) {
		reached = true
		// No principal may have been planted by the pass-through branch.
		if _, ok := PrincipalFromContext(c); ok {
			t.Errorf("a principal was planted for a non-Bearer scheme")
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Basic dGVzdA==")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if !reached {
		t.Errorf("non-Bearer scheme did not reach the route: status = %d, want pass-through", rec.Code)
	}
	if v.calls != 0 {
		t.Errorf("verifier called for non-Bearer scheme: calls = %d", v.calls)
	}
}

// TestBearerPrincipal_WrongSchemePassesToDownstreamGuard is the security floor
// under CONF-1: pass-through must NOT mean admission. A protected route hit
// with a non-Bearer scheme still 401s — from the downstream guard, because no
// principal was planted. Only the layer that refuses moved.
func TestBearerPrincipal_WrongSchemePassesToDownstreamGuard(t *testing.T) {
	v := &stubVerifier{}
	r := bearerEngine(t, v) // BearerPrincipal + RequireSiteAdmin + /probe
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Basic dGVzdA==")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (downstream guard must still refuse an unauthenticated request)", rec.Code)
	}
	if v.calls != 0 {
		t.Errorf("verifier called for non-Bearer scheme: calls = %d", v.calls)
	}
}

func TestBearerPrincipal_EmptyBearerPayloadIs401(t *testing.T) {
	v := &stubVerifier{}
	r := bearerEngine(t, v)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer    ")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if v.calls != 0 {
		t.Errorf("verifier was called for empty bearer payload")
	}
}

func TestBearerPrincipal_VerifierErrorIs401NoDetailLeak(t *testing.T) {
	v := &stubVerifier{err: errors.New("internal failure detail with sensitive info: TOKEN-SENTINEL-LEAK")}
	r := bearerEngine(t, v)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer some-token-value")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "TOKEN-SENTINEL-LEAK") || strings.Contains(body, "some-token-value") {
		t.Errorf("body leaks verifier detail or token: %q", body)
	}
}

func TestBearerPrincipal_NilPrincipalIs401(t *testing.T) {
	v := &stubVerifier{principal: nil}
	r := bearerEngine(t, v)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (nil principal must not pass)", rec.Code)
	}
}

func TestBearerPrincipal_ValidSiteAdminPasses(t *testing.T) {
	v := &stubVerifier{
		principal: &domain.Principal{
			UserID:         uuid.New(),
			OrganizationID: uuid.New(),
			Email:          "admin@example.test",
			Role:           domain.RoleSiteAdmin,
		},
	}
	r := bearerEngine(t, v)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if v.calls != 1 {
		t.Errorf("verifier calls = %d, want 1", v.calls)
	}
}

func TestBearerPrincipal_ValidOrgUserIs403(t *testing.T) {
	v := &stubVerifier{
		principal: &domain.Principal{
			UserID: uuid.New(),
			Role:   domain.RoleOrgUser,
		},
	}
	r := bearerEngine(t, v)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer org-user-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (org_user via RequireSiteAdmin)", rec.Code)
	}
}

// P-018: a nil TokenVerifier must NOT panic. The factory records a fatal
// startup fault and returns a fail-closed populator that admits no
// principal — so a protected route rejects rather than crashing.
func TestBearerPrincipal_NilVerifierFailsClosed(t *testing.T) {
	report := lifecycle.NewStartupReport()

	var h gin.HandlerFunc
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("BearerPrincipal with nil verifier panicked: %v", rec)
			}
		}()
		h = BearerPrincipal(report, nil, nil, nil)
	}()

	if !report.HasFatal() {
		t.Fatalf("nil verifier must record a fatal fault")
	}
	named := false
	for _, f := range report.Faults() {
		if f.Component == "bearer-auth" && f.Severity == lifecycle.SeverityFatal {
			named = true
		}
	}
	if !named {
		t.Errorf("fault must name the bearer-auth component; got %+v", report.Faults())
	}

	// The returned populator admits NO principal: a protected route rejects.
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(h)
	r.Use(RequireSiteAdmin())
	r.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("fail-closed populator: status = %d, want 401 (admits no principal)", rec.Code)
	}
	t.Logf("EVIDENCE nil-verifier: no panic; faults=%+v; protected route → %d", report.Faults(), rec.Code)
}
