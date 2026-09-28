package mw

// OSS-ONBOARD-B item 4. Two public routes carry a one-time credential in the
// PATH: GET /api/v1/auth/invite/:token and
// GET /api/v1/auth/organizations/activate/:token. A log line or audit row that
// records the raw request path would hold that credential. Every internal/mw
// site that records a request path is driven here on both routes, and the
// token must appear in none of what was written; the recorded path names the
// route template instead.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap/zaptest/observer"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/features"
	"github.com/identuum/identuum-idp-oss/ratelimit"
)

// pathToken is distinctive so finding it in output is a real leak, never a
// coincidence of short strings.
const pathToken = "c0ffee5ecre7path7oken0000000000000000000000000000000000000000beef"

var tokenPathRoutes = []struct{ template, raw string }{
	{"/api/v1/auth/invite/:token", "/api/v1/auth/invite/" + pathToken},
	{"/api/v1/auth/organizations/activate/:token", "/api/v1/auth/organizations/activate/" + pathToken},
}

func assertNoTokenInLog(t *testing.T, observed *observer.ObservedLogs, wantMsg, wantPath string) {
	t.Helper()
	found := false
	for _, e := range observed.All() {
		line := renderEntry(e)
		if strings.Contains(line, pathToken) {
			t.Fatalf("path token in a log line: %q", line)
		}
		if e.Message == wantMsg {
			found = true
			if got := fmt.Sprint(e.ContextMap()["path"]); got != wantPath {
				t.Fatalf("%q path = %q, want %q", wantMsg, got, wantPath)
			}
		}
	}
	if !found {
		t.Fatalf("no %q line was logged (control: the site must fire)", wantMsg)
	}
}

func assertNoTokenInAudit(t *testing.T, rec *audit.Recorder, wantAction, wantPath string) {
	t.Helper()
	events := rec.Events()
	if len(events) != 1 || events[0].Action != wantAction {
		t.Fatalf("audit events = %+v, want one %q", events, wantAction)
	}
	if s := fmt.Sprintf("%v", events[0]); strings.Contains(s, pathToken) {
		t.Fatalf("path token in an audit row: %s", s)
	}
	if got := events[0].Metadata["path"]; got != wantPath {
		t.Fatalf("audit path = %v, want %q", got, wantPath)
	}
}

func servePathToken(r *gin.Engine, raw string) int {
	req := httptest.NewRequest(http.MethodGet, raw, nil)
	req.RemoteAddr = "203.0.113.7:4000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestPathTokenRedaction_RateLimitLine(t *testing.T) {
	for _, rt := range tokenPathRoutes {
		observed := observeSecurityLog(t)
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.GET(rt.template, NewRateLimitMiddleware(ratelimit.RateLimit{RequestsPerWindow: 1}, "user-invite"),
			func(c *gin.Context) { c.Status(http.StatusOK) })
		servePathToken(r, rt.raw)
		if code := servePathToken(r, rt.raw); code != http.StatusTooManyRequests {
			t.Fatalf("%s: second request = %d, want 429", rt.template, code)
		}
		assertNoTokenInLog(t, observed, "rate limit exceeded", rt.template)
	}
}

func TestPathTokenRedaction_AuthRefusedLine(t *testing.T) {
	for _, rt := range tokenPathRoutes {
		observed := observeSecurityLog(t)
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.GET(rt.template, RequireAuthenticated(), func(c *gin.Context) { c.Status(http.StatusOK) })
		if code := servePathToken(r, rt.raw); code != http.StatusUnauthorized {
			t.Fatalf("%s: = %d, want 401", rt.template, code)
		}
		assertNoTokenInLog(t, observed, "authentication refused", rt.template)
	}
}

func TestPathTokenRedaction_FeatureDeniedAudit(t *testing.T) {
	for _, rt := range tokenPathRoutes {
		rec := &audit.Recorder{}
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.GET(rt.template, RequireFeatureWithAudit(features.ClosedGate{}, rec, "probe"),
			func(c *gin.Context) { c.Status(http.StatusOK) })
		if code := servePathToken(r, rt.raw); code != http.StatusForbidden {
			t.Fatalf("%s: = %d, want 403", rt.template, code)
		}
		assertNoTokenInAudit(t, rec, "feature.denied", rt.template)
	}
}

func TestPathTokenRedaction_ScopeDeniedAudit(t *testing.T) {
	for _, rt := range tokenPathRoutes {
		rec := &audit.Recorder{}
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.GET(rt.template, func(c *gin.Context) {
			c.Set(principalContextKey, &domain.Principal{Role: domain.RoleOrgUser, Scope: "openid"})
		}, RequireScopesAnyWithAudit(rec, "users:read"), func(c *gin.Context) { c.Status(http.StatusOK) })
		if code := servePathToken(r, rt.raw); code != http.StatusForbidden {
			t.Fatalf("%s: = %d, want 403", rt.template, code)
		}
		assertNoTokenInAudit(t, rec, "scope.denied", rt.template)
	}
}
