package mw

// OSS-ONBOARD-B item 4, the top-level mw half: the access log
// (RequestIDMiddleware's "Request started" / "Request completed"), the
// database-readiness warning, DenyM2MClients, the panic recovery line and the
// request-timeout line all record the request path. On the two routes whose
// path carries a one-time token none of them may write the token; the path
// they record is the route template.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/identuum/identuum-idp-oss/types"
)

const pathToken = "c0ffee5ecre7path7oken0000000000000000000000000000000000000000beef"

var tokenPathRoutes = []struct{ template, raw string }{
	{"/api/v1/auth/invite/:token", "/api/v1/auth/invite/" + pathToken},
	{"/api/v1/auth/organizations/activate/:token", "/api/v1/auth/organizations/activate/" + pathToken},
}

// observeAllLogs swaps every package logger for one observer and restores
// them when the test ends.
func observeAllLogs(t *testing.T) *observer.ObservedLogs {
	t.Helper()
	core, observed := observer.New(zapcore.DebugLevel)
	l := logger.NewLogger(zap.New(core), zapcore.DebugLevel)
	info, warn, errl, sec := logger.Info, logger.Warning, logger.Error, logger.Security
	logger.Info, logger.Warning, logger.Error, logger.Security = l, l, l, l
	t.Cleanup(func() { logger.Info, logger.Warning, logger.Error, logger.Security = info, warn, errl, sec })
	return observed
}

func assertPathRedacted(t *testing.T, observed *observer.ObservedLogs, wantMsg, wantPath string) {
	t.Helper()
	found := 0
	for _, e := range observed.All() {
		line := e.Message
		for k, v := range e.ContextMap() {
			line += fmt.Sprintf(" %s=%v", k, v)
		}
		if strings.Contains(line, pathToken) {
			t.Fatalf("path token in a log line: %q", line)
		}
		if e.Message == wantMsg {
			found++
			if got := fmt.Sprint(e.ContextMap()["path"]); got != wantPath {
				t.Fatalf("%q path = %q, want %q", wantMsg, got, wantPath)
			}
		}
	}
	if found == 0 {
		t.Fatalf("no %q line was logged (control: the site must fire)", wantMsg)
	}
}

func serveTokenPath(r *gin.Engine, raw string) int {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, raw, nil))
	return w.Code
}

func TestPathTokenRedaction_AccessLog(t *testing.T) {
	for _, rt := range tokenPathRoutes {
		observed := observeAllLogs(t)
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.Use(RequestIDMiddleware())
		r.GET(rt.template, func(c *gin.Context) { c.Status(http.StatusOK) })
		serveTokenPath(r, rt.raw)
		assertPathRedacted(t, observed, "Request started", rt.template)
		assertPathRedacted(t, observed, "Request completed", rt.template)
	}
}

func TestPathTokenRedaction_DatabaseNotReady(t *testing.T) {
	for _, rt := range tokenPathRoutes {
		observed := observeAllLogs(t)
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.Use(DatabaseReadinessMiddleware(nil))
		r.GET(rt.template, func(c *gin.Context) { c.Status(http.StatusOK) })
		if code := serveTokenPath(r, rt.raw); code != http.StatusServiceUnavailable {
			t.Fatalf("%s: = %d, want 503", rt.template, code)
		}
		assertPathRedacted(t, observed, "Request rejected - database not ready", rt.template)
	}
}

func TestPathTokenRedaction_DenyM2MClients(t *testing.T) {
	for _, rt := range tokenPathRoutes {
		observed := observeAllLogs(t)
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.GET(rt.template, func(c *gin.Context) {
			c.Set(domain.CtxKeyPrincipal, types.Principal{Kind: types.PrincipalKindClient})
		}, DenyM2MClients(), func(c *gin.Context) { c.Status(http.StatusOK) })
		if code := serveTokenPath(r, rt.raw); code != http.StatusForbidden {
			t.Fatalf("%s: = %d, want 403", rt.template, code)
		}
		assertPathRedacted(t, observed,
			"DenyM2MClients: service account attempted to access a user-only endpoint", rt.template)
	}
}

func TestPathTokenRedaction_Recovery(t *testing.T) {
	for _, rt := range tokenPathRoutes {
		observed := observeAllLogs(t)
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.Use(RecoveryMiddleware())
		r.GET(rt.template, func(c *gin.Context) { panic("probe") })
		if code := serveTokenPath(r, rt.raw); code != http.StatusInternalServerError {
			t.Fatalf("%s: = %d, want 500", rt.template, code)
		}
		assertPathRedacted(t, observed, "Panic recovered in HTTP handler", rt.template)
	}
}

func TestPathTokenRedaction_Timeout(t *testing.T) {
	for _, rt := range tokenPathRoutes {
		observed := observeAllLogs(t)
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.Use(RequestTimeoutMiddleware(time.Millisecond))
		r.GET(rt.template, func(c *gin.Context) { <-c.Request.Context().Done() })
		serveTokenPath(r, rt.raw)
		assertPathRedacted(t, observed, "Request timeout exceeded", rt.template)
	}
}
