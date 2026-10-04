package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// A reverse proxy that is not listed in IDENTUUM_IDP_TRUSTED_PROXIES has its
// X-Forwarded-For ignored (the right default against a forged header), and every
// user then shares the proxy's address and its per-address limits and lockout.
// The operator is told once per such peer, so the cause is not a mystery.
func TestForwardedHeaderWarning_OncePerUntrustedPeerThatSendsOne(t *testing.T) {
	var warned []string
	prev := warnForwardedHeaderIgnored
	warnForwardedHeaderIgnored = func(_ context.Context, peer string) { warned = append(warned, peer) }
	t.Cleanup(func() { warnForwardedHeaderIgnored = prev })

	gin.SetMode(gin.ReleaseMode)
	serve := func(trusted []string, remote string, forwarded bool) {
		r := gin.New()
		if err := r.SetTrustedProxies(trusted); err != nil {
			t.Fatalf("SetTrustedProxies: %v", err)
		}
		mountForwardedHeaderWarning(r)
		r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = remote
		if forwarded {
			req.Header.Set("X-Forwarded-For", "203.0.113.50")
		}
		// Twice on the same engine: the second request must not warn again.
		for i := 0; i < 2; i++ {
			r.ServeHTTP(httptest.NewRecorder(), req)
		}
	}

	serve(nil, "10.0.0.5:4000", true)
	if len(warned) != 1 || warned[0] != "10.0.0.5" {
		t.Fatalf("untrusted peer sending X-Forwarded-For: warned = %v; want one warning naming 10.0.0.5", warned)
	}

	warned = nil
	serve(nil, "10.0.0.5:4000", false)
	serve([]string{"10.0.0.0/8"}, "10.0.0.5:4000", true)
	if len(warned) != 0 {
		t.Errorf("no header, or a trusted proxy: warned = %v; want none", warned)
	}
}

// The real engine carries the warning: it is mounted ahead of every route.
func TestNewOSSEngine_WarnsAboutAnUntrustedForwardingProxy(t *testing.T) {
	var warned []string
	prev := warnForwardedHeaderIgnored
	warnForwardedHeaderIgnored = func(_ context.Context, peer string) { warned = append(warned, peer) }
	t.Cleanup(func() { warnForwardedHeaderIgnored = prev })

	e := NewOSSEngine(OSSRouterDeps{})
	req := httptest.NewRequest(http.MethodGet, "/system/info", nil)
	req.RemoteAddr = "10.0.0.5:4000"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatalf("CONTROL FAILED: /system/info is not mounted (404)")
	}
	if len(warned) != 1 || warned[0] != "10.0.0.5" {
		t.Errorf("warned = %v; want one warning naming 10.0.0.5", warned)
	}
}
