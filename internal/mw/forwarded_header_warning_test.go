package mw

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// A reverse proxy that is not listed in IDENTUUM_IDP_TRUSTED_PROXIES has its
// X-Forwarded-For ignored (the right default against a forged header), and every
// user then shares the proxy's address and its per-address limits and lockout.
// The operator is told once per such peer, so the cause is not a mystery.
func TestForwardedHeaderWarning_OncePerUntrustedPeerThatSendsOne(t *testing.T) {
	var warned []string
	t.Cleanup(SetForwardedHeaderWarnForTest(func(_ context.Context, peer string) { warned = append(warned, peer) }))

	gin.SetMode(gin.ReleaseMode)
	serve := func(trusted []string, remote string, forwarded bool) {
		r := gin.New()
		if err := r.SetTrustedProxies(trusted); err != nil {
			t.Fatalf("SetTrustedProxies: %v", err)
		}
		r.Use(ForwardedHeaderWarning())
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

// The remembered set is bounded by forgetting the oldest peer, not by going
// silent: a peer that arrives after 64 others is still warned about. A global
// limit of 10 warnings a minute keeps a flood of peers out of the log.
func TestForwardedHeaderWarning_NewPeersAreWarnedPastTheBoundWithinARate(t *testing.T) {
	var warned []string
	t.Cleanup(SetForwardedHeaderWarnForTest(func(_ context.Context, peer string) { warned = append(warned, peer) }))
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	t.Cleanup(setForwardedWarnClockForTest(func() time.Time { return now }))

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies: %v", err)
	}
	r.Use(ForwardedHeaderWarning())
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	from := func(peer string) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = peer + ":4000"
		req.Header.Set("X-Forwarded-For", "203.0.113.50")
		r.ServeHTTP(httptest.NewRecorder(), req)
	}

	for i := 0; i < 70; i++ { // one new peer every 7 s: under 10 a minute
		from(fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))
		now = now.Add(7 * time.Second)
	}
	if len(warned) != 70 {
		t.Fatalf("warned about %d of 70 peers arriving under the rate; want all 70 (past the bound of 64 too)", len(warned))
	}

	warned = nil
	now = now.Add(time.Minute)
	for i := 0; i < 25; i++ { // 25 new peers within one instant of a fresh minute
		from(fmt.Sprintf("10.9.0.%d", i+1))
	}
	if len(warned) != 10 {
		t.Errorf("warned about %d of 25 peers in one minute; want 10", len(warned))
	}
}
