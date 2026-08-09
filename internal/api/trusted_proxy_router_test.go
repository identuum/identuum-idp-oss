package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// P2-2: c.ClientIP() is the ONE IP resolution shared by rate limiting AND
// audit/security-event attribution. NewOSSEngine now defaults to trusting NO
// proxy, so a forged X-Forwarded-For cannot change the resolved IP; a proxy is
// honoured only when the operator lists its CIDR in TrustedProxies. The probe
// echoes c.ClientIP() so the assertions read the exact value both consumers use.
//
// The probe is registered after NewOSSEngine so it inherits the engine's
// trusted-proxy configuration (SetTrustedProxies is engine-global state).
func addIPProbe(e *gin.Engine) {
	e.GET("/api/v1/__ip_probe", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})
}

func getClientIP(e *gin.Engine, remoteAddr, xff string) string {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/__ip_probe", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	return w.Body.String()
}

// Default (no trusted proxy): a spoofed X-Forwarded-For is IGNORED — the IP used
// for rate limiting / event attribution is the direct peer address.
func TestNewOSSEngine_TrustedProxies_DefaultIgnoresForwardedFor(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{}) // no TrustedProxies ⇒ trust none
	addIPProbe(e)

	got := getClientIP(e, "203.0.113.9:44321", "1.2.3.4")
	if got != "203.0.113.9" {
		t.Errorf("client IP = %q, want the direct peer 203.0.113.9 (spoofed XFF must be ignored)", got)
	}
}

// With the direct peer listed as a trusted proxy, the FORWARDED client IP is
// honoured — the legitimate reverse-proxy deployment.
func TestNewOSSEngine_TrustedProxies_HonouredFromConfiguredProxy(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{TrustedProxies: []string{"203.0.113.0/24"}})
	addIPProbe(e)

	got := getClientIP(e, "203.0.113.9:44321", "1.2.3.4")
	if got != "1.2.3.4" {
		t.Errorf("client IP = %q, want the forwarded 1.2.3.4 (trusted proxy must be honoured)", got)
	}

	// A peer OUTSIDE the trusted CIDR is still not trusted: its XFF is ignored.
	if got := getClientIP(e, "198.51.100.7:5555", "1.2.3.4"); got != "198.51.100.7" {
		t.Errorf("untrusted peer client IP = %q, want the direct peer 198.51.100.7", got)
	}
}
