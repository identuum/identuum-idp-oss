package api

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// oauthClientRateLimitKey buckets per authenticated client, with an
// IP fallback (empty string) so a request is never un-bucketed.
func TestOAuthClientRateLimitKey(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)

	// With an authenticated client in context → keyed by client id.
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	mw.SetAuthenticatedClientForTest(c, &service.AuthenticatedClient{ClientID: "client-xyz"})
	if got := oauthClientRateLimitKey(c); got != "client-xyz" {
		t.Errorf("with client: key = %q, want \"client-xyz\"", got)
	}

	// With no client in context → empty string (limiter falls back to IP).
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := oauthClientRateLimitKey(c2); got != "" {
		t.Errorf("no client: key = %q, want \"\" (IP fallback)", got)
	}
}
