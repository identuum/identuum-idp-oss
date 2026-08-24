package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// userinfoStubVerifier satisfies service.TokenClaimsVerifier. On the
// empty-bearer path it is never consulted; when a token IS presented it
// returns an error so IntrospectActiveClaims reports the token unverified.
type userinfoStubVerifier struct{}

func (userinfoStubVerifier) IntrospectToken(context.Context, string) (*service.IntrospectionClaims, error) {
	return nil, errors.New("unverified")
}

// GET/POST /api/v1/oidc/userinfo rejects a request that carries no valid bearer
// with 401 and an RFC 6750 challenge header (WWW-Authenticate: Bearer
// error="invalid_token"), never leaking user claims. Driven through the ROUTED
// handler (RegisterUserinfoRoutes -> HandleUserinfo -> respondUserinfoUnauthorized).
// RULE: USERINFO-BEARER-CHALLENGE-1
func TestUserinfo_RejectsMissingBearerWithChallenge(t *testing.T) {
	engine := func() *gin.Engine {
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		RegisterUserinfoRoutes(r, UserinfoHandlerDeps{
			IntrospectionService: service.NewIntrospectionService(nil, userinfoStubVerifier{}, nil),
		})
		return r
	}
	do := func(bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		engine().ServeHTTP(w, req)
		return w
	}

	// No bearer at all -> 401 with the challenge header.
	w := do("")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer must be 401, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Errorf("missing bearer must carry the RFC 6750 challenge, got WWW-Authenticate=%q", got)
	}

	// A presented-but-unverifiable token -> the same opaque 401 + challenge.
	w2 := do("not-a-real-token")
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("an unverifiable bearer must be 401, got %d", w2.Code)
	}
	if got := w2.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Errorf("an unverifiable bearer must carry the challenge, got WWW-Authenticate=%q", got)
	}
}
