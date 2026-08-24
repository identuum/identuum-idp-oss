package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// revokeClientAuth authenticates every request as one fixed OAuth client.
type revokeClientAuth struct{ clientID string }

func (a revokeClientAuth) Authenticate(_ context.Context, _, _, _ string) (*service.AuthenticatedClient, error) {
	return &service.AuthenticatedClient{ClientID: a.clientID}, nil
}

// revokeRefreshRepoStub satisfies repository.RefreshTokenRepository; the raw
// token handed to /revoke below is not selector.validator-shaped, so
// RevokeByRawToken fast-fails and never reaches GetByID — the flow falls
// through to the introspection fan-out path under test.
type revokeRefreshRepoStub struct {
	repository.RefreshTokenRepository
}

func (revokeRefreshRepoStub) GetByID(context.Context, uuid.UUID) (*domain.RefreshToken, error) {
	return nil, nil
}

// revokeClaimsVerifier makes Introspect return one fixed active token whose
// subject + client_id we control.
type revokeClaimsVerifier struct{ claims *service.IntrospectionClaims }

func (v revokeClaimsVerifier) IntrospectToken(context.Context, string) (*service.IntrospectionClaims, error) {
	return v.claims, nil
}

// POST /api/v1/oauth/revoke fans out subject-session revocation ONLY when the
// authenticated OAuth client owns the token (RFC 7009 §2.1 client-binding): a
// cross-client caller gets the same opaque 200 but the victim's sessions are
// never revoked. Driven through the ROUTED handler
// (RegisterRevocationRoutes -> HandleRevoke -> tryRevokeRefreshToken /
// authenticatedOAuthClientID / sessionFanoutAllowed).
// RULE: REVOKE-CLIENT-BINDING-1
func TestRevoke_SessionFanoutOnlyForOwningClient(t *testing.T) {
	sub := uuid.New()

	engine := func(tokenClientID string) (*gin.Engine, *cascadeSpySessionRevoker) {
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		spy := &cascadeSpySessionRevoker{}
		RegisterRevocationRoutes(r, RevocationHandlerDeps{
			IntrospectionService: service.NewIntrospectionService(nil,
				revokeClaimsVerifier{claims: &service.IntrospectionClaims{Sub: sub.String(), ClientID: tokenClientID}}, nil),
			RefreshTokenService: service.NewRefreshTokenService(nil, revokeRefreshRepoStub{}, service.RefreshTokenServiceOptions{}),
			SessionRevoker:      spy,
			ClientAuth:          revokeClientAuth{clientID: "client-A"},
		})
		return r, spy
	}
	post := func(r *gin.Engine) int {
		form := url.Values{"client_id": {"client-A"}, "client_secret": {"x"}, "token": {"opaque-access-token"}}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	// Owning client (token.client_id == authenticated client): 200 + session fan-out.
	rOwned, spyOwned := engine("client-A")
	if code := post(rOwned); code != http.StatusOK {
		t.Fatalf("PREMISE FAILED: revoke by the owning client must be 200, got %d", code)
	}
	if got := spyOwned.calls(); len(got) != 1 || got[0] != sub {
		t.Fatalf("the owning client's revoke must fan out session revocation for the subject %s, got %v", sub, got)
	}

	// Cross-client caller (token.client_id != authenticated client): same opaque
	// 200, but the victim subject's sessions are NEVER revoked.
	rCross, spyCross := engine("client-B")
	if code := post(rCross); code != http.StatusOK {
		t.Errorf("a cross-client revoke must still be an opaque 200, got %d", code)
	}
	if got := spyCross.calls(); len(got) != 0 {
		t.Errorf("a cross-client revoke must NEVER fan out session revocation, but it revoked %v", got)
	}
}
