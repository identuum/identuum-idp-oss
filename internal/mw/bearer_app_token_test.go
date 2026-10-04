package mw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func probeWith(t *testing.T, p *domain.Principal) int {
	t.Helper()
	r := bearerEngine(t, &stubVerifier{principal: p})
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer some-token-value")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

// A user access token issued to an application (actor_type "user" with a
// client_id, minted by the authorization-code grant) is for that application's
// resource servers and for userinfo. It is not a credential for the IdP's own
// API, whatever role its user holds. Console session tokens (no client_id) and
// service-account tokens (actor_type "service_account") are unaffected.
func TestBearerPrincipal_AppIssuedUserTokenIsNotAnAPICredential(t *testing.T) {
	user := uuid.New()

	app := &domain.Principal{Role: domain.RoleSiteAdmin, ActorType: "user", ClientID: "app-1", UserID: user}
	if got := probeWith(t, app); got != http.StatusUnauthorized {
		t.Errorf("a user token issued to an app: status = %d, want 401", got)
	}

	console := &domain.Principal{Role: domain.RoleSiteAdmin, ActorType: "user", UserID: user}
	if got := probeWith(t, console); got != http.StatusOK {
		t.Errorf("a console session token: status = %d, want 200", got)
	}

	machine := &domain.Principal{Role: domain.RoleSiteAdmin, ActorType: "service_account", ClientID: "sa-client", UserID: user}
	if got := probeWith(t, machine); got != http.StatusOK {
		t.Errorf("a service-account token: status = %d, want 200", got)
	}
}

// appTokenProbe answers 200 and says whether BearerPrincipal planted a
// principal, so a test sees both the middleware's own refusals (401) and a
// token it let through without one.
func appTokenProbe(verifier TokenVerifier, sessions SessionRevocationLookup, revocations BearerRevocationLookup) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BearerPrincipal(nil, verifier, sessions, revocations))
	r.GET("/probe", func(c *gin.Context) {
		if _, ok := PrincipalFromContext(c); ok {
			c.Header("X-Principal", "planted")
		}
		c.Status(http.StatusOK)
	})
	return r
}

func probePrincipal(r *gin.Engine) (int, bool) {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code, rec.Header().Get("X-Principal") == "planted"
}

// The access token the refresh_token grant mints names the app (client_id)
// and the user (sub) but carries no actor_type. It is the same app credential
// as the first token and plants no principal. A client-credentials token,
// whose subject is the client itself, is a machine credential and is planted.
func TestBearerPrincipal_RefreshedAppTokenIsNotAnAPICredential(t *testing.T) {
	user := uuid.New()
	refreshed := &domain.Principal{ClientID: "app-1", Sub: user.String(), UserID: user, Scope: "openid offline_access", TokenID: "JTI-REFRESHED"}
	code, planted := probePrincipal(appTokenProbe(&stubVerifier{principal: refreshed}, nil, nil))
	if code != http.StatusOK || planted {
		t.Errorf("refreshed app token: status %d, planted %v; want 200 with no principal", code, planted)
	}

	machine := &domain.Principal{ClientID: "cc-1", Sub: "cc-1", Scope: "m2m:read", TokenID: "JTI-CC"}
	code, planted = probePrincipal(appTokenProbe(&stubVerifier{principal: machine}, nil, nil))
	if code != http.StatusOK || !planted {
		t.Errorf("client-credentials token: status %d, planted %v; want 200 with a principal", code, planted)
	}
}

// An app token plants no principal, but it is still held to revocation and to
// its session's liveness here: a route that reads the Authorization header on
// its own (GET /api/v1/validate) must not accept a revoked token or one whose
// session, user or organization is gone.
func TestBearerPrincipal_AppTokenStillHeldToRevocationAndLiveness(t *testing.T) {
	user := uuid.New()
	revoked := &domain.Principal{ActorType: "user", ClientID: "app-1", Sub: user.String(), UserID: user, TokenID: "JTI-APP-REVOKED"}
	revs := &stubRevocation{revoked: map[string]bool{"JTI-APP-REVOKED": true}}
	if code, _ := probePrincipal(appTokenProbe(&stubVerifier{principal: revoked}, nil, revs)); code != http.StatusUnauthorized {
		t.Errorf("revoked app token: status = %d, want 401", code)
	}

	dead := revokedSession()
	ended := &domain.Principal{ActorType: "user", ClientID: "app-1", Sub: user.String(), UserID: user, SessionID: dead.ID, TokenID: "JTI-APP-ENDED"}
	sessions := &stubSessionLookup{session: dead}
	if code, _ := probePrincipal(appTokenProbe(&stubVerifier{principal: ended}, sessions, &stubRevocation{})); code != http.StatusUnauthorized {
		t.Errorf("app token of an ended session: status = %d, want 401", code)
	}

	live := usableSession()
	ok := &domain.Principal{ActorType: "user", ClientID: "app-1", Sub: user.String(), UserID: user, SessionID: live.ID, TokenID: "JTI-APP-LIVE"}
	code, planted := probePrincipal(appTokenProbe(&stubVerifier{principal: ok}, &stubSessionLookup{session: live}, &stubRevocation{}))
	if code != http.StatusOK || planted {
		t.Errorf("live app token: status %d, planted %v; want 200 with no principal", code, planted)
	}
}
