package mw

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
