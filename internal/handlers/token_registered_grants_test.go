package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// A client registered for some grant types (RFC 7591 grant_types) may use only
// those at the token endpoint: the registration is enforced, not just echoed.
// A client that registered none (an app created in the console, or one
// registered before the field existed) is unrestricted, as it always was.

type grantsStub struct{ grants []string }

func (s grantsStub) Authenticate(_ context.Context, id, _, _ string) (*service.AuthenticatedClient, error) {
	return &service.AuthenticatedClient{
		Kind: service.AuthenticatedClientKindOAuth, ClientID: id, AuthRecordID: uuid.New(), GrantTypes: s.grants,
	}, nil
}

func tokenErrorFor(t *testing.T, grants []string, grantType string) string {
	t.Helper()
	r := newTokenEngine(t, &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}}, nil, grantsStub{grants: grants}, &audit.Recorder{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token",
		strings.NewReader("grant_type="+grantType+"&client_id=cli-1&client_secret=s"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	e, _ := body["error"].(string)
	return e
}

func TestToken_AGrantTheClientDidNotRegisterIsRefused(t *testing.T) {
	registered := []string{"authorization_code"}
	for _, grant := range []string{"refresh_token", "client_credentials"} {
		if got := tokenErrorFor(t, registered, grant); got != "unauthorized_client" {
			t.Errorf("client registered for authorization_code only, grant %s: error = %q; want unauthorized_client", grant, got)
		}
	}
}

func TestToken_AClientWithNoRegisteredGrantsIsUnrestricted(t *testing.T) {
	for _, grants := range [][]string{nil, {}} {
		if got := tokenErrorFor(t, grants, "refresh_token"); got == "unauthorized_client" {
			t.Errorf("client with grants %v was refused a grant it never restricted", grants)
		}
	}
}

// A missing grant_type is invalid_request and an unknown one is
// unsupported_grant_type (RFC 6749 §5.2), whatever the client registered:
// unauthorized_client is for a known grant the client may not use.
func TestToken_AMissingOrUnknownGrantGetsItsRFCError(t *testing.T) {
	registered := []string{"authorization_code"}
	if got := tokenErrorFor(t, registered, ""); got != "invalid_request" {
		t.Errorf("no grant_type: error = %q; want invalid_request", got)
	}
	if got := tokenErrorFor(t, registered, "password"); got != "unsupported_grant_type" {
		t.Errorf("grant_type=password: error = %q; want unsupported_grant_type", got)
	}
}

// offline_access hands out a refresh token only to a client that may redeem
// it: one registered without refresh_token would hold a token it can never
// use.
func TestToken_NoRefreshTokenForAnAppNotRegisteredForIt(t *testing.T) {
	exchange := func(t *testing.T, grants []string) map[string]any {
		t.Helper()
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		keys := &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "kid-eddsa")}}
		codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
		refresh := service.NewRefreshTokenService(nil, newInMemoryRefreshRepo(), service.RefreshTokenServiceOptions{})
		tokenSvc := service.NewTokenService(nil, keys, service.TokenServiceOptions{Issuer: "https://idp.test"})
		tokenSvc.WithRefreshTokenService(refresh)
		user := &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Email: "alice@example.com", EmailVerified: true, Role: domain.RoleOrgUser}
		session := &domain.Session{ID: uuid.New(), UserID: user.ID, CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), IsValid: true, Acr: "0", Amr: []string{"pwd"}}
		RegisterTokenRoutes(r, TokenHandlerDeps{
			TokenService:    tokenSvc,
			ClientAuth:      grantsStub{grants: grants},
			Audit:           &audit.Recorder{},
			AuthCodeService: codes,
			UserToken:       service.NewUserTokenService(nil, keys, service.UserTokenServiceOptions{Issuer: "https://idp.test", AccessTokenTTL: time.Hour}),
			UserLookup:      &fakeUserLookup{user: user},
			SessionLookup:   &fakeSessionLookup{session: session},
			OrgLookup:       &fakeOrgLookup{org: &domain.Organization{ID: user.OrganizationID, Active: true}},
			RefreshTokens:   refresh,
		})
		verifier, challenge := authCodePKCEPair(t)
		created, _ := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
			ClientID: "cli-1", UserID: user.ID, SessionID: session.ID, RedirectURI: "https://app.example.com/cb",
			Scope: "openid offline_access", CodeChallenge: challenge, CodeChallengeMethod: "S256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader("grant_type=authorization_code&code="+created.Code+
			"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&code_verifier="+verifier))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("exchange = %d %q", w.Code, w.Body.String())
		}
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return body
	}
	if got := exchange(t, []string{"authorization_code"}); got["refresh_token"] != nil {
		t.Error("a client registered without refresh_token received a refresh token")
	}
	if got := exchange(t, []string{"authorization_code", "refresh_token"}); got["refresh_token"] == nil {
		t.Error("a client registered for refresh_token received none")
	}
	if got := exchange(t, nil); got["refresh_token"] == nil {
		t.Error("a client with no registered set (unrestricted) received none")
	}
}

func TestToken_ARegisteredGrantIsNotRefusedForBeingUnregistered(t *testing.T) {
	// The registered grant passes this check and meets whatever the grant itself
	// requires (here: an authorization code it did not bring).
	if got := tokenErrorFor(t, []string{"authorization_code"}, "authorization_code"); got == "unauthorized_client" {
		t.Errorf("a registered grant was refused as unauthorized_client")
	}
}
