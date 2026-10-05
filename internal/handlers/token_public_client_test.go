package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// FUNC-H2 (audits/oss-functionality-2026-10-05.md): the console offers a
// "Public client" (token_endpoint_auth_method none) for apps that cannot keep
// a secret, so such a client must be able to redeem its authorization code
// with client_id + code_verifier and no secret. The exchange runs through the
// production client-auth chain (OAuthClientAuthService over a client store),
// not a stub that admits everyone.

type publicClientStore struct {
	mu   sync.Mutex
	rows map[string]*domain.Client
}

func (r *publicClientStore) RegisterClient(_ context.Context, c *domain.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[c.ClientID] = c
	return nil
}
func (r *publicClientStore) GetClientByID(context.Context, uuid.UUID) (*domain.Client, error) {
	return nil, nil
}
func (r *publicClientStore) GetClientByClientID(_ context.Context, clientID string) (*domain.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.rows[clientID]; ok {
		return c, nil
	}
	return nil, domain.ErrClientNotFound
}
func (r *publicClientStore) Update(context.Context, *domain.Client) error        { return nil }
func (r *publicClientStore) Delete(context.Context, uuid.UUID, *uuid.UUID) error { return nil }
func (r *publicClientStore) List(context.Context, repository.Pagination, *uuid.UUID) ([]*domain.Client, int, error) {
	return nil, 0, nil
}
func (r *publicClientStore) ListByServiceAccountID(context.Context, uuid.UUID, uuid.UUID) ([]*domain.Client, error) {
	return nil, nil
}
func (r *publicClientStore) SaveConsent(context.Context, *domain.Consent) error { return nil }
func (r *publicClientStore) GetConsent(context.Context, uuid.UUID, uuid.UUID, *uuid.UUID) (*domain.Consent, error) {
	return nil, nil
}

const (
	publicTestClientID       = "spa-public"
	confidentialTestClientID = "web-confidential"
	publicTestRedirect       = "https://spa.example.com/cb"
)

type publicExchangeFixture struct {
	engine  *gin.Engine
	codes   *service.AuthorizationCodeService
	user    *domain.User
	session *domain.Session
}

func newPublicExchangeFixture(t *testing.T) *publicExchangeFixture {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	store := &publicClientStore{rows: map[string]*domain.Client{
		publicTestClientID: {
			ID: uuid.New(), ClientID: publicTestClientID, Name: "spa", IsPublic: true,
			TokenEndpointAuthMethod: "none", RedirectURIs: []string{publicTestRedirect},
		},
		confidentialTestClientID: {
			ID: uuid.New(), ClientID: confidentialTestClientID, Name: "web",
			ClientSecretHash: crypto.HashSecret("web-secret"), RedirectURIs: []string{publicTestRedirect},
		},
	}}
	clientAuth := service.NewOAuthClientAuthService(nil, service.NewClientService(nil, store), nil)
	keys := &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "kid-eddsa")}}
	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	refresh := service.NewRefreshTokenService(nil, newInMemoryRefreshRepo(), service.RefreshTokenServiceOptions{})
	tokenSvc := service.NewTokenService(nil, keys, service.TokenServiceOptions{Issuer: "https://idp.test"})
	tokenSvc.WithRefreshTokenService(refresh)
	user := &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Email: "alice@example.com", EmailVerified: true, Role: domain.RoleOrgUser}
	session := &domain.Session{ID: uuid.New(), UserID: user.ID, CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), IsValid: true, Acr: "0", Amr: []string{"pwd"}}
	r := gin.New()
	RegisterTokenRoutes(r, TokenHandlerDeps{
		TokenService:    tokenSvc,
		ClientAuth:      clientAuth,
		Audit:           &audit.Recorder{},
		AuthCodeService: codes,
		UserToken:       service.NewUserTokenService(nil, keys, service.UserTokenServiceOptions{Issuer: "https://idp.test", AccessTokenTTL: time.Hour}),
		UserLookup:      &fakeUserLookup{user: user},
		SessionLookup:   &fakeSessionLookup{session: session},
		OrgLookup:       &fakeOrgLookup{org: &domain.Organization{ID: user.OrganizationID, Active: true}},
		RefreshTokens:   refresh,
	})
	return &publicExchangeFixture{engine: r, codes: codes, user: user, session: session}
}

// code mints a PKCE-bound code for clientID and returns it with its verifier.
func (f *publicExchangeFixture) code(t *testing.T, clientID, scope string) (string, string) {
	t.Helper()
	verifier, challenge := authCodePKCEPair(t)
	created, err := f.codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID: clientID, UserID: f.user.ID, SessionID: f.session.ID, RedirectURI: publicTestRedirect,
		Scope: scope, CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("create code: %v", err)
	}
	return created.Code, verifier
}

func (f *publicExchangeFixture) post(form url.Values) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.engine.ServeHTTP(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

func TestToken_PublicClientRedeemsItsCodeWithPKCE(t *testing.T) {
	f := newPublicExchangeFixture(t)
	code, verifier := f.code(t, publicTestClientID, "openid offline_access")
	status, body := f.post(url.Values{
		"grant_type": {"authorization_code"}, "client_id": {publicTestClientID}, "code": {code},
		"redirect_uri": {publicTestRedirect}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("public client code exchange = %d %v; want 200", status, body["error"])
	}
	if tok, _ := body["access_token"].(string); tok == "" {
		t.Error("public client exchange returned no access_token")
	}
	// A public client is refused at the refresh_token grant
	// (TokenService.IssueRefresh), so it is not handed a token it can never
	// redeem.
	if body["refresh_token"] != nil {
		t.Error("public client received a refresh_token it can never redeem")
	}
}

func TestToken_PublicClientWithoutVerifierIsNotAdmitted(t *testing.T) {
	f := newPublicExchangeFixture(t)
	code, _ := f.code(t, publicTestClientID, "openid")
	status, body := f.post(url.Values{
		"grant_type": {"authorization_code"}, "client_id": {publicTestClientID}, "code": {code},
		"redirect_uri": {publicTestRedirect},
	})
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("public client without code_verifier = %d %v; want 401 invalid_client", status, body["error"])
	}
}

func TestToken_PublicClientMayNotUseOtherGrants(t *testing.T) {
	f := newPublicExchangeFixture(t)
	for _, grant := range []string{"client_credentials", "refresh_token"} {
		status, body := f.post(url.Values{
			"grant_type": {grant}, "client_id": {publicTestClientID}, "code_verifier": {"x"}, "refresh_token": {"r"},
		})
		if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Errorf("public client, grant %s, no secret = %d %v; want 401 invalid_client", grant, status, body["error"])
		}
	}
}

func TestToken_ConfidentialClientCannotDropItsSecretForPKCE(t *testing.T) {
	f := newPublicExchangeFixture(t)
	code, verifier := f.code(t, confidentialTestClientID, "openid")
	status, body := f.post(url.Values{
		"grant_type": {"authorization_code"}, "client_id": {confidentialTestClientID}, "code": {code},
		"redirect_uri": {publicTestRedirect}, "code_verifier": {verifier},
	})
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("confidential client without its secret = %d %v; want 401 invalid_client", status, body["error"])
	}
}
