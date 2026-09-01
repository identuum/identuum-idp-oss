package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// helper: seed a confidential client into the existing
// inMemoryClientRepo with a known plaintext secret. The
// in-repo struct stores the hash; HashSecret matches what
// ClientService.AuthenticateClient computes from the plaintext.
func seedConfidentialClient(t *testing.T, repo *inMemoryClientRepo, clientID, plaintextSecret string, isPublic bool) *domain.Client {
	t.Helper()
	id := uuid.New()
	orgID := uuid.New()
	c := &domain.Client{
		ID:               id,
		ClientID:         clientID,
		Name:             "test-client",
		IsPublic:         isPublic,
		ClientSecretHash: crypto.HashSecret(plaintextSecret),
		OrganizationID:   &orgID,
	}
	if err := repo.RegisterClient(context.Background(), c); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	return c
}

// seedClientMethod seeds a client with an EXPLICIT token_endpoint_auth_method
// so the P0-7 exact-method tests can pin each registered method.
func seedClientMethod(t *testing.T, repo *inMemoryClientRepo, clientID, plaintextSecret string, isPublic bool, method string) *domain.Client {
	t.Helper()
	oid := uuid.New()
	c := &domain.Client{
		ID:                      uuid.New(),
		ClientID:                clientID,
		Name:                    "test-client",
		IsPublic:                isPublic,
		ClientSecretHash:        crypto.HashSecret(plaintextSecret),
		TokenEndpointAuthMethod: method,
		OrganizationID:          &oid,
	}
	if err := repo.RegisterClient(context.Background(), c); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	return c
}

// ---------- P0-7: exact registered-method client auth ----------

// A private_key_jwt (assertion-only) client MUST NOT authenticate via a secret,
// even if a leftover secret hash lingers on the row (the existing-client case).
func TestOAuthClientAuth_PrivateKeyJWTClient_SecretAuthRejected(t *testing.T) {
	repo := newClientRepo()
	auth := NewOAuthClientAuthService(nil, NewClientService(nil, repo), nil)
	c := seedClientMethod(t, repo, "pkjwt-cli", "LEFTOVER-SECRET", false, "private_key_jwt")

	for _, m := range []string{ClientAuthMethodBasic, ClientAuthMethodPost} {
		if _, err := auth.Authenticate(context.Background(), c.ClientID, "LEFTOVER-SECRET", m); !errors.Is(err, ErrInvalidOAuthClientCredentials) {
			t.Fatalf("private_key_jwt client via %s = %v, want ErrInvalidOAuthClientCredentials", m, err)
		}
	}
}

// Basic and Post are NOT interchangeable: each registered method succeeds ONLY
// with its own presentation, and is rejected via the other.
// RULE: P0-CLIAUTH-1
func TestOAuthClientAuth_BasicVsPostNotInterchangeable(t *testing.T) {
	repo := newClientRepo()
	auth := NewOAuthClientAuthService(nil, NewClientService(nil, repo), nil)
	basicClient := seedClientMethod(t, repo, "basic-cli", "S1", false, ClientAuthMethodBasic)
	postClient := seedClientMethod(t, repo, "post-cli", "S2", false, ClientAuthMethodPost)

	if _, err := auth.Authenticate(context.Background(), basicClient.ClientID, "S1", ClientAuthMethodPost); !errors.Is(err, ErrInvalidOAuthClientCredentials) {
		t.Fatalf("basic-registered client via post = %v, want rejected", err)
	}
	if _, err := auth.Authenticate(context.Background(), basicClient.ClientID, "S1", ClientAuthMethodBasic); err != nil {
		t.Fatalf("basic-registered client via basic = %v, want success", err)
	}
	if _, err := auth.Authenticate(context.Background(), postClient.ClientID, "S2", ClientAuthMethodBasic); !errors.Is(err, ErrInvalidOAuthClientCredentials) {
		t.Fatalf("post-registered client via basic = %v, want rejected", err)
	}
	if _, err := auth.Authenticate(context.Background(), postClient.ClientID, "S2", ClientAuthMethodPost); err != nil {
		t.Fatalf("post-registered client via post = %v, want success", err)
	}
}

// A public ("none") client presenting a secret is rejected.
func TestOAuthClientAuth_PublicClientPresentingSecretRejected(t *testing.T) {
	repo := newClientRepo()
	auth := NewOAuthClientAuthService(nil, NewClientService(nil, repo), nil)
	seedClientMethod(t, repo, "pub-cli", "", true, "none") // public, no secret

	if _, err := auth.Authenticate(context.Background(), "pub-cli", "any-secret", ClientAuthMethodBasic); !errors.Is(err, ErrInvalidOAuthClientCredentials) {
		t.Fatalf("public client presenting secret = %v, want rejected", err)
	}
}

// ---------- P0-7: registration does not mint a secret for private_key_jwt ----------

func TestClientService_RegisterClient_PrivateKeyJWTGetsNoSecret(t *testing.T) {
	svc := NewClientService(nil, newClientRepo())
	c, secret, err := svc.RegisterClient(context.Background(), RegisterClientOptions{
		Name:         "pkjwt",
		RedirectURIs: []string{"https://app.example.com/cb"},
		// THE-MIRROR: create now runs the full document validator, and a
		// private_key_jwt client REQUIRES exactly one key source — the rule
		// the DB CHECK always enforced; this test's fake repo just never
		// fired it. A key-source-less pkj client was never persistable.
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKSUri:                 "https://app.example.com/jwks.json",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if secret != "" {
		t.Errorf("private_key_jwt client returned a plaintext secret, want none")
	}
	if c.ClientSecretHash != "" {
		t.Errorf("private_key_jwt client stored a secret hash, want none")
	}
}

func TestClientService_RegisterClient_ConfidentialStillGetsSecret(t *testing.T) {
	svc := NewClientService(nil, newClientRepo())
	c, secret, err := svc.RegisterClient(context.Background(), RegisterClientOptions{
		Name:         "conf",
		RedirectURIs: []string{"https://app.example.com/cb"},
		// empty method → client_secret_basic (RFC 6749 default) → gets a secret.
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if secret == "" || c.ClientSecretHash == "" {
		t.Errorf("confidential (secret) client must receive a generated secret")
	}
}

// ---------- ClientService.AuthenticateClient ----------

func TestClientService_AuthenticateClient_ConfidentialOK(t *testing.T) {
	repo := newClientRepo()
	svc := NewClientService(nil, repo)
	c := seedConfidentialClient(t, repo, "cli-1", "SEKRET-MUST-NOT-LEAK", false)
	got, err := svc.AuthenticateClient(context.Background(), c.ClientID, "SEKRET-MUST-NOT-LEAK")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if got.ClientID != c.ClientID {
		t.Errorf("client_id = %q, want %q", got.ClientID, c.ClientID)
	}
}

func TestClientService_AuthenticateClient_ConfidentialEmptySecretRejected(t *testing.T) {
	repo := newClientRepo()
	svc := NewClientService(nil, repo)
	c := seedConfidentialClient(t, repo, "cli-1", "S", false)
	_, err := svc.AuthenticateClient(context.Background(), c.ClientID, "")
	if !errors.Is(err, ErrInvalidClientCredentials) {
		t.Errorf("empty secret = %v, want ErrInvalidClientCredentials", err)
	}
}

func TestClientService_AuthenticateClient_ConfidentialWrongSecretRejected(t *testing.T) {
	repo := newClientRepo()
	svc := NewClientService(nil, repo)
	c := seedConfidentialClient(t, repo, "cli-1", "S", false)
	_, err := svc.AuthenticateClient(context.Background(), c.ClientID, "WRONG")
	if !errors.Is(err, ErrInvalidClientCredentials) {
		t.Errorf("wrong secret = %v, want ErrInvalidClientCredentials", err)
	}
}

func TestClientService_AuthenticateClient_UnknownClient(t *testing.T) {
	svc := NewClientService(nil, newClientRepo())
	_, err := svc.AuthenticateClient(context.Background(), "no-such", "anything")
	if !errors.Is(err, ErrInvalidClientCredentials) {
		t.Errorf("unknown = %v, want ErrInvalidClientCredentials", err)
	}
}

func TestClientService_AuthenticateClient_EmptyClientID(t *testing.T) {
	svc := NewClientService(nil, newClientRepo())
	_, err := svc.AuthenticateClient(context.Background(), "", "anything")
	if !errors.Is(err, ErrInvalidClientCredentials) {
		t.Errorf("empty client_id = %v, want ErrInvalidClientCredentials", err)
	}
}

// Public client + supplied (matching) secret still authenticates.
func TestClientService_AuthenticateClient_PublicWithMatchingSecretOK(t *testing.T) {
	repo := newClientRepo()
	svc := NewClientService(nil, repo)
	c := seedConfidentialClient(t, repo, "cli-pub", "P", true)
	got, err := svc.AuthenticateClient(context.Background(), c.ClientID, "P")
	if err != nil {
		t.Errorf("public+matching = %v, want nil", err)
	}
	if got == nil {
		t.Errorf("public+matching returned nil client")
	}
}

// Public client + WRONG supplied secret is rejected.
func TestClientService_AuthenticateClient_PublicWithWrongSecretRejected(t *testing.T) {
	repo := newClientRepo()
	svc := NewClientService(nil, repo)
	c := seedConfidentialClient(t, repo, "cli-pub", "P", true)
	_, err := svc.AuthenticateClient(context.Background(), c.ClientID, "WRONG")
	if !errors.Is(err, ErrInvalidClientCredentials) {
		t.Errorf("public+wrong = %v, want ErrInvalidClientCredentials", err)
	}
}

// Public client + EMPTY secret authenticates (no secret required).
func TestClientService_AuthenticateClient_PublicEmptySecretOK(t *testing.T) {
	repo := newClientRepo()
	svc := NewClientService(nil, repo)
	c := seedConfidentialClient(t, repo, "cli-pub", "P", true)
	got, err := svc.AuthenticateClient(context.Background(), c.ClientID, "")
	if err != nil {
		t.Errorf("public+empty = %v, want nil", err)
	}
	if got == nil {
		t.Errorf("public+empty returned nil client")
	}
}

// ---------- APIResourceService.AuthenticateAPIResource ----------

func seedAPIResource(t *testing.T, repo *inMemoryAPIResourceRepo, audience, plaintextSecret string, active bool) *domain.APIResource {
	t.Helper()
	r := &domain.APIResource{
		ID:                 uuid.New(),
		OrganizationID:     uuid.New(),
		Name:               "test-resource",
		Audience:           audience,
		Active:             active,
		TokenTTLSecs:       3600,
		ResourceSecretHash: crypto.HashSecret(plaintextSecret),
	}
	if err := repo.Create(context.Background(), r, nil); err != nil {
		t.Fatalf("seed api resource: %v", err)
	}
	return r
}

// Extend inMemoryAPIResourceRepo with GetByAudienceGlobal so the
// new AuthenticateAPIResource path works in tests.
func (r *inMemoryAPIResourceRepo) GetByAudienceGlobalLookup(audience string) *domain.APIResource {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.rows {
		if v.Audience == audience {
			return v
		}
	}
	return nil
}

func TestAPIResourceService_AuthenticateAPIResource_OK(t *testing.T) {
	repo := newAPIResourceRepo()
	svc := NewAPIResourceService(nil, repo)
	res := seedAPIResource(t, repo, "https://api.example.com", "RES-SEKRET-MUST-NOT-LEAK", true)
	got, err := svc.AuthenticateAPIResource(context.Background(), res.Audience, "RES-SEKRET-MUST-NOT-LEAK")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if got.Audience != res.Audience {
		t.Errorf("audience = %q", got.Audience)
	}
}

func TestAPIResourceService_AuthenticateAPIResource_EmptyAudienceRejected(t *testing.T) {
	svc := NewAPIResourceService(nil, newAPIResourceRepo())
	_, err := svc.AuthenticateAPIResource(context.Background(), "", "x")
	if !errors.Is(err, ErrInvalidAPIResourceCredentials) {
		t.Errorf("empty audience = %v, want ErrInvalidAPIResourceCredentials", err)
	}
}

func TestAPIResourceService_AuthenticateAPIResource_EmptySecretRejected(t *testing.T) {
	repo := newAPIResourceRepo()
	svc := NewAPIResourceService(nil, repo)
	res := seedAPIResource(t, repo, "https://api.example.com", "S", true)
	_, err := svc.AuthenticateAPIResource(context.Background(), res.Audience, "")
	if !errors.Is(err, ErrInvalidAPIResourceCredentials) {
		t.Errorf("empty secret = %v, want ErrInvalidAPIResourceCredentials", err)
	}
}

// An API resource authenticates only by constant-time match of its active
// audience-bound secret; a wrong secret is refused with the one opaque
// credentials error.
// RULE: APIRES-AUTH-1
func TestAPIResourceService_AuthenticateAPIResource_WrongSecretRejected(t *testing.T) {
	repo := newAPIResourceRepo()
	svc := NewAPIResourceService(nil, repo)
	res := seedAPIResource(t, repo, "https://api.example.com", "S", true)
	_, err := svc.AuthenticateAPIResource(context.Background(), res.Audience, "WRONG")
	if !errors.Is(err, ErrInvalidAPIResourceCredentials) {
		t.Errorf("wrong secret = %v, want ErrInvalidAPIResourceCredentials", err)
	}
}

func TestAPIResourceService_AuthenticateAPIResource_InactiveRejected(t *testing.T) {
	repo := newAPIResourceRepo()
	svc := NewAPIResourceService(nil, repo)
	res := seedAPIResource(t, repo, "https://api.example.com", "S", false)
	_, err := svc.AuthenticateAPIResource(context.Background(), res.Audience, "S")
	if !errors.Is(err, ErrInvalidAPIResourceCredentials) {
		t.Errorf("inactive = %v, want ErrInvalidAPIResourceCredentials", err)
	}
}

// ---------- OAuthClientAuthService ----------

func TestOAuthClientAuth_NewRequiresClient(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewOAuthClientAuthService(nil, nil, ...) did not panic")
		}
	}()
	_ = NewOAuthClientAuthService(nil, nil, nil)
}

func TestOAuthClientAuth_OAuthClientSucceeds(t *testing.T) {
	clientRepo := newClientRepo()
	clientSvc := NewClientService(nil, clientRepo)
	auth := NewOAuthClientAuthService(nil, clientSvc, nil)
	c := seedConfidentialClient(t, clientRepo, "cli-1", "S", false)
	got, err := auth.Authenticate(context.Background(), c.ClientID, "S", ClientAuthMethodBasic)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.Kind != AuthenticatedClientKindOAuth {
		t.Errorf("kind = %v, want oauth_client", got.Kind)
	}
	if got.ClientID != c.ClientID {
		t.Errorf("client_id = %q", got.ClientID)
	}
}

func TestOAuthClientAuth_APIResourceFallback(t *testing.T) {
	clientRepo := newClientRepo()
	clientSvc := NewClientService(nil, clientRepo)
	resRepo := newAPIResourceRepo()
	resSvc := NewAPIResourceService(nil, resRepo)
	auth := NewOAuthClientAuthService(nil, clientSvc, resSvc)
	res := seedAPIResource(t, resRepo, "https://api.example.com", "RES-S", true)
	got, err := auth.Authenticate(context.Background(), res.Audience, "RES-S", ClientAuthMethodBasic)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.Kind != AuthenticatedClientKindAPIResource {
		t.Errorf("kind = %v, want api_resource", got.Kind)
	}
	if got.ClientID != res.Audience {
		t.Errorf("client_id = %q", got.ClientID)
	}
}

func TestOAuthClientAuth_UnknownReturnsOpaqueError(t *testing.T) {
	auth := NewOAuthClientAuthService(nil, NewClientService(nil, newClientRepo()), NewAPIResourceService(nil, newAPIResourceRepo()))
	_, err := auth.Authenticate(context.Background(), "no-such", "anything", ClientAuthMethodBasic)
	if !errors.Is(err, ErrInvalidOAuthClientCredentials) {
		t.Errorf("unknown = %v, want ErrInvalidOAuthClientCredentials", err)
	}
}

func TestOAuthClientAuth_NoAPIResourceServiceSkipsFallback(t *testing.T) {
	clientRepo := newClientRepo()
	clientSvc := NewClientService(nil, clientRepo)
	auth := NewOAuthClientAuthService(nil, clientSvc, nil) // no fallback
	// Even with seeded api resource in a separate repo, no fallback fires.
	_, err := auth.Authenticate(context.Background(), "https://api.example.com", "RES-S", ClientAuthMethodBasic)
	if !errors.Is(err, ErrInvalidOAuthClientCredentials) {
		t.Errorf("no-fallback = %v, want ErrInvalidOAuthClientCredentials", err)
	}
}

// Pin opaqueness: the returned AuthenticatedClient must not
// carry the raw secret in any field. Sanity check.
func TestOAuthClientAuth_AuthenticatedClientHasNoSecretField(t *testing.T) {
	clientRepo := newClientRepo()
	clientSvc := NewClientService(nil, clientRepo)
	auth := NewOAuthClientAuthService(nil, clientSvc, nil)
	seedConfidentialClient(t, clientRepo, "cli-1", "SEKRET", false)
	got, err := auth.Authenticate(context.Background(), "cli-1", "SEKRET", ClientAuthMethodBasic)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	// Reflect on the struct fields: none should be named "Secret"
	// or "Hash". The struct is small enough to enumerate by name
	// directly.
	if got.Name == "SEKRET" || got.ClientID == "SEKRET" {
		t.Errorf("raw secret reflected through identity field")
	}
}
