package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// inMemoryKeyProvider satisfies SigningKeyProvider for tests.
type inMemoryKeyProvider struct {
	keys []domain.SigningKey
	err  error
}

func (p *inMemoryKeyProvider) ListActive(_ context.Context) ([]domain.SigningKey, error) {
	if p.err != nil {
		return nil, p.err
	}
	out := make([]domain.SigningKey, len(p.keys))
	copy(out, p.keys)
	return out, nil
}

// helpers --------------------------------------------------------

func genEdDSAKey(t *testing.T, kid string) domain.SigningKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("EdDSA gen: %v", err)
	}
	return domain.SigningKey{
		KID:        kid,
		Algorithm:  domain.KeyAlgorithmEdDSA,
		PrivateKey: pemMarshal(t, priv),
		PublicKey:  pemMarshalPub(t, pub),
		State:      domain.KeyStateActive,
	}
}

func genES256Key(t *testing.T, kid string) domain.SigningKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ES256 gen: %v", err)
	}
	return domain.SigningKey{
		KID:        kid,
		Algorithm:  domain.KeyAlgorithmES256,
		PrivateKey: pemMarshal(t, priv),
		PublicKey:  pemMarshalPub(t, &priv.PublicKey),
		State:      domain.KeyStateActive,
	}
}

func genRS256Key(t *testing.T, kid string) domain.SigningKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RS256 gen: %v", err)
	}
	return domain.SigningKey{
		KID:        kid,
		Algorithm:  domain.KeyAlgorithmRS256,
		PrivateKey: pemMarshal(t, priv),
		PublicKey:  pemMarshalPub(t, &priv.PublicKey),
		State:      domain.KeyStateActive,
	}
}

func pemMarshal(t *testing.T, key any) string {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}

func pemMarshalPub(t *testing.T, key any) string {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}

func newConfidentialOAuthClient() *AuthenticatedClient {
	return &AuthenticatedClient{
		Kind:     AuthenticatedClientKindOAuth,
		ClientID: "cli-1",
		Name:     "test-client",
		IsPublic: false,
	}
}

func newPublicOAuthClient() *AuthenticatedClient {
	return &AuthenticatedClient{
		Kind:     AuthenticatedClientKindOAuth,
		ClientID: "cli-pub",
		Name:     "public-client",
		IsPublic: true,
	}
}

func newAPIResourceClient(scopes []string) *AuthenticatedClient {
	return &AuthenticatedClient{
		Kind:          AuthenticatedClientKindAPIResource,
		ClientID:      "https://api.example.com",
		Name:          "resource",
		AllowedScopes: scopes,
	}
}

// ---------- Construction ----------

func TestNewTokenService_NilKeysPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewTokenService(nil, nil,...) did not panic")
		}
	}()
	_ = NewTokenService(nil, nil, TokenServiceOptions{Issuer: "x"})
}

func TestNewTokenService_EmptyIssuerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewTokenService(nil, _, empty issuer) did not panic")
		}
	}()
	_ = NewTokenService(nil, &inMemoryKeyProvider{}, TokenServiceOptions{})
}

// ---------- Grant-type validation ----------

func TestIssueClientCredentials_MissingGrantTypeRejected(t *testing.T) {
	svc := NewTokenService(nil, &inMemoryKeyProvider{}, TokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{})
	if !errors.Is(err, ErrTokenServiceInvalidRequest) {
		t.Errorf("err = %v, want ErrTokenServiceInvalidRequest", err)
	}
}

func TestIssueClientCredentials_UnsupportedGrantRejected(t *testing.T) {
	svc := NewTokenService(nil, &inMemoryKeyProvider{}, TokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{GrantType: "authorization_code"})
	if !errors.Is(err, ErrTokenServiceUnsupportedGrant) {
		t.Errorf("err = %v, want ErrTokenServiceUnsupportedGrant", err)
	}
}

func TestIssueClientCredentials_PublicClientRejected(t *testing.T) {
	svc := NewTokenService(nil, &inMemoryKeyProvider{keys: []domain.SigningKey{genEdDSAKey(t, "kid-eddsa")}}, TokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.IssueClientCredentials(context.Background(), newPublicOAuthClient(), ClientCredentialsRequest{GrantType: "client_credentials"})
	if !errors.Is(err, ErrTokenServiceUnauthorizedClient) {
		t.Errorf("err = %v, want ErrTokenServiceUnauthorizedClient", err)
	}
}

// ---------- Key selection + RS256 ban ----------

func TestIssueClientCredentials_NoSigningKeyFailsClosed(t *testing.T) {
	svc := NewTokenService(nil, &inMemoryKeyProvider{}, TokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{GrantType: "client_credentials"})
	if !errors.Is(err, ErrTokenServiceNoSigningKey) {
		t.Errorf("err = %v, want ErrTokenServiceNoSigningKey", err)
	}
}

func TestIssueClientCredentials_RS256OnlyKeyRejectedAsUnavailable(t *testing.T) {
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{genRS256Key(t, "kid-rs256")}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{GrantType: "client_credentials"})
	if !errors.Is(err, ErrTokenServiceNoSigningKey) {
		t.Errorf("RS256-only key not filtered: err=%v", err)
	}
}

func TestIssueClientCredentials_EdDSAPreferredOverES256(t *testing.T) {
	es := genES256Key(t, "kid-es256")
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{es, ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{GrantType: "client_credentials"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Decode header to confirm kid.
	parts := strings.Split(resp.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("token shape wrong: %d parts", len(parts))
	}
	// Trust jwt parser to confirm alg.
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, _, err := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tok.Header["alg"] != "EdDSA" {
		t.Errorf("alg = %v, want EdDSA (preferred)", tok.Header["alg"])
	}
	if tok.Header["kid"] != "kid-eddsa" {
		t.Errorf("kid = %v, want kid-eddsa", tok.Header["kid"])
	}
}

func TestIssueClientCredentials_ES256UsedWhenOnlyES256Available(t *testing.T) {
	es := genES256Key(t, "kid-es256")
	rs := genRS256Key(t, "kid-rs256")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{rs, es}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{GrantType: "client_credentials"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256"}))
	tok, _, err := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tok.Header["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256", tok.Header["alg"])
	}
}

// ---------- Claims ----------

func TestIssueClientCredentials_ClaimsPopulated(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{
		Issuer:         "https://idp.test",
		AccessTokenTTL: 30 * time.Minute,
	})
	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType:         "client_credentials",
		RequestedAudience: "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q", resp.TokenType)
	}
	if resp.ExpiresIn != int64((30 * time.Minute).Seconds()) {
		t.Errorf("expires_in = %d", resp.ExpiresIn)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, _, err := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["iss"] != "https://idp.test" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["sub"] != "cli-1" || claims["client_id"] != "cli-1" {
		t.Errorf("sub/client_id = %v/%v", claims["sub"], claims["client_id"])
	}
	if claims["aud"] != "https://api.example.com" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if _, ok := claims["jti"].(string); !ok {
		t.Errorf("jti missing or not string: %v", claims["jti"])
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Errorf("iat missing or not number: %v", claims["iat"])
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Errorf("exp missing or not number: %v", claims["exp"])
	}
}

// ---------- Scope negotiation ----------

func TestIssueClientCredentials_EmptyScopeYieldsEmpty(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{GrantType: "client_credentials"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if resp.Scope != "" {
		t.Errorf("scope = %q, want empty", resp.Scope)
	}
}

func TestIssueClientCredentials_RequestedScopeWithoutPolicyRejected(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType:      "client_credentials",
		RequestedScope: "billing:read",
	})
	if !errors.Is(err, ErrTokenServiceInvalidScope) {
		t.Errorf("err = %v, want ErrTokenServiceInvalidScope", err)
	}
}

func TestIssueClientCredentials_APIResourceScopeIntersection(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	client := newAPIResourceClient([]string{"billing:read", "billing:write"})
	resp, err := svc.IssueClientCredentials(context.Background(), client, ClientCredentialsRequest{
		GrantType:      "client_credentials",
		RequestedScope: "billing:read billing:read",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if resp.Scope != "billing:read" {
		t.Errorf("scope = %q, want dedup billing:read", resp.Scope)
	}
}

func TestIssueClientCredentials_APIResourceUnauthorizedScopeRejected(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	client := newAPIResourceClient([]string{"billing:read"})
	_, err := svc.IssueClientCredentials(context.Background(), client, ClientCredentialsRequest{
		GrantType:      "client_credentials",
		RequestedScope: "billing:read admin:write",
	})
	if !errors.Is(err, ErrTokenServiceInvalidScope) {
		t.Errorf("err = %v, want ErrTokenServiceInvalidScope", err)
	}
}

// ---------- Verifier roundtrip ----------

func TestIssueClientCredentials_RoundTripVerifies(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{GrantType: "client_credentials"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Verify the signed token using the public key bytes from the
	// same row. We don't depend on the auth package here — we
	// parse the public key ourselves and call jwt.Parse with
	// WithValidMethods.
	pubBlock, _ := pem.Decode([]byte(ed.PublicKey))
	if pubBlock == nil {
		t.Fatalf("public PEM decode failed")
	}
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("public parse: %v", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, err := parser.Parse(resp.AccessToken, func(t *jwt.Token) (any, error) {
		if t.Header["kid"] != ed.KID {
			t.Header["kid"] = nil
		}
		return pub, nil
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !tok.Valid {
		t.Errorf("token not Valid")
	}
}

// ---------- Defense: nil client ----------

func TestIssueClientCredentials_NilClientReturnsInvalidRequest(t *testing.T) {
	svc := NewTokenService(nil, &inMemoryKeyProvider{}, TokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.IssueClientCredentials(context.Background(), nil, ClientCredentialsRequest{GrantType: "client_credentials"})
	if !errors.Is(err, ErrTokenServiceInvalidRequest) {
		t.Errorf("err = %v, want ErrTokenServiceInvalidRequest", err)
	}
}

// ---------- Defense: keys error ----------

func TestIssueClientCredentials_KeyRepoErrorMapsToNoSigningKey(t *testing.T) {
	provider := &inMemoryKeyProvider{err: errors.New("repo down")}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{GrantType: "client_credentials"})
	if !errors.Is(err, ErrTokenServiceNoSigningKey) {
		t.Errorf("err = %v, want ErrTokenServiceNoSigningKey", err)
	}
}

// ---------- Audience policy (RFC 8707) ----------

// stubAudienceLookup is a canned AudienceLookup for tests.
type stubAudienceLookup struct {
	resources map[string]*domain.APIResource
	err       error
	calls     []string
}

func (s *stubAudienceLookup) LookupAudience(_ context.Context, aud string) (*domain.APIResource, error) {
	s.calls = append(s.calls, aud)
	if s.err != nil {
		return nil, s.err
	}
	return s.resources[aud], nil
}

func newActiveResource(t *testing.T, aud string, scopes ...string) *domain.APIResource {
	t.Helper()
	r := &domain.APIResource{
		ID:       uuid.New(),
		Audience: aud,
		Active:   true,
	}
	for _, name := range scopes {
		r.Scopes = append(r.Scopes, domain.APIScope{Name: name})
	}
	return r
}

func TestIssueClientCredentials_UnknownAudienceRejectedAsInvalidTarget(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	lookup := &stubAudienceLookup{resources: map[string]*domain.APIResource{}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithAudienceLookup(lookup)
	_, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType:         "client_credentials",
		RequestedAudience: "https://unknown.example.com",
	})
	if !errors.Is(err, ErrTokenServiceInvalidTarget) {
		t.Errorf("err = %v, want ErrTokenServiceInvalidTarget", err)
	}
	if len(lookup.calls) != 1 || lookup.calls[0] != "https://unknown.example.com" {
		t.Errorf("lookup calls = %v", lookup.calls)
	}
}

func TestIssueClientCredentials_InactiveAudienceRejectedAsInvalidTarget(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	res := newActiveResource(t, "https://billing.example.com", "billing:read")
	res.Active = false
	lookup := &stubAudienceLookup{resources: map[string]*domain.APIResource{
		res.Audience: res,
	}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithAudienceLookup(lookup)
	_, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType:         "client_credentials",
		RequestedAudience: res.Audience,
	})
	if !errors.Is(err, ErrTokenServiceInvalidTarget) {
		t.Errorf("err = %v, want ErrTokenServiceInvalidTarget", err)
	}
}

func TestIssueClientCredentials_LookupErrorRejectedAsInvalidTarget(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	lookup := &stubAudienceLookup{err: errors.New("repo down")}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithAudienceLookup(lookup)
	_, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType:         "client_credentials",
		RequestedAudience: "https://any.example.com",
	})
	if !errors.Is(err, ErrTokenServiceInvalidTarget) {
		t.Errorf("err = %v, want ErrTokenServiceInvalidTarget", err)
	}
}

func TestIssueClientCredentials_APIResourceCallerMintingOtherAudienceRejected(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	other := newActiveResource(t, "https://other.example.com", "other:read")
	lookup := &stubAudienceLookup{resources: map[string]*domain.APIResource{
		other.Audience: other,
	}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithAudienceLookup(lookup)
	caller := &AuthenticatedClient{
		Kind:          AuthenticatedClientKindAPIResource,
		ClientID:      "https://self.example.com",
		AuthRecordID:  uuid.New(),
		AllowedScopes: []string{"self:read"},
	}
	_, err := svc.IssueClientCredentials(context.Background(), caller, ClientCredentialsRequest{
		GrantType:         "client_credentials",
		RequestedAudience: other.Audience,
	})
	if !errors.Is(err, ErrTokenServiceInvalidTarget) {
		t.Errorf("err = %v, want ErrTokenServiceInvalidTarget", err)
	}
}

func TestIssueClientCredentials_APIResourceCallerMintingOwnAudiencePasses(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	id := uuid.New()
	self := &domain.APIResource{
		ID:       id,
		Audience: "https://self.example.com",
		Active:   true,
		Scopes:   []domain.APIScope{{Name: "self:read"}, {Name: "self:write"}},
	}
	lookup := &stubAudienceLookup{resources: map[string]*domain.APIResource{
		self.Audience: self,
	}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithAudienceLookup(lookup)
	caller := &AuthenticatedClient{
		Kind:          AuthenticatedClientKindAPIResource,
		ClientID:      self.Audience,
		AuthRecordID:  id,
		AllowedScopes: []string{"self:read", "self:write"},
	}
	resp, err := svc.IssueClientCredentials(context.Background(), caller, ClientCredentialsRequest{
		GrantType:         "client_credentials",
		RequestedAudience: self.Audience,
		RequestedScope:    "self:read",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if resp.Scope != "self:read" {
		t.Errorf("scope = %q, want self:read", resp.Scope)
	}
}

func TestIssueClientCredentials_ScopeOutsideAudienceRejectedAsInvalidScope(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	res := newActiveResource(t, "https://billing.example.com", "billing:read")
	lookup := &stubAudienceLookup{resources: map[string]*domain.APIResource{
		res.Audience: res,
	}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithAudienceLookup(lookup)
	caller := &AuthenticatedClient{
		Kind:          AuthenticatedClientKindOAuth,
		ClientID:      "cli-1",
		AllowedScopes: []string{"billing:read", "billing:write"},
	}
	// billing:write is in caller's set but NOT in the audience's
	// set → invalid_scope.
	_, err := svc.IssueClientCredentials(context.Background(), caller, ClientCredentialsRequest{
		GrantType:         "client_credentials",
		RequestedAudience: res.Audience,
		RequestedScope:    "billing:write",
	})
	if !errors.Is(err, ErrTokenServiceInvalidScope) {
		t.Errorf("err = %v, want ErrTokenServiceInvalidScope", err)
	}
}

func TestIssueClientCredentials_OAuthClientWithoutPolicyUsesAudienceScopes(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	res := newActiveResource(t, "https://billing.example.com", "billing:read", "billing:write")
	lookup := &stubAudienceLookup{resources: map[string]*domain.APIResource{
		res.Audience: res,
	}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithAudienceLookup(lookup)
	// Caller has no AllowedScopes → audience set IS the policy.
	caller := newConfidentialOAuthClient()
	resp, err := svc.IssueClientCredentials(context.Background(), caller, ClientCredentialsRequest{
		GrantType:         "client_credentials",
		RequestedAudience: res.Audience,
		RequestedScope:    "billing:read",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if resp.Scope != "billing:read" {
		t.Errorf("scope = %q, want billing:read", resp.Scope)
	}
}

func TestIssueClientCredentials_NoAudienceLookupPreservesLegacyBehavior(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType:         "client_credentials",
		RequestedAudience: "https://any.example.com",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// aud claim present, no policy enforcement.
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, _, err := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["aud"] != "https://any.example.com" {
		t.Errorf("aud = %v (no policy mode should echo verbatim)", claims["aud"])
	}
}

// ---------- refresh_token grant ----------

func TestIssueRefresh_DisabledWithoutWiring(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.IssueRefresh(context.Background(), newConfidentialOAuthClient(), RefreshTokenRequest{
		GrantType: "refresh_token", RefreshToken: "anything",
	})
	if !errors.Is(err, ErrTokenServiceRefreshDisabled) {
		t.Errorf("err = %v, want ErrTokenServiceRefreshDisabled", err)
	}
}

func TestIssueRefresh_MissingRefreshTokenIsInvalidRequest(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	rts := NewRefreshTokenService(nil, newInMemoryRefreshTokenRepo(), RefreshTokenServiceOptions{})
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithRefreshTokenService(rts)
	_, err := svc.IssueRefresh(context.Background(), newConfidentialOAuthClient(), RefreshTokenRequest{
		GrantType: "refresh_token",
	})
	if !errors.Is(err, ErrTokenServiceInvalidRequest) {
		t.Errorf("err = %v, want ErrTokenServiceInvalidRequest", err)
	}
}

func TestIssueRefresh_UnknownTokenIsInvalidGrant(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	rts := NewRefreshTokenService(nil, newInMemoryRefreshTokenRepo(), RefreshTokenServiceOptions{})
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithRefreshTokenService(rts)
	_, err := svc.IssueRefresh(context.Background(), newConfidentialOAuthClient(), RefreshTokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: uuid.NewString() + ".AAAA",
	})
	if !errors.Is(err, ErrTokenServiceInvalidGrant) {
		t.Errorf("err = %v, want ErrTokenServiceInvalidGrant", err)
	}
}

func TestIssueRefresh_RotatesAndMintsNewAccessToken(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	repo := newInMemoryRefreshTokenRepo()
	rts := NewRefreshTokenService(nil, repo, RefreshTokenServiceOptions{TTL: time.Hour})
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithRefreshTokenService(rts)
	// Pre-seed a refresh token via Issue.
	issued, err := rts.Issue(context.Background(), IssueRefreshTokenInput{
		ClientID: "cli-1", Subject: "cli-1", Scope: "read",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp, err := svc.IssueRefresh(context.Background(), newConfidentialOAuthClient(), RefreshTokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: issued.Token,
	})
	if err != nil {
		t.Fatalf("issue refresh: %v", err)
	}
	if resp.RefreshToken == "" || resp.RefreshToken == issued.Token {
		t.Errorf("rotation failed: %q vs %q", resp.RefreshToken, issued.Token)
	}
	if resp.AccessToken == "" {
		t.Errorf("no access token minted")
	}
	if resp.Scope != "read" {
		t.Errorf("scope = %q", resp.Scope)
	}
	// Replay must now fail.
	_, err = svc.IssueRefresh(context.Background(), newConfidentialOAuthClient(), RefreshTokenRequest{
		GrantType: "refresh_token", RefreshToken: issued.Token,
	})
	if !errors.Is(err, ErrTokenServiceInvalidGrant) {
		t.Errorf("replay attempt err = %v, want invalid_grant", err)
	}
}

func TestIssueRefresh_ClientMismatchIsInvalidGrant(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	rts := NewRefreshTokenService(nil, newInMemoryRefreshTokenRepo(), RefreshTokenServiceOptions{TTL: time.Hour})
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithRefreshTokenService(rts)
	issued, _ := rts.Issue(context.Background(), IssueRefreshTokenInput{ClientID: "cli-A", Subject: "cli-A"})
	other := &AuthenticatedClient{Kind: AuthenticatedClientKindOAuth, ClientID: "cli-B"}
	_, err := svc.IssueRefresh(context.Background(), other, RefreshTokenRequest{
		GrantType: "refresh_token", RefreshToken: issued.Token,
	})
	if !errors.Is(err, ErrTokenServiceInvalidGrant) {
		t.Errorf("err = %v, want invalid_grant", err)
	}
}

// ---------- service-account binding ----------

// stubServiceAccountLookup returns canned ServiceAccountTokenSubject
// or an error so the TokenService tests can pin every path.
type stubServiceAccountLookup struct {
	want *ServiceAccountTokenSubject
	err  error
}

func (s *stubServiceAccountLookup) LookupForClient(_ context.Context, _ *domain.Client) (*ServiceAccountTokenSubject, error) {
	return s.want, s.err
}

// stubClientLookup satisfies ClientByClientIDLookup.
type stubClientLookup struct {
	client *domain.Client
	err    error
}

func (s *stubClientLookup) GetClientByClientID(_ context.Context, _ string) (*domain.Client, error) {
	return s.client, s.err
}

func TestIssueClientCredentials_NoLookupPreservesLegacySubject(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"})
	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType: "client_credentials",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, _, err := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["sub"] != "cli-1" {
		t.Errorf("legacy sub = %v, want cli-1", claims["sub"])
	}
	if _, ok := claims["actor_type"]; ok {
		t.Errorf("actor_type leaked when no lookup wired")
	}
}

func TestIssueClientCredentials_SABoundTokenCarriesSAClaims(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	saID := uuid.New()
	orgID := uuid.New()
	saLookup := &stubServiceAccountLookup{want: &ServiceAccountTokenSubject{
		Subject:        saID.String(),
		OrganizationID: orgID,
		Role:           "org_admin",
		ActorType:      ActorTypeServiceAccount,
	}}
	clientLookup := &stubClientLookup{client: &domain.Client{ClientID: "cli-1", ServiceAccountID: &saID}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).
		WithServiceAccountLookup(saLookup, clientLookup)
	resp, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType: "client_credentials",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, _, _ := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	claims := tok.Claims.(jwt.MapClaims)
	if claims["sub"] != saID.String() {
		t.Errorf("sub = %v, want SA UUID %s", claims["sub"], saID)
	}
	if claims["client_id"] != "cli-1" {
		t.Errorf("client_id = %v, want cli-1", claims["client_id"])
	}
	if claims["actor_type"] != ActorTypeServiceAccount {
		t.Errorf("actor_type = %v", claims["actor_type"])
	}
	if claims["org_id"] != orgID.String() {
		t.Errorf("org_id = %v", claims["org_id"])
	}
	if claims["role"] != "org_admin" {
		t.Errorf("role = %v", claims["role"])
	}
}

func TestIssueClientCredentials_SALookupErrorMapsToUnauthorizedClient(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	saLookup := &stubServiceAccountLookup{err: ErrServiceAccountInactive}
	clientLookup := &stubClientLookup{client: &domain.Client{ClientID: "cli-1"}}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).
		WithServiceAccountLookup(saLookup, clientLookup)
	_, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType: "client_credentials",
	})
	if !errors.Is(err, ErrTokenServiceUnauthorizedClient) {
		t.Errorf("err = %v, want ErrTokenServiceUnauthorizedClient", err)
	}
}

func TestIssueClientCredentials_ClientLookupErrorMapsToUnauthorizedClient(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	saLookup := &stubServiceAccountLookup{want: &ServiceAccountTokenSubject{Subject: "x"}}
	clientLookup := &stubClientLookup{err: errors.New("repo down")}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).
		WithServiceAccountLookup(saLookup, clientLookup)
	_, err := svc.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{
		GrantType: "client_credentials",
	})
	if !errors.Is(err, ErrTokenServiceUnauthorizedClient) {
		t.Errorf("err = %v", err)
	}
}

func TestIssueClientCredentials_APIResourceCallerSkipsSALookup(t *testing.T) {
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	// SA lookup would explode if called; api_resource path must
	// skip it entirely.
	saLookup := &stubServiceAccountLookup{err: errors.New("SHOULD-NOT-BE-CALLED")}
	clientLookup := &stubClientLookup{err: errors.New("SHOULD-NOT-BE-CALLED")}
	svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).
		WithServiceAccountLookup(saLookup, clientLookup)
	caller := newAPIResourceClient([]string{"billing:read"})
	resp, err := svc.IssueClientCredentials(context.Background(), caller, ClientCredentialsRequest{
		GrantType: "client_credentials",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, _, _ := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	claims := tok.Claims.(jwt.MapClaims)
	if claims["sub"] != caller.ClientID {
		t.Errorf("api_resource sub = %v, want %s", claims["sub"], caller.ClientID)
	}
	if _, ok := claims["actor_type"]; ok {
		t.Errorf("api_resource path emitted actor_type")
	}
}

// quick uuid satisfy
var _ = uuid.Nil
