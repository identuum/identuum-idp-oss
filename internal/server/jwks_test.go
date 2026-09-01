package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// stubKeyProvider lets tests inject a specific JWKS without going
// through the repository layer.
type stubKeyProvider struct {
	set JWKS
	err error
}

func (s stubKeyProvider) PublicJWKS(_ context.Context) (JWKS, error) {
	return s.set, s.err
}

// stubKeyRepository implements repository.KeyRepository just enough
// for the JWKS provider tests. Unused methods panic — the JWKS path
// only reads GetActiveSigningKeys.
type stubKeyRepository struct {
	active []domain.SigningKey
	err    error
}

func (s *stubKeyRepository) GetActiveSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	return s.active, s.err
}
func (s *stubKeyRepository) GetAllSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	panic("stubKeyRepository.GetAllSigningKeys not implemented")
}
func (s *stubKeyRepository) GetSigningKeyByKID(_ context.Context, _ string) (*domain.SigningKey, error) {
	panic("stubKeyRepository.GetSigningKeyByKID not implemented")
}
func (s *stubKeyRepository) CreateSigningKey(_ context.Context, _ *domain.SigningKey) error {
	panic("stubKeyRepository.CreateSigningKey not implemented")
}
func (s *stubKeyRepository) ActivateSigningKey(_ context.Context, _ string) error {
	panic("stubKeyRepository.ActivateSigningKey not implemented")
}
func (s *stubKeyRepository) RotateSigningKey(_ context.Context, _, _ string, _ *time.Time) error {
	panic("stubKeyRepository.RotateSigningKey not implemented")
}
func (s *stubKeyRepository) DeprecateSigningKey(_ context.Context, _ string, _ time.Time) error {
	panic("stubKeyRepository.DeprecateSigningKey not implemented")
}
func (s *stubKeyRepository) DeleteExpiredKeys(_ context.Context) (int, error) {
	panic("stubKeyRepository.DeleteExpiredKeys not implemented")
}

// genEd25519PEM produces a fresh Ed25519 keypair and returns the
// public key encoded as PKIX PEM (the format
// internal/postgres/key_repository_pgx.go persists).
func genEd25519PEM(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// genP256PEM produces a fresh P-256 keypair and returns the public
// key encoded as PKIX PEM.
func genP256PEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// genRSAPEM produces a fresh RSA keypair and returns the public key
// encoded as PKIX PEM.
func genRSAPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestPublicKeyToJWK_EdDSA(t *testing.T) {
	pemStr := genEd25519PEM(t)
	jwk, err := PublicKeyToJWK("ed-test-1", domain.KeyAlgorithmEdDSA, pemStr)
	if err != nil {
		t.Fatalf("PublicKeyToJWK(EdDSA) error: %v", err)
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Alg != "EdDSA" || jwk.Use != "sig" {
		t.Errorf("EdDSA JWK fields wrong: %+v", jwk)
	}
	if jwk.Kid != "ed-test-1" {
		t.Errorf("kid = %q, want ed-test-1", jwk.Kid)
	}
	// x is a base64url-encoded Ed25519 public key (32 bytes).
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatalf("x is not base64url: %v", err)
	}
	if len(x) != ed25519.PublicKeySize {
		t.Errorf("x length = %d, want %d", len(x), ed25519.PublicKeySize)
	}
	// y must be absent for OKP keys.
	if jwk.Y != "" {
		t.Errorf("EdDSA JWK must not carry y; got %q", jwk.Y)
	}
}

func TestPublicKeyToJWK_ES256(t *testing.T) {
	pemStr := genP256PEM(t)
	jwk, err := PublicKeyToJWK("es-test-1", domain.KeyAlgorithmES256, pemStr)
	if err != nil {
		t.Fatalf("PublicKeyToJWK(ES256) error: %v", err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Alg != "ES256" || jwk.Use != "sig" {
		t.Errorf("ES256 JWK fields wrong: %+v", jwk)
	}
	if jwk.Kid != "es-test-1" {
		t.Errorf("kid = %q, want es-test-1", jwk.Kid)
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatalf("x is not base64url: %v", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		t.Fatalf("y is not base64url: %v", err)
	}
	if len(x) != 32 {
		t.Errorf("x length = %d, want 32 (P-256)", len(x))
	}
	if len(y) != 32 {
		t.Errorf("y length = %d, want 32 (P-256)", len(y))
	}
}

// TestPublicKeyToJWK_RS256 pins THE-PKCE-DECISION posture at the JWK
// serializer layer: RS256 is a REAL (testing-only, never-default) id_token
// signing capability, so its public JWK must serialise correctly — kty RSA,
// n/e populated per RFC 7518 §6.3.1, and no private material.
func TestPublicKeyToJWK_RS256(t *testing.T) {
	pemStr := genRSAPEM(t)
	jwk, err := PublicKeyToJWK("rsa-test-1", domain.KeyAlgorithmRS256, pemStr)
	if err != nil {
		t.Fatalf("PublicKeyToJWK(RS256) error: %v", err)
	}
	if jwk.Kty != "RSA" || jwk.Alg != "RS256" || jwk.Use != "sig" {
		t.Errorf("RS256 JWK fields wrong: %+v", jwk)
	}
	if jwk.Kid != "rsa-test-1" {
		t.Errorf("kid = %q, want rsa-test-1", jwk.Kid)
	}
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("n is not base64url: %v", err)
	}
	if len(n) != 256 {
		t.Errorf("n length = %d bytes, want 256 (2048-bit modulus)", len(n))
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Fatalf("e is not base64url: %v", err)
	}
	if len(e) == 0 {
		t.Error("e is empty")
	}
	// RSA JWK must not reuse the EC/OKP coordinate fields.
	if jwk.X != "" || jwk.Y != "" || jwk.Crv != "" {
		t.Errorf("RSA JWK carries EC/OKP fields: %+v", jwk)
	}
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(raw), `"d"`) {
		t.Errorf("RSA JWK JSON contains private field d: %s", raw)
	}
}

// The serializer still refuses algorithms outside the issuance set.
func TestPublicKeyToJWK_UnknownAlgorithmRejected(t *testing.T) {
	_, err := PublicKeyToJWK("hs-test-1", domain.KeyAlgorithm("HS256"), genRSAPEM(t))
	if err == nil {
		t.Fatal("PublicKeyToJWK(HS256) returned nil error; expected unsupported-algorithm")
	}
	if !errors.Is(err, errUnsupportedAlgorithm) {
		t.Errorf("expected errUnsupportedAlgorithm sentinel; got %v", err)
	}
}

func TestPublicKeyToJWK_NeverEmitsPrivateField(t *testing.T) {
	// Confirms the JWK struct shape itself excludes the private
	// scalar `d`. If a future slice adds a private-mode JWK type, it
	// must not reuse this struct.
	jwk, err := PublicKeyToJWK("ed-priv-check", domain.KeyAlgorithmEdDSA, genEd25519PEM(t))
	if err != nil {
		t.Fatalf("PublicKeyToJWK: %v", err)
	}
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	// PREMISE: the serialisation must be a REAL JWK before absence over it
	// means anything — a zero-valued struct marshals to near-empty JSON that
	// contains no "d" while containing no key either (V4).
	for _, want := range []string{`"kty":"OKP"`, `"x":`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("JWK JSON lacks %s — this is not a populated public JWK, so the private-field sweep below would pass vacuously: %s", want, raw)
		}
	}
	if strings.Contains(string(raw), `"d"`) {
		t.Errorf("JWK JSON contains private field d: %s", raw)
	}
	if strings.Contains(string(raw), `"p"`) || strings.Contains(string(raw), `"q"`) {
		t.Errorf("JWK JSON contains RSA private factors: %s", raw)
	}
}

// TestJWKSEndpoint_EmptyProvider verifies the smoke handler serves
// {"keys":[]} when nothing is configured — the default --serve mode
// without a DB-backed provider.
func TestJWKSEndpoint_EmptyProvider(t *testing.T) {
	h := NewSmokeHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var set JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("body is not JWKS JSON: %v; raw=%q", err, rec.Body.String())
	}
	if set.Keys == nil {
		t.Errorf("Keys is nil; want empty slice")
	}
	if len(set.Keys) != 0 {
		t.Errorf("Keys has %d entries; want 0", len(set.Keys))
	}
}

// TestJWKSEndpoint_PopulatedProvider verifies that when a provider
// returns one EdDSA + one ES256 key, both surface on the wire with
// the correct shape and no private material.
func TestJWKSEndpoint_PopulatedProvider(t *testing.T) {
	edJWK, err := PublicKeyToJWK("ed-1", domain.KeyAlgorithmEdDSA, genEd25519PEM(t))
	if err != nil {
		t.Fatalf("EdDSA conversion: %v", err)
	}
	esJWK, err := PublicKeyToJWK("es-1", domain.KeyAlgorithmES256, genP256PEM(t))
	if err != nil {
		t.Fatalf("ES256 conversion: %v", err)
	}
	provider := stubKeyProvider{set: JWKS{Keys: []JWK{edJWK, esJWK}}}
	h := NewSmokeHandlerWithJWKS(OIDCDiscoveryConfig{}, provider)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var set JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("body is not JWKS JSON: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("Keys has %d entries; want 2", len(set.Keys))
	}
	for _, k := range set.Keys {
		if k.Use != "sig" {
			t.Errorf("key %q use = %q, want sig", k.Kid, k.Use)
		}
		if k.Alg != "EdDSA" && k.Alg != "ES256" {
			t.Errorf("key %q alg = %q, want EdDSA or ES256", k.Kid, k.Alg)
		}
	}
	// Final shield: literal substring check against the raw body
	// guarantees no private field d (or RSA fields n/e) snuck in.
	body := rec.Body.String()
	for _, banned := range []string{`"d":`, `"p":`, `"q":`, `"dp":`, `"dq":`, `"qi":`, `"n":`, `"e":`} {
		if strings.Contains(body, banned) {
			t.Errorf("JWKS body contains banned field %s; body=%s", banned, body)
		}
	}
}

// TestJWKSEndpoint_RS256PublicOnly (THE-PKCE-DECISION): an RS256 key now
// serves over the wire — its id_tokens must be verifiable — but strictly
// public-only: modulus + exponent, never a private scalar.
func TestJWKSEndpoint_RS256PublicOnly(t *testing.T) {
	rsaJWK, err := PublicKeyToJWK("rsa-wire", domain.KeyAlgorithmRS256, genRSAPEM(t))
	if err != nil {
		t.Fatalf("RS256 conversion: %v", err)
	}
	h := NewSmokeHandlerWithJWKS(OIDCDiscoveryConfig{}, stubKeyProvider{set: JWKS{Keys: []JWK{rsaJWK}}})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `"alg":"RS256"`) || !strings.Contains(body, `"n":`) || !strings.Contains(body, `"e":`) {
		t.Errorf("JWKS body does not serve the RS256 public key: %s", body)
	}
	for _, banned := range []string{`"d":`, `"p":`, `"q":`, `"dp":`, `"dq":`, `"qi":`} {
		if strings.Contains(body, banned) {
			t.Errorf("JWKS body contains private field %s; body=%s", banned, body)
		}
	}
}

// TestJWKSEndpoint_POSTIs405 enforces the GET-only contract.
func TestJWKSEndpoint_POSTIs405(t *testing.T) {
	h := NewSmokeHandler()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		req := httptest.NewRequest(method, "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s jwks status = %d, want 405", method, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
			t.Errorf("%s jwks Allow header = %q, want GET", method, allow)
		}
	}
}

// TestJWKSEndpoint_ProviderError surfaces 500 + generic body when
// the provider fails. No provider-internal detail leaks to the
// caller.
func TestJWKSEndpoint_ProviderError(t *testing.T) {
	provider := stubKeyProvider{err: errors.New("internal provider failure with sensitive detail")}
	h := NewSmokeHandlerWithJWKS(OIDCDiscoveryConfig{}, provider)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "sensitive detail") {
		t.Errorf("response body leaks provider error detail: %q", rec.Body.String())
	}
}

// TestRepositoryJWKSProvider_PublishesRS256 (THE-PKCE-DECISION): an active
// RS256 row now publishes its public JWK alongside EdDSA — the id_tokens it
// signs (explicit-registration, testing-only) must be verifiable. A row with
// an algorithm outside the issuance set still drops silently, keeping the
// per-key filter boundary pinned.
func TestRepositoryJWKSProvider_PublishesRS256(t *testing.T) {
	repo := &stubKeyRepository{
		active: []domain.SigningKey{
			{KID: "ed-keep", Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: genEd25519PEM(t)},
			{KID: "rsa-keep", Algorithm: domain.KeyAlgorithmRS256, PublicKey: genRSAPEM(t)},
			{KID: "hs-drop", Algorithm: domain.KeyAlgorithm("HS256"), PublicKey: genRSAPEM(t)},
		},
	}
	provider := RepositoryJWKSProvider{Repo: repo}
	set, err := provider.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("Keys has %d entries; want 2 (EdDSA + RS256 publish, HS256 drops)", len(set.Keys))
	}
	kids := map[string]bool{}
	for _, k := range set.Keys {
		kids[k.Kid] = true
	}
	if !kids["ed-keep"] || !kids["rsa-keep"] {
		t.Errorf("published kids = %v, want ed-keep + rsa-keep", kids)
	}
}

// TestRepositoryJWKSProvider_NilRepo guards against the "forgot to
// wire" mistake — nil repo surfaces an explicit error instead of
// nil-dereferencing.
func TestRepositoryJWKSProvider_NilRepo(t *testing.T) {
	provider := RepositoryJWKSProvider{Repo: nil}
	_, err := provider.PublicJWKS(context.Background())
	if err == nil {
		t.Fatal("PublicJWKS with nil Repo returned nil error")
	}
}
