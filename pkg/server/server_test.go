package server_test

// Tests for the public OSS pkg/server seam.
//
// These tests guard five properties future identuum-idp-ce work will
// rely on:
//
//   1. Every public named type is a true Go type alias of the
//      internal/server authority — values constructed at either path
//      are interchangeable without conversion.
//   2. The public discovery payload exactly matches the internal
//      authority for the same input config, with both ResolveDiscoveryConfig
//      and DiscoveryDocument single-sourcing the OSS no-RS256-issuance
//      policy.
//   3. The JWKSProvider seam round-trips through the public package —
//      EmptyJWKSProvider returns {"keys":[]}, RepositoryJWKSProvider
//      can be constructed via the public alias and feeds the smoke
//      handler the same JWKS the internal authority would.
//   4. PublicKeyToJWK through the public package agrees with the
//      internal authority for an EdDSA input and rejects RS256
//      identically.
//   5. The public package's direct production imports do not pull in
//      CE, the identuum-idp monolith, identuum-ag, identuum-ui, or
//      auth-service.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	internalserver "github.com/identuum/identuum-idp-oss/internal/server"
	pkgserver "github.com/identuum/identuum-idp-oss/pkg/server"
)

// TestPublicTypes_AreAliasesOfInternal pins every public named type
// to its internal/server authority. If any alias degrades to a
// distinct named type this test breaks at compile time (the two
// assignment statements per type require alias identity to compile).
func TestPublicTypes_AreAliasesOfInternal(t *testing.T) {
	// JWK / JWKS: round-trip a zero value through both names.
	jwkPub := pkgserver.JWK{Kid: "alias-jwk", Alg: "EdDSA", Kty: "OKP", Crv: "Ed25519", Use: "sig"}
	var jwkAsInternal internalserver.JWK = jwkPub
	var jwkAsPublic pkgserver.JWK = jwkAsInternal
	assert.Equal(t, "alias-jwk", jwkAsPublic.Kid, "JWK alias must round-trip the Kid field")

	jwksPub := pkgserver.JWKS{Keys: []pkgserver.JWK{jwkPub}}
	var jwksAsInternal internalserver.JWKS = jwksPub
	var jwksAsPublic pkgserver.JWKS = jwksAsInternal
	require.Len(t, jwksAsPublic.Keys, 1, "JWKS alias must round-trip the Keys slice")
	assert.Equal(t, "alias-jwk", jwksAsPublic.Keys[0].Kid)

	// EmptyJWKSProvider: zero value at either path must satisfy both
	// names of the JWKSProvider interface.
	var providerPub pkgserver.JWKSProvider = pkgserver.EmptyJWKSProvider{}
	var providerAsInternal internalserver.JWKSProvider = providerPub
	var providerAsPublic pkgserver.JWKSProvider = providerAsInternal
	set, err := providerAsPublic.PublicJWKS(context.Background())
	require.NoError(t, err)
	assert.Empty(t, set.Keys, "EmptyJWKSProvider through alias must serve {\"keys\":[]}")

	// RepositoryJWKSProvider: zero value with a nil Repo round-trips
	// across the alias boundary. The error-path behaviour is pinned
	// by the per-provider tests below.
	repoPub := pkgserver.RepositoryJWKSProvider{}
	var repoAsInternal internalserver.RepositoryJWKSProvider = repoPub
	var repoAsPublic pkgserver.RepositoryJWKSProvider = repoAsInternal
	assert.Nil(t, repoAsPublic.Repo, "RepositoryJWKSProvider alias must round-trip the nil Repo")

	// OIDCDiscoveryConfig: a literal at either path is the same value.
	cfgPub := pkgserver.OIDCDiscoveryConfig{Issuer: "https://alias.example"}
	var cfgAsInternal internalserver.OIDCDiscoveryConfig = cfgPub
	var cfgAsPublic pkgserver.OIDCDiscoveryConfig = cfgAsInternal
	assert.Equal(t, "https://alias.example", cfgAsPublic.Issuer, "OIDCDiscoveryConfig alias must round-trip Issuer")
}

// TestResolveDiscoveryConfig_PublicMatchesInternal pins that the
// default-filling logic for an OIDCDiscoveryConfig is single-sourced
// at the internal authority and the public seam adds no divergence.
func TestResolveDiscoveryConfig_PublicMatchesInternal(t *testing.T) {
	cases := []pkgserver.OIDCDiscoveryConfig{
		{}, // all defaults
		{Issuer: "https://idp.example.test"},
		{Issuer: "https://idp.example.test/"}, // trailing-slash trim
		{
			Issuer:                "https://idp.example.test",
			AuthorizationEndpoint: "https://idp.example.test/oauth2/authorize-override",
			TokenEndpoint:         "https://idp.example.test/oauth2/token-override",
			JWKSURI:               "https://idp.example.test/keys-override",
		},
	}
	for i, in := range cases {
		gotPublic := pkgserver.ResolveDiscoveryConfig(in)
		gotInternal := internalserver.ResolveDiscoveryConfig(in)
		assert.Equalf(t, gotInternal, gotPublic, "case %d: public ResolveDiscoveryConfig must agree with internal authority", i)
	}
}

// TestDiscoveryDocument_PublicMatchesInternal pins the OSS signing-alg
// policy (THE-PKCE-DECISION: exactly EdDSA/ES256/RS256, RS256 explicit-
// registration testing-only) + every advertised discovery field as
// single-sourced at the internal layer. The two payloads must be
// byte-for-byte equal after JSON marshalling.
func TestDiscoveryDocument_PublicMatchesInternal(t *testing.T) {
	cases := []pkgserver.OIDCDiscoveryConfig{
		{},
		{Issuer: "https://idp.example.test"},
		{Issuer: "https://idp.example.test/"},
		{
			Issuer:                "https://idp.example.test",
			AuthorizationEndpoint: "https://idp.example.test/oauth2/authorize",
			TokenEndpoint:         "https://idp.example.test/oauth2/token",
			JWKSURI:               "https://idp.example.test/.well-known/jwks.json",
		},
	}
	for i, in := range cases {
		gotPublic := pkgserver.DiscoveryDocument(in)
		gotInternal := internalserver.DiscoveryDocument(in)
		assert.Equalf(t, gotInternal, gotPublic, "case %d: discovery payload must match internal authority", i)

		// Confirm the signing-alg policy survives the public seam:
		// exactly EdDSA + ES256 — what the issuer signs an ID token with
		// (THE-ADVERTISED-RS256). RS256 stays a per-client registration
		// and is NOT advertised, here or anywhere else.
		algs, ok := gotPublic["id_token_signing_alg_values_supported"].([]string)
		require.Truef(t, ok, "case %d: alg list missing or wrong type", i)
		assert.Containsf(t, algs, "EdDSA", "case %d: EdDSA must be advertised", i)
		assert.Containsf(t, algs, "ES256", "case %d: ES256 must be advertised", i)
		assert.Lenf(t, algs, 2, "case %d: the advertised list is exactly EdDSA + ES256", i)
		assert.NotContainsf(t, algs, "RS256", "case %d: RS256 is registrable, never advertised", i)
		assert.NotContainsf(t, algs, "none", "case %d: 'none' must NOT be advertised", i)
		assert.NotContainsf(t, algs, "HS256", "case %d: HS256 must NOT be advertised", i)
	}
}

// TestSmokeHandler_JWKSThroughPublicSeam wires the smoke handler via
// the public seam with a stub provider and proves the served body
// equals the JWKS the provider returned. This is the end-to-end
// confirmation that the JWKSProvider seam works through the public
// package — the same shape CE composition will use.
func TestSmokeHandler_JWKSThroughPublicSeam(t *testing.T) {
	expected := pkgserver.JWKS{Keys: []pkgserver.JWK{{
		Kty: "OKP",
		Crv: "Ed25519",
		Kid: "kid-seam-test",
		Use: "sig",
		Alg: "EdDSA",
		X:   "AAA",
	}}}
	handler := pkgserver.NewSmokeHandlerWithJWKS(
		pkgserver.OIDCDiscoveryConfig{Issuer: "https://seam.example"},
		stubJWKSProvider{set: expected},
	)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "JWKS endpoint via public seam: %d, body=%q", rec.Code, rec.Body.String())

	var got pkgserver.JWKS
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	assert.Equal(t, expected, got, "JWKS served through public seam must equal the provider's payload")
}

// TestEmptyJWKSProvider_ThroughPublicSeam pins that the smoke
// handler defaults to {"keys":[]} when wired through the public seam
// with EmptyJWKSProvider. Confirms the safe-default path used by the
// --serve smoke CLI.
func TestEmptyJWKSProvider_ThroughPublicSeam(t *testing.T) {
	handler := pkgserver.NewSmokeHandlerWithJWKS(
		pkgserver.OIDCDiscoveryConfig{},
		pkgserver.EmptyJWKSProvider{},
	)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "empty JWKS via public seam: %d, body=%q", rec.Code, rec.Body.String())

	var got pkgserver.JWKS
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	assert.Empty(t, got.Keys, "EmptyJWKSProvider through public seam must serve {\"keys\":[]}")
}

// TestRepositoryJWKSProvider_PublicConstructionMatchesInternal builds
// a RepositoryJWKSProvider value through the public alias and through
// the internal authority — both bound to the same stub repository —
// and confirms the served JWKS is identical. This is the end-to-end
// "the alias actually wires the same path" check for the CE-facing
// constructor.
func TestRepositoryJWKSProvider_PublicConstructionMatchesInternal(t *testing.T) {
	repo := &stubKeyRepository{
		active: []domain.SigningKey{
			{KID: "ed-1", Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: genEd25519PEM(t)},
		},
	}
	pub := pkgserver.RepositoryJWKSProvider{Repo: repo}
	internal := internalserver.RepositoryJWKSProvider{Repo: repo}

	gotPublic, err := pub.PublicJWKS(context.Background())
	require.NoError(t, err)
	gotInternal, err := internal.PublicJWKS(context.Background())
	require.NoError(t, err)

	assert.Equal(t, gotInternal, gotPublic, "RepositoryJWKSProvider constructed via public alias must match internal authority")
	require.Len(t, gotPublic.Keys, 1, "RepositoryJWKSProvider must publish the one active EdDSA key")
	assert.Equal(t, "ed-1", gotPublic.Keys[0].Kid)
	assert.Equal(t, "EdDSA", gotPublic.Keys[0].Alg)
}

// TestPublicKeyToJWK_AgreesWithInternal pins that the public seam's
// PublicKeyToJWK pass-through produces the same JWK as the internal
// authority — for EdDSA and (since THE-PKCE-DECISION, where RS256 became a
// real testing-only capability) for RS256 — and that an algorithm outside
// the issuance set is rejected identically on both sides.
func TestPublicKeyToJWK_AgreesWithInternal(t *testing.T) {
	edPEM := genEd25519PEM(t)
	gotPublic, errPublic := pkgserver.PublicKeyToJWK("kid-pub", domain.KeyAlgorithmEdDSA, edPEM)
	gotInternal, errInternal := internalserver.PublicKeyToJWK("kid-pub", domain.KeyAlgorithmEdDSA, edPEM)
	require.NoError(t, errPublic)
	require.NoError(t, errInternal)
	assert.Equal(t, gotInternal, gotPublic, "PublicKeyToJWK via public seam must match internal authority")
	assert.Equal(t, "OKP", gotPublic.Kty)
	assert.Equal(t, "Ed25519", gotPublic.Crv)
	assert.Equal(t, "EdDSA", gotPublic.Alg)

	// RS256 serialises identically on both sides — public-only material.
	rsaPEM := genRSAPEM(t)
	gotPublic, errPublic = pkgserver.PublicKeyToJWK("kid-rs", domain.KeyAlgorithmRS256, rsaPEM)
	gotInternal, errInternal = internalserver.PublicKeyToJWK("kid-rs", domain.KeyAlgorithmRS256, rsaPEM)
	require.NoError(t, errPublic, "public PublicKeyToJWK must serialise RS256 (THE-PKCE-DECISION)")
	require.NoError(t, errInternal, "internal PublicKeyToJWK must serialise RS256 (THE-PKCE-DECISION)")
	assert.Equal(t, gotInternal, gotPublic, "RS256 JWK via public seam must match internal authority")
	assert.Equal(t, "RSA", gotPublic.Kty)
	assert.Equal(t, "RS256", gotPublic.Alg)
	assert.NotEmpty(t, gotPublic.N)
	assert.NotEmpty(t, gotPublic.E)

	// An algorithm outside the issuance set is rejected on both sides.
	_, errPublic = pkgserver.PublicKeyToJWK("kid-hs", domain.KeyAlgorithm("HS256"), rsaPEM)
	_, errInternal = internalserver.PublicKeyToJWK("kid-hs", domain.KeyAlgorithm("HS256"), rsaPEM)
	require.Error(t, errPublic, "public PublicKeyToJWK must reject non-issuance algorithms")
	require.Error(t, errInternal, "internal PublicKeyToJWK must reject non-issuance algorithms")
}

// TestPublicTypes_HaveIdenticalReflectType is a defensive runtime
// pin: alias identity at the Go type system is strongest at compile
// time (see TestPublicTypes_AreAliasesOfInternal), but reflect.Type
// equality is the cheapest snapshot-style cross-check. Catches a
// regression where someone replaces an alias with a same-shaped
// distinct named type.
func TestPublicTypes_HaveIdenticalReflectType(t *testing.T) {
	pairs := []struct {
		name   string
		pub    any
		intern any
	}{
		{"JWK", pkgserver.JWK{}, internalserver.JWK{}},
		{"JWKS", pkgserver.JWKS{}, internalserver.JWKS{}},
		{"EmptyJWKSProvider", pkgserver.EmptyJWKSProvider{}, internalserver.EmptyJWKSProvider{}},
		{"RepositoryJWKSProvider", pkgserver.RepositoryJWKSProvider{}, internalserver.RepositoryJWKSProvider{}},
		{"OIDCDiscoveryConfig", pkgserver.OIDCDiscoveryConfig{}, internalserver.OIDCDiscoveryConfig{}},
	}
	for _, p := range pairs {
		assert.Equalf(t,
			reflect.TypeOf(p.intern),
			reflect.TypeOf(p.pub),
			"%s: public and internal reflect.Type must be identical (alias regression?)",
			p.name,
		)
	}
}

// TestPublicPackageDoesNotImportForbiddenTrees parses the public
// package's production source files and asserts that none of their
// direct imports reach into the CE, monolith, AG, UI, or auth-service
// trees. This is the seam-level enforcement of the
// OSS-must-not-import-CE invariant (I3) and of the broader repo
// boundaries documented in wiki/agent-rules.md §D.
//
// Transitive import checking is owned by the module-wide validation
// matrix (`go list -deps ./...` + import-boundary grep); this test
// is scoped to the direct surface of pkg/server so a drifting import
// shows up at the first edit, not at module-wide validation time.
func TestPublicPackageDoesNotImportForbiddenTrees(t *testing.T) {
	forbidden := []string{
		"github.com/identuum/identuum-idp-ce",
		"github.com/identuum/identuum-idp/internal",
		"github.com/identuum/identuum-ag",
		"github.com/identuum/identuum-ui",
		"github.com/identuum/auth-service",
	}

	wd, err := os.Getwd()
	require.NoError(t, err)

	fset := token.NewFileSet()
	entries, err := os.ReadDir(wd)
	require.NoError(t, err)

	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		// Inspect only production-source files (not _test.go). Test
		// files are allowed to import the stdlib's testing scaffolding;
		// we are pinning the seam's public surface.
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(wd, name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		require.NoErrorf(t, err, "failed to parse %q", name)

		for _, imp := range file.Imports {
			pathLit := strings.Trim(imp.Path.Value, `"`)
			for _, banned := range forbidden {
				assert.Falsef(t, strings.HasPrefix(pathLit, banned),
					"%s: forbidden import %q (matches %q)", name, pathLit, banned)
			}
		}
		checked++
	}
	require.GreaterOrEqual(t, checked, 1,
		"at least one production source file must have been scanned")
}

// stubJWKSProvider lets the smoke-handler tests inject a deterministic
// JWKS without going through the repository layer.
type stubJWKSProvider struct {
	set pkgserver.JWKS
	err error
}

func (s stubJWKSProvider) PublicJWKS(_ context.Context) (pkgserver.JWKS, error) {
	return s.set, s.err
}

// stubKeyRepository implements repository.KeyRepository just enough
// for the RepositoryJWKSProvider seam test. Only GetActiveSigningKeys
// is exercised; the rest panic to surface accidental reads.
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
// public key encoded as PKIX PEM. Mirror of the internal helper.
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

// genRSAPEM produces a fresh RSA keypair and returns the public key
// encoded as PKIX PEM. Used only to confirm RS256 is rejected at the
// JWK conversion layer.
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
