package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// seedActiveEdDSAKey inserts an active EdDSA signing key carrying pubPEM
// under kid and returns the private key so the test can mint tokens the
// runtime's verifier will accept by signature.
func seedActiveEdDSAKey(t *testing.T, dbURL, kid string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	pool, err := postgres.NewPool(context.Background(), dbURL, nil)
	if err != nil {
		t.Fatalf("seed pool: %v", err)
	}
	defer pool.Close()
	// P3-5: seeding a signing key requires a real cipher (throwaway 32-byte
	// hex key) so CreateSigningKey encrypts the private material at rest.
	seedCipher, err := crypto.NewCryptoService("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatalf("seed cipher: %v", err)
	}
	repos := postgres.NewPgxRepositories(pool, seedCipher)
	if err := repos.Key.CreateSigningKey(context.Background(), &domain.SigningKey{
		ID:        uuid.New(),
		KID:       kid,
		Algorithm: domain.KeyAlgorithmEdDSA,
		PublicKey: pubPEM,
		State:     domain.KeyStateActive,
	}); err != nil {
		t.Fatalf("create signing key: %v", err)
	}
	return priv
}

func signBearer(t *testing.T, priv ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// TestBuildDeps_EmptyIssuer_ConfinesToResolvedAnchor is the P2-5 teeth
// test at the RUNTIME WIRING level. With IDENTUUM_IDP_ISSUER empty, the
// verifier the runtime builds MUST confine iss/aud to the resolved anchor
// (http://localhost) — so a validly-signed token whose aud is a
// downstream resource is REJECTED, while a legitimate self-issued token
// (aud = resolved anchor) is ACCEPTED.
//
// TEETH: revert the wiring to ExpectedIssuer/ExpectedAudience: r.cfg.Issuer
// and the wrong-aud token is ACCEPTED → this test fails.
func TestBuildDeps_EmptyIssuer_ConfinesToResolvedAnchor(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	// Unique kid per run — the shared test DB's signing_keys table is not
	// truncated between runs, so a fixed kid would collide.
	kid := "p2-5-test-" + uuid.NewString()
	priv := seedActiveEdDSAKey(t, dbURL, kid)

	var stderr bytes.Buffer
	rt, err := New(Config{
		Addr:      "127.0.0.1:0",
		Issuer:    "", // EMPTY — the crux
		JWKSDBURL: dbURL,
		DataDir:   t.TempDir(),
		Stdout:    &bytes.Buffer{},
		Stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	deps, pool, _, _, _, _, _, _, _, _, _, _, err := rt.buildDeps(context.Background(), lifecycle.NewStartupReport())
	if err != nil {
		t.Fatalf("buildDeps: %v", err)
	}
	defer pool.Close()
	if deps.TokenVerifier == nil {
		t.Fatal("runtime did not wire a bearer TokenVerifier")
	}

	const resolved = "http://localhost"
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour))
	sub := uuid.NewString()

	// Legitimate self-issued token: aud == resolved anchor → ACCEPTED.
	legit := signBearer(t, priv, kid, jwt.MapClaims{
		"iss": resolved, "aud": resolved, "sub": sub, "exp": exp,
	})
	if _, err := deps.TokenVerifier.VerifyBearerToken(context.Background(), legit); err != nil {
		t.Fatalf("legitimate self-issued token (aud=%s) must be ACCEPTED with an empty configured issuer; got %v", resolved, err)
	}

	// Wrong-audience token: valid signature + correct iss, but aud is a
	// downstream api_resource → must be REJECTED (confinement active).
	wrongAud := signBearer(t, priv, kid, jwt.MapClaims{
		"iss": resolved, "aud": "https://api.downstream.example", "sub": sub, "exp": exp,
	})
	if _, err := deps.TokenVerifier.VerifyBearerToken(context.Background(), wrongAud); err == nil {
		t.Fatal("token minted for a downstream audience was ACCEPTED at the IdP bearer surface — issuer/audience confinement is DISABLED (P2-5 regression)")
	}

	// The empty-issuer startup warning must have fired.
	if !strings.Contains(stderr.String(), "IDENTUUM_IDP_ISSUER is unset") {
		t.Errorf("expected the loud empty-issuer warning on Stderr; got: %q", stderr.String())
	}
}
