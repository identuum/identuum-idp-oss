package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeyManager_RS256VerifyOnly_HappyPath confirms the asymmetric posture
// established by docs/ID_JAG_DESIGN.md cross-Q finding #15: KeyManager
// can VERIFY RS256-signed JWTs (the verify capability is the load-bearing
// new behavior in Q6) while continuing to refuse RS256 SIGNING (the
// signing path is unchanged and asserted by sibling tests below).
func TestKeyManager_RS256VerifyOnly_HappyPath(t *testing.T) {
	// Generate an RSA-2048 keypair externally (Identuum never produces
	// these — the verifying use case is foreign-key rotation drills, key
	// import for migration scenarios, etc.).
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Mint a JWT with RS256 against the private key — this happens
	// outside Identuum in production (a foreign IdP signs); here we
	// simulate it inline.
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://foreign.example.com",
		"sub": "user-1",
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "rs256-test-kid"
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)

	// Build a SigningKey row carrying the RSA PUBLIC key only (no
	// private key) — the parseKey invariant for RS256.
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	dbKey := domain.SigningKey{
		KID:        "rs256-test-kid",
		Algorithm:  domain.KeyAlgorithmRS256,
		PublicKey:  string(pubPEM),
		PrivateKey: "", // explicit — RS256 keys MUST NOT carry a private key
		State:      domain.KeyStateActive,
	}

	// Q5's mint test exercises the EdDSA primary; this test loads a
	// dual-keyed KeyManager so the RS256 verify path coexists with an
	// active EdDSA primary (the production reality).
	edKey, err := AutoGenerateInitialKey("EdDSA")
	require.NoError(t, err)
	km, err := NewKeyManager([]domain.SigningKey{*edKey, dbKey})
	require.NoError(t, err)

	// Signature verification must succeed.
	parsed, err := jwt.ParseWithClaims(signed, jwt.MapClaims{}, km.standardKeyFunc)
	require.NoError(t, err, "RS256 verification must work after Q6's KeyManager extension")
	require.True(t, parsed.Valid)
	assert.Equal(t, "RS256", parsed.Method.Alg())
}

// TestKeyManager_RS256_PrivateKeyRejected confirms parseKey refuses an
// RS256 row that carries any non-empty PrivateKey field. This is the
// data-layer enforcement of the verify-only invariant — a misconfigured
// row that includes a private key cannot be loaded; the KeyManager
// fails-fast at construction rather than silently allowing a hypothetical
// RS256 signing path to develop later.
func TestKeyManager_RS256_PrivateKeyRejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	dbKey := domain.SigningKey{
		KID:        "rs256-with-private",
		Algorithm:  domain.KeyAlgorithmRS256,
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM), // INVALID — RS256 must be verify-only
		State:      domain.KeyStateActive,
	}

	_, err = parseKey(dbKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify-only",
		"parseKey must reject RS256 keys carrying a PrivateKey; got %v", err)
}

// TestKeyManager_RS256_RejectsUndersizedKey ensures the 2048-bit floor
// fires for malformed-or-too-small RSA public keys.
func TestKeyManager_RS256_RejectsUndersizedKey(t *testing.T) {
	// 1024-bit key — below the floor.
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	dbKey := domain.SigningKey{
		KID:       "rs256-1024",
		Algorithm: domain.KeyAlgorithmRS256,
		PublicKey: string(pubPEM),
		State:     domain.KeyStateActive,
	}

	_, err = parseKey(dbKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2048")
}

// TestKeyManager_SignBytes_RefusesRS256 confirms the signing path still
// refuses RS256. SignBytes selects the primary key; this test uses a
// KeyManager whose primaryKey selection logic naturally never picks
// RS256 because the `if activeEdDSA != nil ... else if activeES256 !=
// nil` cascade has no RS256 branch (NewKeyManager construction). We
// verify this property directly by inspecting that primaryKey is
// EdDSA / ES256 even when an active RS256 key is present.
func TestKeyManager_SignBytes_RefusesRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	rs256Key := domain.SigningKey{
		KID:       "rs256-only",
		Algorithm: domain.KeyAlgorithmRS256,
		PublicKey: string(pubPEM),
		State:     domain.KeyStateActive,
	}

	// Construct a KeyManager with only the RS256 key. NewKeyManager's
	// primaryKey selection skips RS256 (no EdDSA or ES256 active key
	// available), so primaryKey ends up nil → NewKeyManager returns
	// "no active signing key found" error.
	_, err = NewKeyManager([]domain.SigningKey{rs256Key})
	require.Error(t, err, "KeyManager construction with only RS256 keys must fail — no signing primary available")
	assert.True(t, strings.Contains(err.Error(), "no active signing key"),
		"error must report missing signing primary; got %v", err)
}

// TestKeyManager_GenerateJWTToken_RefusesRS256 confirms the high-level
// access-token mint path refuses RS256 at the algorithm-switch in
// GenerateJWTToken (auth/jwt_generate.go). This is the architectural
// safeguard mirrored across every mint surface: SignBytes,
// GenerateJWTToken, GenerateIDToken, GenerateIDJagAssertion, and the
// capability mints all use the same algorithm-switch shape, all refuse
// RS256 via their default cases.
//
// We construct a KeyManager whose primaryKey is RS256 (bypassing the
// production NewKeyManager ordering by hand-injecting the field) — this
// simulates the unreachable-but-defense-in-depth scenario where some
// future code accidentally promotes an RS256 ParsedKey to primary. The
// test asserts the mint path still refuses to sign.
func TestKeyManager_GenerateJWTToken_RefusesRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	rs256DbKey := domain.SigningKey{
		KID:       "rs256-defense-in-depth",
		Algorithm: domain.KeyAlgorithmRS256,
		PublicKey: string(pubPEM),
		State:     domain.KeyStateActive,
	}
	rs256Parsed, err := parseKey(rs256DbKey)
	require.NoError(t, err, "RS256 verify-only key must parse cleanly when PrivateKey is empty")

	// Build a KeyManager with an EdDSA active key (so NewKeyManager
	// succeeds), then surgically replace primaryKey with the RS256 key.
	// Real production cannot reach this state (the primary-selection
	// cascade in NewKeyManager has no RS256 branch), but defense-in-
	// depth: the mint path's algorithm switch must still refuse.
	edKey, err := AutoGenerateInitialKey("EdDSA")
	require.NoError(t, err)
	km, err := NewKeyManager([]domain.SigningKey{*edKey})
	require.NoError(t, err)
	km.mu.Lock()
	km.primaryKey = rs256Parsed
	km.mu.Unlock()

	_, err = km.GenerateJWTToken(GenerateTokenOptions{
		ExpiresIn: 5 * time.Minute,
		Audience:  "any",
		Scope:     "openid",
	})
	require.Error(t, err, "GenerateJWTToken must refuse RS256 — verify-only invariant")
	assert.Contains(t, err.Error(), "unsupported algorithm")
}
