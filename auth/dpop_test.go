package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mintDPoPProof builds a valid DPoP proof JWS for testing. Mirrors what a
// real DPoP client would produce: typ=dpop+jwt, jwk header, claims for htm,
// htu, iat, jti, ath. Signing key passed in so tests can deliberately mint
// proofs with keys that do NOT match the expected jkt (rejection test).
func mintDPoPProof(
	t *testing.T,
	priv interface{},
	jwk map[string]interface{},
	alg, method, uri, bearer string,
	iat time.Time,
	jti string,
) string {
	t.Helper()

	// ath — base64url(sha256(bearer)) per RFC 9449 §4.2
	ath := base64.RawURLEncoding.EncodeToString(sha256Sum(bearer))

	claims := jwt.MapClaims{
		"htm": method,
		"htu": uri,
		"iat": iat.Unix(),
		"jti": jti,
		"ath": ath,
	}

	var signingMethod jwt.SigningMethod
	switch alg {
	case "EdDSA":
		signingMethod = jwt.SigningMethodEdDSA
	case "ES256":
		signingMethod = jwt.SigningMethodES256
	default:
		t.Fatalf("unsupported alg for test: %s", alg)
	}

	tok := jwt.NewWithClaims(signingMethod, claims)
	tok.Header["typ"] = dpopJWTTyp
	tok.Header["jwk"] = jwk

	signed, err := tok.SignedString(priv)
	require.NoError(t, err)
	return signed
}

// ed25519TestKey returns a fresh Ed25519 keypair + its JWK representation.
func ed25519TestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, map[string]interface{}) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	xStr := base64.RawURLEncoding.EncodeToString(pub)
	jwk := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   xStr,
	}
	return pub, priv, jwk
}

// es256TestKey returns a fresh P-256 keypair + its JWK representation.
func es256TestKey(t *testing.T) (*ecdsa.PrivateKey, map[string]interface{}) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Pad to the full curve field size — some implementations (including
	// ours) reject coordinates whose base64 decodes to fewer than 32 bytes.
	size := (priv.Curve.Params().BitSize + 7) / 8
	xBytes := make([]byte, size)
	priv.X.FillBytes(xBytes)
	yBytes := make([]byte, size)
	priv.Y.FillBytes(yBytes)
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}
	return priv, jwk
}

func TestVerifyDPoPProof_EdDSA_HappyPath(t *testing.T) {
	_, priv, jwk := ed25519TestKey(t)
	now := time.Now()
	bearer := "cap-" + uuid.NewString()
	proof := mintDPoPProof(t, priv, jwk, "EdDSA", "POST",
		"https://auth.example.com/api/v1/agent/feedback/0193abcd-1234",
		bearer, now, uuid.NewString())

	claims, err := VerifyDPoPProof(proof, "POST",
		"https://auth.example.com/api/v1/agent/feedback/0193abcd-1234",
		bearer, now)
	require.NoError(t, err)
	assert.Equal(t, "POST", claims.HTM)
	assert.NotEmpty(t, claims.JTI)
	assert.NotEmpty(t, claims.JKT, "jkt thumbprint must be computed")
}

func TestVerifyDPoPProof_ES256_HappyPath(t *testing.T) {
	priv, jwk := es256TestKey(t)
	now := time.Now()
	bearer := "cap-" + uuid.NewString()
	proof := mintDPoPProof(t, priv, jwk, "ES256", "POST",
		"https://auth.example.com/api/v1/agent/feedback/abc",
		bearer, now, uuid.NewString())

	claims, err := VerifyDPoPProof(proof, "POST",
		"https://auth.example.com/api/v1/agent/feedback/abc",
		bearer, now)
	require.NoError(t, err)
	assert.NotEmpty(t, claims.JKT)
}

func TestVerifyDPoPProof_HTM_Mismatch_Rejected(t *testing.T) {
	_, priv, jwk := ed25519TestKey(t)
	now := time.Now()
	bearer := "cap-x"
	proof := mintDPoPProof(t, priv, jwk, "EdDSA", "POST",
		"https://a/b", bearer, now, uuid.NewString())

	// Request method differs.
	_, err := VerifyDPoPProof(proof, "PUT", "https://a/b", bearer, now)
	require.ErrorIs(t, err, ErrDPoPInvalid)
}

func TestVerifyDPoPProof_HTU_Mismatch_Rejected(t *testing.T) {
	_, priv, jwk := ed25519TestKey(t)
	now := time.Now()
	bearer := "cap-x"
	proof := mintDPoPProof(t, priv, jwk, "EdDSA", "POST",
		"https://a/b", bearer, now, uuid.NewString())

	// Request URI differs (e.g. attacker tries to replay against a different path).
	_, err := VerifyDPoPProof(proof, "POST", "https://a/c", bearer, now)
	require.ErrorIs(t, err, ErrDPoPInvalid)
}

func TestVerifyDPoPProof_ATH_Mismatch_Rejected(t *testing.T) {
	_, priv, jwk := ed25519TestKey(t)
	now := time.Now()
	proof := mintDPoPProof(t, priv, jwk, "EdDSA", "POST",
		"https://a/b", "bearer-A", now, uuid.NewString())

	// Different bearer than the proof was minted for.
	_, err := VerifyDPoPProof(proof, "POST", "https://a/b", "bearer-B", now)
	require.ErrorIs(t, err, ErrDPoPInvalid)
}

func TestVerifyDPoPProof_StaleIAT_Rejected(t *testing.T) {
	_, priv, jwk := ed25519TestKey(t)
	issued := time.Now().Add(-5 * time.Minute) // well outside skew
	bearer := "cap-x"
	proof := mintDPoPProof(t, priv, jwk, "EdDSA", "POST",
		"https://a/b", bearer, issued, uuid.NewString())

	_, err := VerifyDPoPProof(proof, "POST", "https://a/b", bearer, time.Now())
	require.ErrorIs(t, err, ErrDPoPInvalid)
}

func TestVerifyDPoPProof_FutureIAT_Rejected(t *testing.T) {
	_, priv, jwk := ed25519TestKey(t)
	// Pre-minted proof scheduled for 5 minutes in the future — defends against
	// skewed clocks used to mint "valid tomorrow" proofs today.
	issued := time.Now().Add(5 * time.Minute)
	bearer := "cap-x"
	proof := mintDPoPProof(t, priv, jwk, "EdDSA", "POST",
		"https://a/b", bearer, issued, uuid.NewString())

	_, err := VerifyDPoPProof(proof, "POST", "https://a/b", bearer, time.Now())
	require.ErrorIs(t, err, ErrDPoPInvalid)
}

func TestVerifyDPoPProof_WrongSigningKey_Rejected(t *testing.T) {
	// Advertise jwk A, sign with key B — the kind of forgery DPoP's
	// signature verification exists to catch.
	pubA, _, jwkA := ed25519TestKey(t)
	_ = pubA
	_, privB, _ := ed25519TestKey(t)

	now := time.Now()
	bearer := "cap-x"
	proof := mintDPoPProof(t, privB, jwkA, "EdDSA", "POST",
		"https://a/b", bearer, now, uuid.NewString())

	_, err := VerifyDPoPProof(proof, "POST", "https://a/b", bearer, now)
	require.ErrorIs(t, err, ErrDPoPInvalid)
}

func TestVerifyDPoPProof_ForbiddenAlg_Rejected(t *testing.T) {
	// HS256 uses a symmetric secret — forbidden. Trying to present such a
	// proof must fail at alg-gate before any signature work.
	claims := jwt.MapClaims{
		"htm": "POST",
		"htu": "https://a/b",
		"iat": time.Now().Unix(),
		"jti": uuid.NewString(),
		"ath": base64.RawURLEncoding.EncodeToString(sha256Sum("bearer")),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["typ"] = dpopJWTTyp
	tok.Header["jwk"] = map[string]interface{}{"kty": "oct"}
	signed, err := tok.SignedString([]byte("secret"))
	require.NoError(t, err)

	_, err = VerifyDPoPProof(signed, "POST", "https://a/b", "bearer", time.Now())
	require.ErrorIs(t, err, ErrDPoPInvalid)
}

func TestVerifyDPoPProof_WrongTyp_Rejected(t *testing.T) {
	// A regular JWT (typ=JWT) being replayed as a DPoP proof — the typ gate
	// must refuse it so DPoP proofs cannot be forged from random access tokens.
	_, priv, jwk := ed25519TestKey(t)
	claims := jwt.MapClaims{
		"htm": "POST", "htu": "https://a/b",
		"iat": time.Now().Unix(),
		"jti": uuid.NewString(),
		"ath": base64.RawURLEncoding.EncodeToString(sha256Sum("bearer")),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	// Intentionally omit the typ header — defaults to "JWT" per golang-jwt.
	tok.Header["jwk"] = jwk
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)

	_, err = VerifyDPoPProof(signed, "POST", "https://a/b", "bearer", time.Now())
	require.ErrorIs(t, err, ErrDPoPInvalid)
}

func TestVerifyDPoPProof_MissingJTI_Rejected(t *testing.T) {
	_, priv, jwk := ed25519TestKey(t)
	now := time.Now()
	bearer := "cap-x"

	claims := jwt.MapClaims{
		"htm": "POST", "htu": "https://a/b",
		"iat": now.Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(sha256Sum(bearer)),
		// jti intentionally omitted
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["typ"] = dpopJWTTyp
	tok.Header["jwk"] = jwk
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)

	_, err = VerifyDPoPProof(signed, "POST", "https://a/b", bearer, now)
	require.ErrorIs(t, err, ErrDPoPInvalid)
}

// The jkt returned by VerifyDPoPProof must match the canonical RFC 7638
// thumbprint of the presenter's public key. Computing it two ways and
// asserting equality catches drift in the canonical-JSON construction.
func TestVerifyDPoPProof_JKT_MatchesRFC7638(t *testing.T) {
	pub, priv, jwk := ed25519TestKey(t)
	now := time.Now()
	bearer := "cap-x"
	proof := mintDPoPProof(t, priv, jwk, "EdDSA", "POST",
		"https://a/b", bearer, now, uuid.NewString())

	claims, err := VerifyDPoPProof(proof, "POST", "https://a/b", bearer, now)
	require.NoError(t, err)

	// Independent computation: marshal the canonical JWK via json.Marshal
	// on a struct with sorted fields and hash. Matches the RFC 7638 recipe.
	canonical := struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
	}{
		Crv: "Ed25519",
		Kty: "OKP",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
	marshalled, err := json.Marshal(canonical)
	require.NoError(t, err)
	expected := base64.RawURLEncoding.EncodeToString(sha256Sum(string(marshalled)))

	assert.Equal(t, expected, claims.JKT,
		"jkt must match RFC 7638 canonical SHA-256 thumbprint")
}
