package service

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const dpopTestHTU = "https://idp.test/api/v1/oauth/token"

var dpopTestNow = time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)

// dpopTestKey is a proof key with its public JWK and RFC 7638 thumbprint.
type dpopTestKey struct {
	priv   any
	method jwt.SigningMethod
	jwk    map[string]any
	jkt    string
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newEdDSAProofKey(t *testing.T) dpopTestKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64u(pub)}
	jkt, err := JWKThumbprint(jwk)
	require.NoError(t, err)
	return dpopTestKey{priv: priv, method: jwt.SigningMethodEdDSA, jwk: jwk, jkt: jkt}
}

func newES256ProofKey(t *testing.T) dpopTestKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Uncompressed point: 0x04 || X (32) || Y (32).
	point, err := priv.PublicKey.Bytes()
	require.NoError(t, err)
	require.Len(t, point, 65)
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "x": b64u(point[1:33]), "y": b64u(point[33:65])}
	jkt, err := JWKThumbprint(jwk)
	require.NoError(t, err)
	return dpopTestKey{priv: priv, method: jwt.SigningMethodES256, jwk: jwk, jkt: jkt}
}

func newRS256ProofKey(t *testing.T) dpopTestKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	e := []byte{1, 0, 1}
	jwk := map[string]any{"kty": "RSA", "n": b64u(priv.PublicKey.N.Bytes()), "e": b64u(e)}
	jkt, err := JWKThumbprint(jwk)
	require.NoError(t, err)
	return dpopTestKey{priv: priv, method: jwt.SigningMethodRS256, jwk: jwk, jkt: jkt}
}

// mintProof builds a token-endpoint DPoP proof; mutate lets a test bend the
// header or the claims before signing.
func mintProof(t *testing.T, k dpopTestKey, htm, htu string, iat time.Time, mutate func(hdr map[string]any, claims jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{"htm": htm, "htu": htu, "iat": iat.Unix(), "jti": uuid.NewString()}
	tok := jwt.NewWithClaims(k.method, claims)
	tok.Header["typ"] = dpopProofTyp
	tok.Header["jwk"] = k.jwk
	if mutate != nil {
		mutate(tok.Header, claims)
	}
	s, err := tok.SignedString(k.priv)
	require.NoError(t, err)
	return s
}

func TestJWKThumbprint_RFC7638Vector(t *testing.T) {
	// RFC 7638 §3.1 example key.
	jwk := map[string]any{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29",
	}
	jkt, err := JWKThumbprint(jwk)
	require.NoError(t, err)
	assert.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", jkt, "alg/kid are not thumbprint members; order is canonical")

	_, err = JWKThumbprint(map[string]any{"kty": "oct", "k": "x"})
	assert.Error(t, err, "symmetric keys have no place here")
	_, err = JWKThumbprint(map[string]any{"kty": "RSA", "n": "x"})
	assert.Error(t, err, "missing member")
}

func TestVerifyDPoPTokenEndpointProof_AcceptsEveryAsymmetricFamily(t *testing.T) {
	for name, k := range map[string]dpopTestKey{"EdDSA": newEdDSAProofKey(t), "ES256": newES256ProofKey(t), "RS256": newRS256ProofKey(t)} {
		t.Run(name, func(t *testing.T) {
			proof := mintProof(t, k, "POST", dpopTestHTU, dpopTestNow, nil)
			got, err := VerifyDPoPTokenEndpointProof(proof, "POST", dpopTestHTU, dpopTestNow)
			require.NoError(t, err)
			assert.Equal(t, k.jkt, got.JKT)
			assert.Equal(t, "POST", got.HTM)
			assert.Equal(t, dpopTestHTU, got.HTU)
			assert.NotEmpty(t, got.JTI)
		})
	}
}

func TestVerifyDPoPTokenEndpointProof_NormalizesHTU(t *testing.T) {
	k := newEdDSAProofKey(t)
	proof := mintProof(t, k, "post", "HTTPS://IDP.test:443/api/v1/oauth/token?x=1#frag", dpopTestNow, nil)
	got, err := VerifyDPoPTokenEndpointProof(proof, "POST", dpopTestHTU, dpopTestNow)
	require.Error(t, err, "htm is compared exactly (POST)")
	_ = got
	proof = mintProof(t, k, "POST", "HTTPS://IDP.test:443/api/v1/oauth/token?x=1#frag", dpopTestNow, nil)
	got, err = VerifyDPoPTokenEndpointProof(proof, "POST", dpopTestHTU, dpopTestNow)
	require.NoError(t, err, "scheme/host case, default port, query and fragment are normalized away")
	assert.Equal(t, dpopTestHTU, got.HTU)
}

func TestVerifyDPoPTokenEndpointProof_Refusals(t *testing.T) {
	k := newEdDSAProofKey(t)
	other := newEdDSAProofKey(t)
	cases := map[string]struct {
		proof string
		want  error
	}{
		"empty":       {"", ErrDPoPProofRequired},
		"garbage":     {"not.a.jwt", ErrDPoPProofInvalid},
		"wrong typ":   {mintProof(t, k, "POST", dpopTestHTU, dpopTestNow, func(h map[string]any, _ jwt.MapClaims) { h["typ"] = "JWT" }), ErrDPoPProofInvalid},
		"missing jwk": {mintProof(t, k, "POST", dpopTestHTU, dpopTestNow, func(h map[string]any, _ jwt.MapClaims) { delete(h, "jwk") }), ErrDPoPProofInvalid},
		"private key leak": {mintProof(t, k, "POST", dpopTestHTU, dpopTestNow, func(h map[string]any, _ jwt.MapClaims) {
			j := map[string]any{}
			for kk, v := range k.jwk {
				j[kk] = v
			}
			j["d"] = "AA"
			h["jwk"] = j
		}), ErrDPoPProofInvalid},
		"foreign jwk (signature mismatch)": {mintProof(t, k, "POST", dpopTestHTU, dpopTestNow, func(h map[string]any, _ jwt.MapClaims) { h["jwk"] = other.jwk }), ErrDPoPProofInvalid},
		"htm mismatch":                     {mintProof(t, k, "GET", dpopTestHTU, dpopTestNow, nil), ErrDPoPProofInvalid},
		"htu other path":                   {mintProof(t, k, "POST", "https://idp.test/api/v1/oauth/introspection", dpopTestNow, nil), ErrDPoPProofInvalid},
		"htu other host":                   {mintProof(t, k, "POST", "https://evil.test/api/v1/oauth/token", dpopTestNow, nil), ErrDPoPProofInvalid},
		"iat too old":                      {mintProof(t, k, "POST", dpopTestHTU, dpopTestNow.Add(-2*time.Minute), nil), ErrDPoPProofInvalid},
		"iat in future":                    {mintProof(t, k, "POST", dpopTestHTU, dpopTestNow.Add(2*time.Minute), nil), ErrDPoPProofInvalid},
		"missing jti":                      {mintProof(t, k, "POST", dpopTestHTU, dpopTestNow, func(_ map[string]any, c jwt.MapClaims) { delete(c, "jti") }), ErrDPoPProofInvalid},
		"ath present":                      {mintProof(t, k, "POST", dpopTestHTU, dpopTestNow, func(_ map[string]any, c jwt.MapClaims) { c["ath"] = "x" }), ErrDPoPProofInvalid},
		"nonce present":                    {mintProof(t, k, "POST", dpopTestHTU, dpopTestNow, func(_ map[string]any, c jwt.MapClaims) { c["nonce"] = "x" }), ErrDPoPProofInvalid},
		"unknown claim":                    {mintProof(t, k, "POST", dpopTestHTU, dpopTestNow, func(_ map[string]any, c jwt.MapClaims) { c["scope"] = "x" }), ErrDPoPProofInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyDPoPTokenEndpointProof(tc.proof, "POST", dpopTestHTU, dpopTestNow)
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("alg none and symmetric are refused", func(t *testing.T) {
		claims := jwt.MapClaims{"htm": "POST", "htu": dpopTestHTU, "iat": dpopTestNow.Unix(), "jti": "j1"}
		none := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		none.Header["typ"] = dpopProofTyp
		none.Header["jwk"] = k.jwk
		s, err := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)
		_, err = VerifyDPoPTokenEndpointProof(s, "POST", dpopTestHTU, dpopTestNow)
		assert.ErrorIs(t, err, ErrDPoPProofInvalid)

		hs := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		hs.Header["typ"] = dpopProofTyp
		hs.Header["jwk"] = k.jwk
		s, err = hs.SignedString([]byte("shared"))
		require.NoError(t, err)
		_, err = VerifyDPoPTokenEndpointProof(s, "POST", dpopTestHTU, dpopTestNow)
		assert.ErrorIs(t, err, ErrDPoPProofInvalid)
	})
}

func TestDPoPThumbprintMatches(t *testing.T) {
	assert.True(t, DPoPThumbprintMatches("abc", "abc"))
	assert.False(t, DPoPThumbprintMatches("abc", "abd"))
	assert.False(t, DPoPThumbprintMatches("", ""))
	assert.False(t, DPoPThumbprintMatches("abc", ""))
}
