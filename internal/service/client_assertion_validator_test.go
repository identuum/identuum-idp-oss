package service

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ---------- Test fixtures ----------

func newAssertionValidator(t *testing.T) *ClientAssertionValidator {
	t.Helper()
	v, err := NewClientAssertionValidator(ClientAssertionValidatorConfig{
		TokenEndpointURL: "https://idp.test/api/v1/oauth/token",
	})
	if err != nil {
		t.Fatalf("validator init: %v", err)
	}
	return v
}

// newJWKSClient constructs a private_key_jwt-configured Client
// whose inline JWKS contains the supplied Ed25519 public key with
// the given kid.
func newJWKSClient(t *testing.T, clientID, kid string, pub ed25519.PublicKey) *domain.Client {
	t.Helper()
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
		"kid": kid,
	}
	jwksBytes, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	return &domain.Client{
		ID:                          uuid.New(),
		ClientID:                    clientID,
		Name:                        "test-jwt-client",
		IsPublic:                    false,
		ClientSecretHash:            "ignored-for-assertion-path",
		TokenEndpointAuthMethod:     "private_key_jwt",
		TokenEndpointAuthSigningAlg: "EdDSA",
		JWKS:                        string(jwksBytes),
	}
}

func signEdDSAAssertion(t *testing.T, priv ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func baseAssertionClaims(clientID, tokenEndpoint string) jwt.MapClaims {
	now := time.Now().Unix()
	return jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": tokenEndpoint,
		"exp": now + 60,
		"iat": now,
		"jti": "jti-" + uuid.NewString(),
	}
}

// ---------- Construction ----------

func TestNewClientAssertionValidator_EmptyTokenEndpointRejected(t *testing.T) {
	_, err := NewClientAssertionValidator(ClientAssertionValidatorConfig{})
	if err == nil {
		t.Errorf("empty TokenEndpointURL accepted")
	}
}

// ---------- Happy path ----------

func TestValidate_ValidEdDSAAssertionAccepted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	v := newAssertionValidator(t)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	out, err := v.Validate(context.Background(), client, signed)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if out == nil || out.JTI == "" {
		t.Errorf("missing validated jti: %+v", out)
	}
}

// ---------- alg policy ----------

func TestValidate_AlgNoneRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	v := newAssertionValidator(t)
	// Hand-craft a JWT with alg=none.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`))
	payload, _ := json.Marshal(baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token"))
	body := base64.RawURLEncoding.EncodeToString(payload)
	token := header + "." + body + "."
	_, err := v.Validate(context.Background(), client, token)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("alg=none accepted: %v", err)
	}
}

func TestValidate_AlgHS256Rejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	v := newAssertionValidator(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token"))
	tok.Header["kid"] = "k1"
	signed, _ := tok.SignedString([]byte("any-secret"))
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("HS256 accepted: %v", err)
	}
}

// ---------- iss / sub / aud ----------

func TestValidate_IssMismatchRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	v := newAssertionValidator(t)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	claims["iss"] = "imposter-iss"
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("iss mismatch accepted: %v", err)
	}
}

func TestValidate_SubMismatchRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	v := newAssertionValidator(t)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	claims["sub"] = "other"
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("sub mismatch accepted: %v", err)
	}
}

func TestValidate_AudWrongRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	v := newAssertionValidator(t)
	claims := baseAssertionClaims("cli-1", "https://wrong.example.com/token")
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("wrong aud accepted: %v", err)
	}
}

// ---------- exp / iat ----------

func TestValidate_ExpiredRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	v := newAssertionValidator(t)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	claims["exp"] = time.Now().Add(-2 * time.Minute).Unix()
	claims["iat"] = time.Now().Add(-3 * time.Minute).Unix()
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("expired assertion accepted: %v", err)
	}
}

func TestValidate_MissingJTIRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	v := newAssertionValidator(t)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	delete(claims, "jti")
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("no-jti accepted: %v", err)
	}
}

// ---------- key source ----------

func TestValidate_JWKSUriClientReturnsUnsupported(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	// Swap inline JWKS for a JWKS URI — this OSS slice doesn't
	// fetch URIs, so the validator must surface unsupported.
	client.JWKS = ""
	client.JWKSUri = "https://client.example.com/jwks.json"
	v := newAssertionValidator(t)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionUnsupported) {
		t.Errorf("err = %v, want ErrClientAssertionUnsupported", err)
	}
}

func TestValidate_WrongPublicKeyRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	imposterPub, _, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", imposterPub)
	v := newAssertionValidator(t)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("wrong-key assertion accepted: %v", err)
	}
}

// ---------- replay detection ----------

// fakeReplayDetector records mark calls so the validator tests
// can pin both the firstUse path and the replay path without
// reaching the postgres layer.
type fakeReplayDetector struct {
	marks  int
	replay bool
	err    error
}

func (f *fakeReplayDetector) Mark(_ context.Context, _, _ string, _ time.Time) (bool, error) {
	f.marks++
	if f.err != nil {
		return false, f.err
	}
	if f.replay {
		return false, nil
	}
	return true, nil
}

func TestValidate_ReplayDetectorFirstUseAccepted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	det := &fakeReplayDetector{}
	v := newAssertionValidator(t).WithReplayDetector(det)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	if _, err := v.Validate(context.Background(), client, signed); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if det.marks != 1 {
		t.Errorf("mark calls = %d", det.marks)
	}
}

func TestValidate_ReplayDetectorReplayRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	det := &fakeReplayDetector{replay: true}
	v := newAssertionValidator(t).WithReplayDetector(det)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("replay err = %v, want ErrClientAssertionInvalid", err)
	}
}

func TestValidate_ReplayDetectorErrorIsFailClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	det := &fakeReplayDetector{err: errors.New("store down")}
	v := newAssertionValidator(t).WithReplayDetector(det)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("store error: err = %v, want ErrClientAssertionInvalid (fail-closed)", err)
	}
}

func TestValidate_InvalidAssertionDoesNotPollute(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	det := &fakeReplayDetector{}
	v := newAssertionValidator(t).WithReplayDetector(det)
	// Forge claims with wrong aud — pre-replay validation must
	// reject and replay detector must NOT be called.
	bad := baseAssertionClaims("cli-1", "https://wrong.example.com/")
	signed := signEdDSAAssertion(t, priv, "k1", bad)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Fatalf("bad aud: %v", err)
	}
	if det.marks != 0 {
		t.Errorf("replay detector called on invalid assertion: marks=%d", det.marks)
	}
}

// ---------- JWKS URI fetch ----------

// fakeJWKSFetcher returns a fixed public key for any (uri, kid).
type fakeJWKSFetcher struct {
	key  ed25519.PublicKey
	err  error
	uri  string
	kid  string
	hits int
}

func (f *fakeJWKSFetcher) Fetch(_ context.Context, uri, kid string) (crypto.PublicKey, error) {
	f.uri = uri
	f.kid = kid
	f.hits++
	if f.err != nil {
		return nil, f.err
	}
	return f.key, nil
}

func TestValidate_JWKSUriUsesFetcherWhenWired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub) // inline JWKS to derive a working client
	client.JWKS = ""
	client.JWKSUri = "https://client.example.com/jwks.json"
	fetcher := &fakeJWKSFetcher{key: pub}
	v := newAssertionValidator(t).WithJWKSFetcher(fetcher)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	if _, err := v.Validate(context.Background(), client, signed); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if fetcher.hits != 1 {
		t.Errorf("fetcher hits = %d", fetcher.hits)
	}
	if fetcher.uri != client.JWKSUri || fetcher.kid != "k1" {
		t.Errorf("fetcher args = %q/%q", fetcher.uri, fetcher.kid)
	}
}

func TestValidate_JWKSUriWithoutFetcherStillUnsupported(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	client.JWKS = ""
	client.JWKSUri = "https://client.example.com/jwks.json"
	v := newAssertionValidator(t)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionUnsupported) {
		t.Errorf("err = %v, want ErrClientAssertionUnsupported", err)
	}
}

func TestValidate_JWKSUriFetcherErrorMapsToInvalid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	client.JWKS = ""
	client.JWKSUri = "https://client.example.com/jwks.json"
	fetcher := &fakeJWKSFetcher{err: errors.New("network down")}
	v := newAssertionValidator(t).WithJWKSFetcher(fetcher)
	claims := baseAssertionClaims("cli-1", "https://idp.test/api/v1/oauth/token")
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	if !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("err = %v", err)
	}
}

// ---------- raw-token leak guard ----------

func TestValidate_ErrorPathDoesNotLeakAssertion(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	v := newAssertionValidator(t)
	const banner = "MUST-NOT-LEAK-RAW-ASSERTION"
	_, err := v.Validate(context.Background(), client, banner)
	if err == nil {
		t.Errorf("malformed assertion accepted")
	}
	// The sentinel error must NOT contain the raw assertion text.
	if errMsg := err.Error(); errMsg == "" || errMsg == banner {
		t.Errorf("error message leaked raw token: %q", errMsg)
	}
}
