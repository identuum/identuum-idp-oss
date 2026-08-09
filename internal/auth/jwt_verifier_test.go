package auth

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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// stubKeyRepo implements just the subset of repository.KeyRepository
// the verifier consumes. Other methods panic — drift surfaces as
// test failure.
type stubKeyRepo struct {
	keys []domain.SigningKey
	err  error
}

func (s *stubKeyRepo) GetActiveSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	return s.keys, s.err
}
func (s *stubKeyRepo) GetAllSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	panic("not used")
}
func (s *stubKeyRepo) GetSigningKeyByKID(_ context.Context, _ string) (*domain.SigningKey, error) {
	panic("not used")
}
func (s *stubKeyRepo) CreateSigningKey(_ context.Context, _ *domain.SigningKey) error {
	panic("not used")
}
func (s *stubKeyRepo) ActivateSigningKey(_ context.Context, _ string) error { panic("not used") }
func (s *stubKeyRepo) RotateSigningKey(_ context.Context, _, _ string, _ *time.Time) error {
	panic("not used")
}
func (s *stubKeyRepo) DeprecateSigningKey(_ context.Context, _ string, _ time.Time) error {
	panic("not used")
}
func (s *stubKeyRepo) DeleteExpiredKeys(_ context.Context) (int, error) { panic("not used") }

func ed25519Pair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return pub, priv, string(pemBytes)
}

func p256Pair(t *testing.T) (*ecdsa.PublicKey, *ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &priv.PublicKey, priv, string(pemBytes)
}

func rsaPair(t *testing.T) (*rsa.PublicKey, *rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &priv.PublicKey, priv, string(pemBytes)
}

// signEdDSA returns a fresh signed JWT using priv with the given kid
// and claims. Tests build the token + verify against a verifier
// wired to a repository carrying the matching public PEM.
func signEdDSA(t *testing.T, priv ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString(EdDSA): %v", err)
	}
	return s
}

func signES256(t *testing.T, priv *ecdsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString(ES256): %v", err)
	}
	return s
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString(RS256): %v", err)
	}
	return s
}

func TestVerifyBearerToken_EdDSAHappyPath(t *testing.T) {
	_, priv, pubPEM := ed25519Pair(t)
	const kid = "ed-1"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{})

	userID := uuid.New()
	tok := signEdDSA(t, priv, kid, jwt.MapClaims{
		"sub":   userID.String(),
		"email": "admin@example.test",
		"role":  "site_admin",
		"scope": "keys:read",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	p, err := v.VerifyBearerToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyBearerToken error: %v", err)
	}
	if p.UserID != userID {
		t.Errorf("UserID = %v, want %v", p.UserID, userID)
	}
	if p.Role != domain.RoleSiteAdmin {
		t.Errorf("Role = %q, want site_admin", p.Role)
	}
	if p.Email != "admin@example.test" {
		t.Errorf("Email = %q", p.Email)
	}
	if p.Scope != "keys:read" {
		t.Errorf("Scope = %q", p.Scope)
	}
}

func TestVerifyBearerToken_ES256HappyPath(t *testing.T) {
	_, priv, pubPEM := p256Pair(t)
	const kid = "es-1"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmES256, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{})

	tok := signES256(t, priv, kid, jwt.MapClaims{
		"sub":  uuid.New().String(),
		"role": "site_admin",
		"exp":  time.Now().Add(5 * time.Minute).Unix(),
	})
	if _, err := v.VerifyBearerToken(context.Background(), tok); err != nil {
		t.Fatalf("ES256 verification failed: %v", err)
	}
}

func TestVerifyBearerToken_RejectsRS256(t *testing.T) {
	// Even if an RS256 row sneaks into active keys (verify-only
	// keys exist in domain.KeyAlgorithmRS256), the verifier filters
	// it out — every RS256 token therefore fails.
	_, rsaPriv, rsaPEM := rsaPair(t)
	const kid = "rsa-1"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmRS256, PublicKey: rsaPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{})

	tok := signRS256(t, rsaPriv, kid, jwt.MapClaims{
		"sub": uuid.New().String(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	_, err := v.VerifyBearerToken(context.Background(), tok)
	if !errors.Is(err, errTokenInvalid) {
		t.Errorf("RS256 verification: err = %v, want errTokenInvalid", err)
	}
}

func TestVerifyBearerToken_RejectsAlgNone(t *testing.T) {
	_, priv, pubPEM := ed25519Pair(t)
	const kid = "ed-1"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{})

	// Build a token signed with a real key but then swap the alg
	// header on the wire. golang-jwt's WithValidMethods should
	// catch this; the test confirms the rejection.
	good := signEdDSA(t, priv, kid, jwt.MapClaims{
		"sub": uuid.New().String(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	// A bare "alg=none" token is constructed manually below — the
	// jwt-v5 SigningMethodNone is opt-in and rare. We just assert
	// the manual alg-rewrite is rejected.
	tampered := alterAlgToNone(t, good)
	if _, err := v.VerifyBearerToken(context.Background(), tampered); !errors.Is(err, errTokenInvalid) {
		t.Errorf("alg=none accepted; err = %v", err)
	}
}

func TestVerifyBearerToken_UnknownKidRejected(t *testing.T) {
	_, priv, pubPEM := ed25519Pair(t)
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: "ed-1", Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{})

	tok := signEdDSA(t, priv, "ed-NOT-IN-REPO", jwt.MapClaims{
		"sub": uuid.New().String(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := v.VerifyBearerToken(context.Background(), tok); !errors.Is(err, errTokenInvalid) {
		t.Errorf("unknown kid accepted; err = %v", err)
	}
}

func TestVerifyBearerToken_ExpiredRejected(t *testing.T) {
	_, priv, pubPEM := ed25519Pair(t)
	const kid = "ed-1"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{})

	tok := signEdDSA(t, priv, kid, jwt.MapClaims{
		"sub": uuid.New().String(),
		"exp": time.Now().Add(-time.Minute).Unix(),
		"iat": time.Now().Add(-time.Hour).Unix(),
	})
	if _, err := v.VerifyBearerToken(context.Background(), tok); !errors.Is(err, errTokenInvalid) {
		t.Errorf("expired token accepted; err = %v", err)
	}
}

func TestVerifyBearerToken_NotBeforeRejected(t *testing.T) {
	_, priv, pubPEM := ed25519Pair(t)
	const kid = "ed-1"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{})

	tok := signEdDSA(t, priv, kid, jwt.MapClaims{
		"sub": uuid.New().String(),
		"nbf": time.Now().Add(time.Hour).Unix(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
	})
	if _, err := v.VerifyBearerToken(context.Background(), tok); !errors.Is(err, errTokenInvalid) {
		t.Errorf("nbf-in-future token accepted; err = %v", err)
	}
}

func TestVerifyBearerToken_IssuerMismatchRejected(t *testing.T) {
	_, priv, pubPEM := ed25519Pair(t)
	const kid = "ed-1"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{ExpectedIssuer: "https://idp.example.com"})

	tok := signEdDSA(t, priv, kid, jwt.MapClaims{
		"sub": uuid.New().String(),
		"iss": "https://wrong.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := v.VerifyBearerToken(context.Background(), tok); !errors.Is(err, errTokenInvalid) {
		t.Errorf("wrong issuer accepted; err = %v", err)
	}
}

func TestVerifyBearerToken_EmptyTokenRejected(t *testing.T) {
	repo := &stubKeyRepo{}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{})
	if _, err := v.VerifyBearerToken(context.Background(), ""); !errors.Is(err, errTokenInvalid) {
		t.Errorf("empty token accepted; err = %v", err)
	}
}

func TestVerifyBearerToken_KidAlgMismatchRejected(t *testing.T) {
	// Repository has an EdDSA key under kid "ed-1". The token
	// header announces alg=ES256 with that kid — the verifier
	// must refuse to verify ES256 against an EdDSA public key.
	_, _, pubPEM := ed25519Pair(t)
	const kid = "ed-1"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{})

	// Sign with a real ES256 key but under the EdDSA kid — the
	// verifier looks up the kid → EdDSA entry, sees alg mismatch,
	// and rejects.
	_, esPriv, _ := p256Pair(t)
	tampered := signES256(t, esPriv, kid, jwt.MapClaims{
		"sub": uuid.New().String(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := v.VerifyBearerToken(context.Background(), tampered); !errors.Is(err, errTokenInvalid) {
		t.Errorf("kid/alg mismatch accepted; err = %v", err)
	}
}

// alterAlgToNone is a low-level helper that rewrites the header
// portion of a signed JWT to alg="none". The resulting token is
// invalid for any reasonable verifier; this test asserts the
// verifier rejects it.
func alterAlgToNone(t *testing.T, signed string) string {
	t.Helper()
	// header.payload.signature
	parts := splitJWT(signed)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	// Manually craft an alg=none header (base64url-no-pad).
	header := `{"alg":"none","typ":"JWT","kid":"ed-1"}`
	parts[0] = b64URL(header)
	parts[2] = "" // drop signature for alg=none
	return parts[0] + "." + parts[1] + "." + parts[2]
}

// splitJWT splits on '.' without using strings.Split — keeps this
// helper alone-standing and reviewable.
func splitJWT(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func b64URL(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	src := []byte(s)
	var out []byte
	for i := 0; i < len(src); i += 3 {
		var n uint32
		var pad int
		switch {
		case i+3 <= len(src):
			n = uint32(src[i])<<16 | uint32(src[i+1])<<8 | uint32(src[i+2])
		case i+2 == len(src):
			n = uint32(src[i])<<16 | uint32(src[i+1])<<8
			pad = 1
		case i+1 == len(src):
			n = uint32(src[i]) << 16
			pad = 2
		}
		out = append(out,
			alphabet[(n>>18)&63],
			alphabet[(n>>12)&63],
			alphabet[(n>>6)&63],
			alphabet[n&63],
		)
		if pad > 0 {
			out = out[:len(out)-pad]
		}
	}
	return string(out)
}

func TestNewRepositoryVerifier_NilRepoPanics(t *testing.T) {
	defer func() {
		if recover() != nil {
			t.Errorf("NewRepositoryVerifier(nil, nil) did not panic")
		}
	}()
	_ = NewRepositoryVerifier(nil, nil, VerifierOptions{})
}
