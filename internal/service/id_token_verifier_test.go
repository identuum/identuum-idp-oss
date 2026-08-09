package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// inMemoryKeyRepo is a minimal KeyRepository for the verifier tests.
type inMemoryKeyRepo struct {
	keys []domain.SigningKey
}

func (r *inMemoryKeyRepo) GetActiveSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	return r.keys, nil
}
func (r *inMemoryKeyRepo) GetAllSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	return r.keys, nil
}
func (r *inMemoryKeyRepo) GetSigningKeyByKID(_ context.Context, kid string) (*domain.SigningKey, error) {
	for i, k := range r.keys {
		if k.KID == kid {
			return &r.keys[i], nil
		}
	}
	return nil, nil
}
func (r *inMemoryKeyRepo) CreateSigningKey(context.Context, *domain.SigningKey) error { return nil }
func (r *inMemoryKeyRepo) ActivateSigningKey(context.Context, string) error           { return nil }
func (r *inMemoryKeyRepo) RotateSigningKey(context.Context, string, string, *time.Time) error {
	return nil
}
func (r *inMemoryKeyRepo) DeprecateSigningKey(context.Context, string, time.Time) error { return nil }
func (r *inMemoryKeyRepo) DeleteExpiredKeys(context.Context) (int, error)               { return 0, nil }

// mintIDToken signs a test ID token with the supplied claims.
func mintIDToken(t *testing.T, kid string, priv ed25519.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func newVerifierHarness(t *testing.T) (*IDTokenVerifier, ed25519.PrivateKey, string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(priv.Public())
	pkBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	const kid = "kid-eddsa"
	repo := &inMemoryKeyRepo{keys: []domain.SigningKey{{
		KID:        kid,
		Algorithm:  domain.KeyAlgorithmEdDSA,
		PublicKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})),
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkBytes})),
		State:      domain.KeyStateActive,
	}}}
	v := NewIDTokenVerifier(nil, repo, IDTokenVerifierOptions{Issuer: "https://idp.test"})
	return v, priv, kid
}

// ---------- Construction ----------

func TestNewIDTokenVerifier_NilKeysPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil keys did not panic")
		}
	}()
	_ = NewIDTokenVerifier(nil, nil, IDTokenVerifierOptions{Issuer: "x"})
}

func TestNewIDTokenVerifier_EmptyIssuerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("empty issuer did not panic")
		}
	}()
	_ = NewIDTokenVerifier(nil, &inMemoryKeyRepo{}, IDTokenVerifierOptions{})
}

// ---------- Verify ----------

func TestVerifyIDTokenHint_ValidEdDSAReturnsClaims(t *testing.T) {
	v, priv, kid := newVerifierHarness(t)
	uid := uuid.New()
	sid := uuid.New()
	raw := mintIDToken(t, kid, priv, jwt.MapClaims{
		"iss":        "https://idp.test",
		"sub":        uid.String(),
		"aud":        []string{"cli-1", "cli-2"},
		"exp":        time.Now().Add(time.Hour).Unix(),
		"iat":        time.Now().Unix(),
		"session_id": sid.String(),
	})
	out, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if out.Subject != uid {
		t.Errorf("sub mismatch")
	}
	if len(out.Audience) != 2 || out.Audience[0] != "cli-1" {
		t.Errorf("audience = %v", out.Audience)
	}
	if out.SessionID != sid {
		t.Errorf("session_id mismatch")
	}
}

func TestVerifyIDTokenHint_EmptyTokenReturnsMalformed(t *testing.T) {
	v, _, _ := newVerifierHarness(t)
	_, err := v.Verify(context.Background(), "")
	if !errors.Is(err, ErrIDTokenHintMalformed) {
		t.Errorf("err = %v", err)
	}
}

func TestVerifyIDTokenHint_WrongIssuerRejected(t *testing.T) {
	v, priv, kid := newVerifierHarness(t)
	raw := mintIDToken(t, kid, priv, jwt.MapClaims{
		"iss": "https://imposter.example.com",
		"sub": uuid.New().String(),
		"aud": "cli-1",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	_, err := v.Verify(context.Background(), raw)
	if !errors.Is(err, ErrIDTokenHintIssuerMismatch) {
		t.Errorf("err = %v", err)
	}
}

func TestVerifyIDTokenHint_ExpiredRejected(t *testing.T) {
	v, priv, kid := newVerifierHarness(t)
	raw := mintIDToken(t, kid, priv, jwt.MapClaims{
		"iss": "https://idp.test",
		"sub": uuid.New().String(),
		"aud": "cli-1",
		"exp": time.Now().Add(-time.Minute).Unix(),
		"iat": time.Now().Add(-2 * time.Minute).Unix(),
	})
	_, err := v.Verify(context.Background(), raw)
	if !errors.Is(err, ErrIDTokenHintExpired) {
		t.Errorf("err = %v", err)
	}
}

func TestVerifyIDTokenHint_UnknownKIDRejected(t *testing.T) {
	v, priv, _ := newVerifierHarness(t)
	raw := mintIDToken(t, "kid-other", priv, jwt.MapClaims{
		"iss": "https://idp.test",
		"sub": uuid.New().String(),
		"aud": "cli-1",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	_, err := v.Verify(context.Background(), raw)
	if !errors.Is(err, ErrIDTokenHintUnknownKID) {
		t.Errorf("err = %v", err)
	}
}

func TestVerifyIDTokenHint_NoneAlgRejected(t *testing.T) {
	v, _, _ := newVerifierHarness(t)
	// hand-craft alg=none token.
	noneTok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss": "https://idp.test",
		"sub": uuid.New().String(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	noneTok.Header["kid"] = "kid-eddsa"
	raw, _ := noneTok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	_, err := v.Verify(context.Background(), raw)
	if err == nil {
		t.Errorf("alg=none accepted: expected rejection")
	}
}

func TestVerifyIDTokenHint_GarbageRejected(t *testing.T) {
	v, _, _ := newVerifierHarness(t)
	_, err := v.Verify(context.Background(), "this.is.not-a-jwt")
	if !errors.Is(err, ErrIDTokenHintMalformed) && !errors.Is(err, ErrIDTokenHintSignature) {
		t.Errorf("err = %v", err)
	}
}

func TestVerifyIDTokenHint_SingleStringAudienceParsed(t *testing.T) {
	v, priv, kid := newVerifierHarness(t)
	raw := mintIDToken(t, kid, priv, jwt.MapClaims{
		"iss": "https://idp.test",
		"sub": uuid.New().String(),
		"aud": "cli-only",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	out, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(out.Audience) != 1 || out.Audience[0] != "cli-only" {
		t.Errorf("audience = %v", out.Audience)
	}
}

func TestVerifyIDTokenHint_RS256RepoKeysRejected(t *testing.T) {
	// Simulate a repo that only has an RS256 key — verifier
	// should refuse to load it and return signature error.
	repo := &inMemoryKeyRepo{keys: []domain.SigningKey{{
		KID: "kid-rs256", Algorithm: domain.KeyAlgorithmRS256, State: domain.KeyStateActive,
	}}}
	v := NewIDTokenVerifier(nil, repo, IDTokenVerifierOptions{Issuer: "https://idp.test"})
	_, err := v.Verify(context.Background(), "anything.here.atall")
	if !errors.Is(err, ErrIDTokenHintSignature) {
		t.Errorf("err = %v", err)
	}
}
