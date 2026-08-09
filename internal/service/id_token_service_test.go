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

// ---------- helpers ----------

func newIDTokenSvc(t *testing.T) (*IDTokenService, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	provider := &inMemoryKeyProvider{
		keys: []domain.SigningKey{
			{
				KID:        "kid-eddsa",
				Algorithm:  domain.KeyAlgorithmEdDSA,
				PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
				State:      domain.KeyStateActive,
			},
		},
	}
	svc := NewIDTokenService(nil, provider, IDTokenServiceOptions{
		Issuer: "https://idp.test",
		TTL:    time.Hour,
	})
	return svc, pub
}

func newIDTokenUser() *domain.User {
	return &domain.User{
		ID:             uuid.New(),
		OrganizationID: uuid.New(),
		Email:          "alice@example.com",
		EmailVerified:  true,
		Role:           domain.RoleOrgUser,
	}
}

func newIDTokenSession() *domain.Session {
	return &domain.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		CreatedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		IsValid:   true,
		Acr:       "0",
		Amr:       []string{"pwd"},
	}
}

func parseIDToken(t *testing.T, raw string) (jwt.MapClaims, *jwt.Token) {
	t.Helper()
	tok, _, err := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c, _ := tok.Claims.(jwt.MapClaims)
	return c, tok
}

// ---------- Construction ----------

func TestNewIDTokenService_NilKeysPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil keys did not panic")
		}
	}()
	_ = NewIDTokenService(nil, nil, IDTokenServiceOptions{Issuer: "x"})
}

func TestNewIDTokenService_EmptyIssuerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("empty issuer did not panic")
		}
	}()
	_ = NewIDTokenService(nil, &inMemoryKeyProvider{}, IDTokenServiceOptions{})
}

// ---------- Issue ----------

func TestIDToken_StampsCanonicalClaims(t *testing.T) {
	svc, _ := newIDTokenSvc(t)
	user := newIDTokenUser()
	session := newIDTokenSession()
	resp, err := svc.Issue(context.Background(), IDTokenInput{
		User:     user,
		Session:  session,
		Audience: "cli-1",
		Nonce:    "nonce-1",
		Scope:    "openid email profile",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, _ := parseIDToken(t, resp.IDToken)
	if claims["iss"] != "https://idp.test" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["sub"] != user.ID.String() {
		t.Errorf("sub = %v", claims["sub"])
	}
	if claims["aud"] != "cli-1" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if claims["nonce"] != "nonce-1" {
		t.Errorf("nonce = %v", claims["nonce"])
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("email = %v", claims["email"])
	}
	if claims["email_verified"] != true {
		t.Errorf("email_verified = %v", claims["email_verified"])
	}
	if claims["acr"] != "0" {
		t.Errorf("acr = %v", claims["acr"])
	}
	authTime, ok := claims["auth_time"].(float64)
	if !ok {
		t.Errorf("auth_time missing or wrong type: %T", claims["auth_time"])
	}
	if int64(authTime) <= 0 {
		t.Errorf("auth_time = %v", authTime)
	}
}

func TestIDToken_HeaderHasEdDSAAlgAndKID(t *testing.T) {
	svc, _ := newIDTokenSvc(t)
	resp, err := svc.Issue(context.Background(), IDTokenInput{
		User:     newIDTokenUser(),
		Session:  newIDTokenSession(),
		Audience: "cli-1",
		Scope:    "openid",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, tok := parseIDToken(t, resp.IDToken)
	if tok.Header["alg"] != "EdDSA" {
		t.Errorf("alg = %v", tok.Header["alg"])
	}
	if tok.Header["kid"] != "kid-eddsa" {
		t.Errorf("kid = %v", tok.Header["kid"])
	}
}

func TestIDToken_EmailOmittedWithoutEmailScope(t *testing.T) {
	svc, _ := newIDTokenSvc(t)
	resp, err := svc.Issue(context.Background(), IDTokenInput{
		User:     newIDTokenUser(),
		Session:  newIDTokenSession(),
		Audience: "cli-1",
		Scope:    "openid profile",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, _ := parseIDToken(t, resp.IDToken)
	if _, ok := claims["email"]; ok {
		t.Errorf("email leaked without email scope: %v", claims["email"])
	}
	if _, ok := claims["email_verified"]; ok {
		t.Errorf("email_verified leaked without email scope: %v", claims["email_verified"])
	}
}

func TestIDToken_NonceOmittedWhenEmpty(t *testing.T) {
	svc, _ := newIDTokenSvc(t)
	resp, err := svc.Issue(context.Background(), IDTokenInput{
		User:     newIDTokenUser(),
		Session:  newIDTokenSession(),
		Audience: "cli-1",
		Scope:    "openid",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, _ := parseIDToken(t, resp.IDToken)
	if _, ok := claims["nonce"]; ok {
		t.Errorf("nonce leaked when not supplied: %v", claims["nonce"])
	}
}

func TestIDToken_RoundtripVerifies(t *testing.T) {
	svc, pub := newIDTokenSvc(t)
	resp, err := svc.Issue(context.Background(), IDTokenInput{
		User:     newIDTokenUser(),
		Session:  newIDTokenSession(),
		Audience: "cli-1",
		Scope:    "openid",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, err := parser.Parse(resp.IDToken, func(t *jwt.Token) (any, error) {
		return pub, nil
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !tok.Valid {
		t.Errorf("token not valid")
	}
}

func TestIDToken_RS256BannedAtSelection(t *testing.T) {
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{genRS256Key(t, "kid-rs256")}}
	svc := NewIDTokenService(nil, provider, IDTokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.Issue(context.Background(), IDTokenInput{
		User:     newIDTokenUser(),
		Session:  newIDTokenSession(),
		Audience: "cli-1",
		Scope:    "openid",
	})
	if !errors.Is(err, ErrIDTokenNoSigningKey) {
		t.Errorf("RS256-only provider issued: err = %v", err)
	}
}

func TestIDToken_NilUserOrSessionInvalid(t *testing.T) {
	svc, _ := newIDTokenSvc(t)
	if _, err := svc.Issue(context.Background(), IDTokenInput{User: nil, Session: newIDTokenSession(), Audience: "cli-1"}); !errors.Is(err, ErrIDTokenInvalidRequest) {
		t.Errorf("nil user err = %v", err)
	}
	if _, err := svc.Issue(context.Background(), IDTokenInput{User: newIDTokenUser(), Session: nil, Audience: "cli-1"}); !errors.Is(err, ErrIDTokenInvalidRequest) {
		t.Errorf("nil session err = %v", err)
	}
}

func TestIDToken_EmptyAudienceInvalid(t *testing.T) {
	svc, _ := newIDTokenSvc(t)
	if _, err := svc.Issue(context.Background(), IDTokenInput{User: newIDTokenUser(), Session: newIDTokenSession()}); !errors.Is(err, ErrIDTokenInvalidRequest) {
		t.Errorf("err = %v", err)
	}
}

func TestIDToken_NoSigningKeyMapsToSentinel(t *testing.T) {
	svc := NewIDTokenService(nil, &inMemoryKeyProvider{}, IDTokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.Issue(context.Background(), IDTokenInput{
		User:     newIDTokenUser(),
		Session:  newIDTokenSession(),
		Audience: "cli-1",
		Scope:    "openid",
	})
	if !errors.Is(err, ErrIDTokenNoSigningKey) {
		t.Errorf("err = %v", err)
	}
}
