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

func newLogoutTokenSvc(t *testing.T) (*LogoutTokenService, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID: "kid-eddsa", Algorithm: domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	svc := NewLogoutTokenService(nil, provider, LogoutTokenServiceOptions{Issuer: "https://idp.test", TTL: 2 * time.Minute})
	return svc, pub
}

// ---------- Construction ----------

func TestNewLogoutTokenService_NilKeysPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil keys did not panic")
		}
	}()
	_ = NewLogoutTokenService(nil, nil, LogoutTokenServiceOptions{Issuer: "x"})
}

func TestNewLogoutTokenService_EmptyIssuerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("empty issuer did not panic")
		}
	}()
	_ = NewLogoutTokenService(nil, &inMemoryKeyProvider{}, LogoutTokenServiceOptions{})
}

// ---------- Issue ----------

func TestLogoutToken_RequiresSubOrSid(t *testing.T) {
	svc, _ := newLogoutTokenSvc(t)
	_, err := svc.Issue(context.Background(), LogoutTokenInput{Audience: "cli-1"})
	if !errors.Is(err, ErrLogoutTokenInvalidInput) {
		t.Errorf("err = %v", err)
	}
}

func TestLogoutToken_RequiresAudience(t *testing.T) {
	svc, _ := newLogoutTokenSvc(t)
	_, err := svc.Issue(context.Background(), LogoutTokenInput{Subject: uuid.New()})
	if !errors.Is(err, ErrLogoutTokenInvalidInput) {
		t.Errorf("err = %v", err)
	}
}

func TestLogoutToken_StampsCanonicalClaims(t *testing.T) {
	svc, _ := newLogoutTokenSvc(t)
	uid := uuid.New()
	sid := uuid.New()
	resp, err := svc.Issue(context.Background(), LogoutTokenInput{
		Audience:  "cli-1",
		Subject:   uid,
		SessionID: sid,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	tok, _, _ := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(resp.LogoutToken, jwt.MapClaims{})
	claims := tok.Claims.(jwt.MapClaims)
	if claims["iss"] != "https://idp.test" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["aud"] != "cli-1" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if claims["sub"] != uid.String() {
		t.Errorf("sub = %v", claims["sub"])
	}
	if claims["sid"] != sid.String() {
		t.Errorf("sid = %v", claims["sid"])
	}
	if _, ok := claims["nonce"]; ok {
		t.Errorf("nonce MUST NOT appear in logout_token: %v", claims["nonce"])
	}
	events, ok := claims["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim missing or wrong type: %T", claims["events"])
	}
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Errorf("backchannel-logout event missing: %v", events)
	}
}

func TestLogoutToken_AlgEdDSANeverRS256(t *testing.T) {
	svc, _ := newLogoutTokenSvc(t)
	resp, _ := svc.Issue(context.Background(), LogoutTokenInput{
		Audience: "cli-1",
		Subject:  uuid.New(),
	})
	tok, _, _ := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(resp.LogoutToken, jwt.MapClaims{})
	if tok.Header["alg"] != "EdDSA" {
		t.Errorf("alg = %v", tok.Header["alg"])
	}
}

func TestLogoutToken_RS256OnlyProviderRejected(t *testing.T) {
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{genRS256Key(t, "kid-rs256")}}
	svc := NewLogoutTokenService(nil, provider, LogoutTokenServiceOptions{Issuer: "https://idp.test"})
	_, err := svc.Issue(context.Background(), LogoutTokenInput{
		Audience: "cli-1",
		Subject:  uuid.New(),
	})
	if !errors.Is(err, ErrLogoutTokenNoSigningKey) {
		t.Errorf("err = %v", err)
	}
}

func TestLogoutToken_RoundtripVerifies(t *testing.T) {
	svc, pub := newLogoutTokenSvc(t)
	resp, _ := svc.Issue(context.Background(), LogoutTokenInput{
		Audience: "cli-1",
		Subject:  uuid.New(),
	})
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, err := parser.Parse(resp.LogoutToken, func(t *jwt.Token) (any, error) {
		return pub, nil
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !tok.Valid {
		t.Errorf("token not valid")
	}
}
