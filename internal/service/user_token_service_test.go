package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ---------- helpers ----------

func newUserTokenSvc(t *testing.T) (*UserTokenService, *inMemoryKeyProvider, ed25519.PublicKey) {
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
	svc := NewUserTokenService(nil, provider, UserTokenServiceOptions{
		Issuer:         "https://idp.test",
		AccessTokenTTL: time.Hour,
	})
	return svc, provider, pub
}

func newUserAndSession(t *testing.T) (*domain.User, *domain.Session) {
	t.Helper()
	uid := uuid.New()
	orgID := uuid.New()
	sid := uuid.New()
	role := domain.RoleOrgUser
	return &domain.User{
		ID:             uid,
		OrganizationID: orgID,
		Email:          "alice@example.com",
		Role:           role,
	}, &domain.Session{
		ID:        sid,
		UserID:    uid,
		CreatedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		IsValid:   true,
		Acr:       "0",
		Amr:       []string{"pwd"},
	}
}

// ---------- Construction ----------

func TestNewUserTokenService_NilKeysPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil keys did not panic")
		}
	}()
	_ = NewUserTokenService(nil, nil, UserTokenServiceOptions{Issuer: "x"})
}

func TestNewUserTokenService_EmptyIssuerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("empty issuer did not panic")
		}
	}()
	_ = NewUserTokenService(nil, &inMemoryKeyProvider{}, UserTokenServiceOptions{})
}

// ---------- IssueForSession ----------

func TestIssueForSession_StampsCanonicalClaims(t *testing.T) {
	svc, _, _ := newUserTokenSvc(t)
	user, session := newUserAndSession(t)
	resp, err := svc.IssueForSession(context.Background(), user, session)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, _, _ := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	claims := tok.Claims.(jwt.MapClaims)
	if claims["sub"] != user.ID.String() {
		t.Errorf("sub = %v", claims["sub"])
	}
	if claims["iss"] != "https://idp.test" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["actor_type"] != ActorTypeUser {
		t.Errorf("actor_type = %v", claims["actor_type"])
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("email = %v", claims["email"])
	}
	if claims["org_id"] != user.OrganizationID.String() {
		t.Errorf("org_id = %v", claims["org_id"])
	}
	if claims["role"] != string(domain.RoleOrgUser) {
		t.Errorf("role = %v", claims["role"])
	}
	if claims["session_id"] != session.ID.String() {
		t.Errorf("session_id = %v", claims["session_id"])
	}
}

func TestIssueForSession_AlgEdDSAHeaderHasKid(t *testing.T) {
	svc, _, _ := newUserTokenSvc(t)
	user, session := newUserAndSession(t)
	resp, err := svc.IssueForSession(context.Background(), user, session)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	tok, _, _ := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	if tok.Header["alg"] != "EdDSA" {
		t.Errorf("alg = %v", tok.Header["alg"])
	}
	if tok.Header["kid"] != "kid-eddsa" {
		t.Errorf("kid = %v", tok.Header["kid"])
	}
}

func TestIssueForSession_NoSigningKeyMapsToSentinel(t *testing.T) {
	provider := &inMemoryKeyProvider{}
	svc := NewUserTokenService(nil, provider, UserTokenServiceOptions{Issuer: "https://idp.test"})
	user, session := newUserAndSession(t)
	_, err := svc.IssueForSession(context.Background(), user, session)
	if !errors.Is(err, ErrTokenServiceNoSigningKey) {
		t.Errorf("err = %v", err)
	}
}

func TestIssueForSession_RoundtripVerifies(t *testing.T) {
	svc, _, pub := newUserTokenSvc(t)
	user, session := newUserAndSession(t)
	resp, err := svc.IssueForSession(context.Background(), user, session)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, err := parser.Parse(resp.AccessToken, func(t *jwt.Token) (any, error) {
		return pub, nil
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !tok.Valid {
		t.Errorf("token not valid")
	}
}

func TestIssueForSession_NoRefreshTokenField(t *testing.T) {
	svc, _, _ := newUserTokenSvc(t)
	user, session := newUserAndSession(t)
	resp, err := svc.IssueForSession(context.Background(), user, session)
	// PREMISE: the issue must SUCCEED and produce a token. The error was
	// discarded here for this test's whole life — a failed issue leaves
	// resp zero-valued, and an empty AccessToken contains no substring, so
	// the check below passed while measuring nothing (V4, the same shape as
	// CE's envelope leak tests).
	if err != nil {
		t.Fatalf("IssueForSession: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("IssueForSession returned an empty AccessToken — the absence check below would pass vacuously")
	}
	// The response struct has no RefreshToken — compile-time
	// guarantee enforced by the type. Runtime sanity:
	if strings.Contains(resp.AccessToken, "refresh_token") {
		t.Errorf("response leaked refresh_token field")
	}
}

func TestIssueForSession_NilUserOrSessionInvalid(t *testing.T) {
	svc, _, _ := newUserTokenSvc(t)
	if _, err := svc.IssueForSession(context.Background(), nil, &domain.Session{}); !errors.Is(err, ErrTokenServiceInvalidRequest) {
		t.Errorf("nil user err = %v", err)
	}
	if _, err := svc.IssueForSession(context.Background(), &domain.User{}, nil); !errors.Is(err, ErrTokenServiceInvalidRequest) {
		t.Errorf("nil session err = %v", err)
	}
}

func TestIssueForSession_RS256BannedAtSelection(t *testing.T) {
	// inMemoryKeyProvider exposes an RS256 helper via the
	// existing test file; reuse genRS256Key to ensure RS256-only
	// rotations never produce a key.
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{genRS256Key(t, "kid-rs256")}}
	svc := NewUserTokenService(nil, provider, UserTokenServiceOptions{Issuer: "https://idp.test"})
	user, session := newUserAndSession(t)
	_, err := svc.IssueForSession(context.Background(), user, session)
	if !errors.Is(err, ErrTokenServiceNoSigningKey) {
		t.Errorf("RS256-only provider issued: err = %v", err)
	}
}
