package service

// THE-PKCE-DECISION (owner ruling 2, verbatim): "Add RS256 into the list BUT
// DO NOT USE except testing and put this into documentation CLEARLY."
//
// These tests pin the two halves of that ruling at the minter seam:
//
//   NEVER-DEFAULT — with an RS256 signing key PRESENT and ACTIVE, a client
//   that did not explicitly register RS256 still gets an EdDSA id_token.
//   EXPLICIT-FIRES — a client that registered RS256 gets a real, verifiable
//   RS256 id_token.

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

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func pkcs8PEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// newMultiAlgIDTokenSvc builds an IDTokenService over an active EdDSA key,
// an active ES256 key, AND an active RS256 key (all signing-capable), and
// returns the service plus the RSA public key for verification.
func newMultiAlgIDTokenSvc(t *testing.T) (*IDTokenService, *rsa.PublicKey) {
	t.Helper()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	esPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	provider := &inMemoryKeyProvider{
		keys: []domain.SigningKey{
			// RS256 listed FIRST so any "first active key wins" regression
			// would pick it — the never-default assertions below must still
			// see EdDSA.
			{KID: "kid-rs256", Algorithm: domain.KeyAlgorithmRS256, PrivateKey: pkcs8PEM(t, rsaPriv), State: domain.KeyStateActive},
			{KID: "kid-es256", Algorithm: domain.KeyAlgorithmES256, PrivateKey: pkcs8PEM(t, esPriv), State: domain.KeyStateActive},
			{KID: "kid-eddsa", Algorithm: domain.KeyAlgorithmEdDSA, PrivateKey: pkcs8PEM(t, edPriv), State: domain.KeyStateActive},
		},
	}
	svc := NewIDTokenService(nil, provider, IDTokenServiceOptions{
		Issuer: "https://idp.test",
		TTL:    time.Hour,
	})
	return svc, &rsaPriv.PublicKey
}

func issueWithAlg(t *testing.T, svc *IDTokenService, alg string) *IDTokenResponse {
	t.Helper()
	resp, err := svc.Issue(context.Background(), IDTokenInput{
		User:       newIDTokenUser(),
		Session:    newIDTokenSession(),
		Audience:   "cli-1",
		Scope:      "openid",
		SigningAlg: alg,
	})
	if err != nil {
		t.Fatalf("issue (alg=%q): %v", alg, err)
	}
	return resp
}

func headerAlg(t *testing.T, raw string) (string, string) {
	t.Helper()
	tok, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	alg, _ := tok.Header["alg"].(string)
	kid, _ := tok.Header["kid"].(string)
	return alg, kid
}

// NEVER-DEFAULT: an empty SigningAlg (no registration at all) and the
// default "EdDSA" registration both mint EdDSA — even though a
// signing-capable RS256 key is active and listed first.
// RULE: IDTOKEN-RS256-NEVER-DEFAULT-1
func TestIDToken_RS256NeverDefault(t *testing.T) {
	svc, _ := newMultiAlgIDTokenSvc(t)
	for _, alg := range []string{"", "EdDSA"} {
		resp := issueWithAlg(t, svc, alg)
		gotAlg, gotKID := headerAlg(t, resp.IDToken)
		if gotAlg != "EdDSA" || gotKID != "kid-eddsa" {
			t.Errorf("SigningAlg=%q minted alg=%q kid=%q; want EdDSA/kid-eddsa — RS256 must NEVER be the default", alg, gotAlg, gotKID)
		}
	}
}

// EXPLICIT-FIRES: SigningAlg "RS256" mints a token that VERIFIES against
// the RS256 key — the capability is real, not just a header claim.
func TestIDToken_RS256OnExplicitRegistration(t *testing.T) {
	svc, rsaPub := newMultiAlgIDTokenSvc(t)
	resp := issueWithAlg(t, svc, "RS256")
	gotAlg, gotKID := headerAlg(t, resp.IDToken)
	if gotAlg != "RS256" || gotKID != "kid-rs256" {
		t.Fatalf("minted alg=%q kid=%q; want RS256/kid-rs256", gotAlg, gotKID)
	}
	tok, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"})).Parse(resp.IDToken, func(*jwt.Token) (any, error) {
		return rsaPub, nil
	})
	if err != nil || !tok.Valid {
		t.Fatalf("RS256 id_token does not verify against the RSA public key: %v", err)
	}
}

// An explicit ES256 registration is strict: it mints ES256, not the EdDSA
// preference.
func TestIDToken_ES256ExplicitIsStrict(t *testing.T) {
	svc, _ := newMultiAlgIDTokenSvc(t)
	resp := issueWithAlg(t, svc, "ES256")
	gotAlg, gotKID := headerAlg(t, resp.IDToken)
	if gotAlg != "ES256" || gotKID != "kid-es256" {
		t.Errorf("minted alg=%q kid=%q; want ES256/kid-es256", gotAlg, gotKID)
	}
}

// A client registered for RS256 against a deployment with no RS256 key gets
// the no-signing-key sentinel — never a silent downgrade to another alg.
func TestIDToken_RS256RequestedWithoutKeyFails(t *testing.T) {
	svc, _ := newIDTokenSvc(t) // EdDSA-only provider
	_, err := svc.Issue(context.Background(), IDTokenInput{
		User:       newIDTokenUser(),
		Session:    newIDTokenSession(),
		Audience:   "cli-1",
		Scope:      "openid",
		SigningAlg: "RS256",
	})
	if !errors.Is(err, ErrIDTokenNoSigningKey) {
		t.Fatalf("err = %v, want ErrIDTokenNoSigningKey — no silent downgrade", err)
	}
}

// "EdDSA" keeps the issuer default ORDER, not a strict match: a deployment
// whose only signing key is ES256 (pre-slice reality for ES256-configured
// installs, and every migrated row reads back the 'EdDSA' column default)
// must keep minting via the ES256 fallback rather than break.
func TestIDToken_EdDSADefaultOrderFallsBackToES256(t *testing.T) {
	esPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	provider := &inMemoryKeyProvider{
		keys: []domain.SigningKey{
			{KID: "kid-es-only", Algorithm: domain.KeyAlgorithmES256, PrivateKey: pkcs8PEM(t, esPriv), State: domain.KeyStateActive},
		},
	}
	svc := NewIDTokenService(nil, provider, IDTokenServiceOptions{Issuer: "https://idp.test", TTL: time.Hour})
	resp := issueWithAlg(t, svc, "EdDSA")
	gotAlg, gotKID := headerAlg(t, resp.IDToken)
	if gotAlg != "ES256" || gotKID != "kid-es-only" {
		t.Errorf("minted alg=%q kid=%q; want the ES256 fallback of the issuer default order", gotAlg, gotKID)
	}
}
