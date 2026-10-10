package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// OSS-HARDENING-2 item 3 (OSS-CONFORMANCE-FIXES Q1, judge: (a)): the client
// assertion's aud may name the token endpoint URL or the OP's issuer
// identifier (the suite's oidcc-ensure-client-assertion-with-iss-aud-succeeds
// and the current OAuth JWT client-authentication guidance). Nothing else.

const (
	assertionAudIssuer        = "https://idp.test"
	assertionAudTokenEndpoint = "https://idp.test/api/v1/oauth/token"
)

func newAssertionValidatorWithIssuer(t *testing.T) *ClientAssertionValidator {
	t.Helper()
	v, err := NewClientAssertionValidator(ClientAssertionValidatorConfig{
		TokenEndpointURL: assertionAudTokenEndpoint,
		Issuer:           assertionAudIssuer,
	})
	if err != nil {
		t.Fatalf("validator init: %v", err)
	}
	return v
}

func validateWithAud(t *testing.T, v *ClientAssertionValidator, aud any) error {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	claims := baseAssertionClaims("cli-1", assertionAudTokenEndpoint)
	claims["aud"] = aud
	signed := signEdDSAAssertion(t, priv, "k1", claims)
	_, err := v.Validate(context.Background(), client, signed)
	return err
}

func TestValidate_AudIssuerIdentifierAccepted(t *testing.T) {
	v := newAssertionValidatorWithIssuer(t)
	if err := validateWithAud(t, v, assertionAudIssuer); err != nil {
		t.Fatalf("aud = the issuer identifier refused: %v", err)
	}
	// A multi-valued aud that names the issuer among others is accepted too.
	if err := validateWithAud(t, v, jwt.ClaimStrings{"https://other.example/rs", assertionAudIssuer}); err != nil {
		t.Fatalf("aud list naming the issuer refused: %v", err)
	}
}

func TestValidate_AudTokenEndpointStillAccepted(t *testing.T) {
	v := newAssertionValidatorWithIssuer(t)
	if err := validateWithAud(t, v, assertionAudTokenEndpoint); err != nil {
		t.Fatalf("aud = the token endpoint URL refused with an issuer configured: %v", err)
	}
}

func TestValidate_AudNeitherIssuerNorTokenEndpointRefused(t *testing.T) {
	v := newAssertionValidatorWithIssuer(t)
	for _, aud := range []string{
		"https://idp.test/api/v1/oauth/authorize", // same OP, another endpoint
		"https://idp.test/",                       // the issuer with a trailing slash is another string
		"https://wrong.example.com/token",
		"",
	} {
		if err := validateWithAud(t, v, aud); !errors.Is(err, ErrClientAssertionInvalid) {
			t.Errorf("aud %q accepted (err=%v); want ErrClientAssertionInvalid", aud, err)
		}
	}
}

func TestValidate_AudIssuerRefusedWhenNoIssuerConfigured(t *testing.T) {
	// The pre-existing construction (token endpoint only) admits nothing new.
	v := newAssertionValidator(t)
	if err := validateWithAud(t, v, assertionAudIssuer); !errors.Is(err, ErrClientAssertionInvalid) {
		t.Fatalf("aud = issuer accepted without an issuer configured (err=%v)", err)
	}
}
