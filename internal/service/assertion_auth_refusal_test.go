package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// pkjwtClientLookup returns one fixed client for any client_id.
type pkjwtClientLookup struct{ client *domain.Client }

func (l pkjwtClientLookup) GetClientByClientID(context.Context, string) (*domain.Client, error) {
	return l.client, nil
}

// pkjwtService builds an OAuthClientAuthService whose assertion path resolves
// the given client, sharing the validator config used by the same-package
// validator tests (token endpoint https://idp.test/api/v1/oauth/token).
func pkjwtService(t *testing.T, client *domain.Client) *OAuthClientAuthService {
	t.Helper()
	return &OAuthClientAuthService{
		assertionVerify:  newAssertionValidator(t),
		clientByClientID: pkjwtClientLookup{client: client},
	}
}

// TestAuthenticateAssertion_RefusesBadAssertion pins RFC 7523 private_key_jwt
// client authentication end to end: the client assertion's alg, aud, exp, and
// signature are each validated before the client is authenticated, and a
// malformed assertion is refused outright — every refusal is
// ErrInvalidOAuthClientCredentials. Each tooth gets its own valid-except-one-
// field signed assertion so each guard is independently load-bearing.
// RULE: ASSERTION-AUTH-REFUSE-1
func TestAuthenticateAssertion_RefusesBadAssertion(t *testing.T) {
	ctx := context.Background()
	const tokenEndpoint = "https://idp.test/api/v1/oauth/token"
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	refuse := func(t *testing.T, svc *OAuthClientAuthService, assertion, what string) {
		t.Helper()
		if _, err := svc.AuthenticateAssertion(ctx, "cli-1", assertion); !errors.Is(err, ErrInvalidOAuthClientCredentials) {
			t.Errorf("%s must be refused with ErrInvalidOAuthClientCredentials, got %v", what, err)
		}
	}

	// Baseline sanity: a fully valid assertion authenticates, so each refusal
	// below is attributable to its ONE bad field.
	okClient := newJWKSClient(t, "cli-1", "k1", pub)
	okSvc := pkjwtService(t, okClient)
	valid := signEdDSAAssertion(t, priv, "k1", baseAssertionClaims("cli-1", tokenEndpoint))
	if _, err := okSvc.AuthenticateAssertion(ctx, "cli-1", valid); err != nil {
		t.Fatalf("a fully valid assertion must authenticate, got %v", err)
	}

	// 1. Malformed assertion (not a JWT at all).
	refuse(t, okSvc, "not-a-valid-jwt", "a malformed assertion")

	// 2. ALG tooth: the assertion is EdDSA-signed with the registered key, but
	// the client is configured for RS256 — the header alg must match the
	// client's effective configured alg.
	rs256Client := newJWKSClient(t, "cli-1", "k1", pub)
	rs256Client.TokenEndpointAuthSigningAlg = "RS256"
	refuse(t, pkjwtService(t, rs256Client),
		signEdDSAAssertion(t, priv, "k1", baseAssertionClaims("cli-1", tokenEndpoint)),
		"an assertion whose alg differs from the client's configured alg")

	// 3. AUD tooth: valid signature, wrong audience.
	wrongAud := baseAssertionClaims("cli-1", "https://attacker.example.com/token")
	refuse(t, okSvc, signEdDSAAssertion(t, priv, "k1", wrongAud),
		"an assertion whose aud is not the token endpoint")

	// 4. EXP tooth: valid signature and audience, expired beyond clock skew
	// (exp 120s ago vs 60s skew) while iat age and lifetime stay legal.
	expired := baseAssertionClaims("cli-1", tokenEndpoint)
	nowU := time.Now().Unix()
	expired["exp"] = nowU - 120
	expired["iat"] = nowU - 180
	refuse(t, okSvc, signEdDSAAssertion(t, priv, "k1", expired),
		"an expired assertion")

	// 5. SIGNATURE tooth: fully valid claims, same kid, but signed with a
	// DIFFERENT key than the one registered in the client's JWKS.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	refuse(t, okSvc, signEdDSAAssertion(t, otherPriv, "k1", baseAssertionClaims("cli-1", tokenEndpoint)),
		"an assertion signed by a key not in the client's JWKS")
}
