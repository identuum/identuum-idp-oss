package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// The /end_session id_token_hint is accepted only when its signature verifies
// under an ACTIVE local signing key AND its issuer equals our issuer: a token
// signed by a foreign key is ErrIDTokenHintSignature, and a token whose iss is
// not our issuer is ErrIDTokenHintIssuerMismatch. A valid EdDSA token issued by
// us round-trips. Reuses the id_token_verifier_test harness (local key repo).
// RULE: IDTOKEN-HINT-VERIFY-1
func TestIDTokenHint_AcceptedOnlyWithValidSignatureAndIssuer(t *testing.T) {
	v, priv, kid := newVerifierHarness(t) // issuer = https://idp.test
	uid := uuid.New()
	claims := func(iss string) jwt.MapClaims {
		return jwt.MapClaims{
			"iss": iss, "sub": uid.String(), "aud": []string{"cli-1"},
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		}
	}

	// A valid EdDSA token under our issuer verifies.
	if _, err := v.Verify(context.Background(), mintIDToken(t, kid, priv, claims("https://idp.test"))); err != nil {
		t.Fatalf("PREMISE FAILED: a valid EdDSA id_token_hint must verify, got %v", err)
	}

	// A token whose issuer is not ours is rejected.
	if _, err := v.Verify(context.Background(), mintIDToken(t, kid, priv, claims("https://evil.test"))); !errors.Is(err, ErrIDTokenHintIssuerMismatch) {
		t.Errorf("a wrong-issuer id_token_hint must be ErrIDTokenHintIssuerMismatch, got %v", err)
	}

	// A token signed by a FOREIGN key (same kid, key not in the repo) fails the
	// signature check — it must never be accepted on the correct issuer.
	_, foreignPriv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := v.Verify(context.Background(), mintIDToken(t, kid, foreignPriv, claims("https://idp.test"))); !errors.Is(err, ErrIDTokenHintSignature) {
		t.Errorf("a foreign-key-signed id_token_hint must be ErrIDTokenHintSignature, got %v", err)
	}
}
