package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// A client assertion is bounded in time from now, not only relative to its
// own iat: an iat in the future or an exp beyond the maximum lifetime from
// now is refused, so a pre-dated assertion cannot outlive the replay record.
func TestValidate_AssertionTimeBoundedFromNow(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := newJWKSClient(t, "cli-1", "k1", pub)
	v := newAssertionValidator(t)
	endpoint := "https://idp.test/api/v1/oauth/token"
	now := time.Now().Unix()

	future := baseAssertionClaims("cli-1", endpoint)
	future["iat"] = now + 3600
	future["exp"] = now + 3600 + 120
	if _, err := v.Validate(context.Background(), client, signEdDSAAssertion(t, priv, "k1", future)); !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("an iat an hour in the future must be refused, got %v", err)
	}

	far := baseAssertionClaims("cli-1", endpoint)
	far["iat"] = now
	far["exp"] = now + 3600
	if _, err := v.Validate(context.Background(), client, signEdDSAAssertion(t, priv, "k1", far)); !errors.Is(err, ErrClientAssertionInvalid) {
		t.Errorf("an exp an hour away must be refused, got %v", err)
	}
}

// The replay record outlives every assertion the validator can accept.
func TestClientAssertionReplay_DefaultCapCoversAcceptanceWindow(t *testing.T) {
	if defaultReplayTTLMax < clientAssertionMaxLifetime+2*time.Minute {
		t.Errorf("replay cap %v must cover the %v assertion lifetime plus clock skew", defaultReplayTTLMax, clientAssertionMaxLifetime)
	}
}
