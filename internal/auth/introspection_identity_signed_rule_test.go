package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AYGHU-5: the spec's "owner identity is attested by IDP-signed tokens
// only" — the only thing that binds a participant identity to a token is
// this server's signature over the claim set; nothing a peer or the relay
// reads from a message field can substitute for it.

// RULE: AYGHU-IDENTITY-SIGNED-1
func TestRule_AYGHU_IDENTITY_SIGNED_1(t *testing.T) {
	_, priv, pubPEM := ed25519Pair(t)
	_, foreignPriv, _ := ed25519Pair(t)
	const kid = "ed-identity"
	const issuer = "https://idp.test"
	const relay = "https://relay.example.test/session"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{ExpectedIssuer: issuer, ExpectedAudience: issuer})

	saID := uuid.New().String()
	claims := jwt.MapClaims{
		"sub": saID, "iss": issuer, "aud": relay,
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(), "jti": uuid.New().String(),
		"client_id": "agent-a-client", "org_id": uuid.New().String(), "actor_type": "service_account",
		"cnf":                 map[string]any{"jkt": "thumb"},
		"agent_communication": map[string]any{"authorization_id": "x", "aci": "y", "role": "initiator"},
	}

	// The IdP-signed claim set is the attestation: accepted, identity read from it.
	signed := signEdDSA(t, priv, kid, claims)
	got, err := v.IntrospectToken(context.Background(), signed)
	if err != nil {
		t.Fatalf("IdP-signed participant token must be accepted: %v", err)
	}
	if got.Sub != saID || got.ClientID != "agent-a-client" {
		t.Errorf("identity must come from the signed claims: sub=%q client_id=%q", got.Sub, got.ClientID)
	}
	if got.Email != "" {
		t.Errorf("no owner identity rides in a participant token: email=%q", got.Email)
	}

	// A tampered claim set (the signature no longer covers it) is refused —
	// the identity inside it is worth nothing.
	parts := strings.Split(signed, ".")
	tamperedPayload := parts[1]
	if strings.HasSuffix(tamperedPayload, "A") {
		tamperedPayload = tamperedPayload[:len(tamperedPayload)-1] + "B"
	} else {
		tamperedPayload = tamperedPayload[:len(tamperedPayload)-1] + "A"
	}
	if _, err := v.IntrospectToken(context.Background(), parts[0]+"."+tamperedPayload+"."+parts[2]); err == nil {
		t.Errorf("a tampered participant token must be refused")
	}

	// A claim set signed by a key this server never published is refused.
	if _, err := v.IntrospectToken(context.Background(), signEdDSA(t, foreignPriv, kid, claims)); err == nil {
		t.Errorf("a token signed by a foreign key must be refused")
	}

	// An unsigned (alg none) claim set is refused.
	none := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	none.Header["kid"] = kid
	unsigned, err := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("mint alg=none: %v", err)
	}
	if _, err := v.IntrospectToken(context.Background(), unsigned); err == nil {
		t.Errorf("an unsigned claim set must be refused")
	}
}
