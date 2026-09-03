package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// TestIntrospectToken_ParticipantTokenAudienceIsDeferredToTheStore pins the
// AYGHU-4 verifier contract: a participant token (signed claim set carrying
// BOTH agent_communication and cnf) is addressed to its relay audience, so
// IntrospectToken hands it back with those claims in Extra and lets the
// introspection service judge the audience against the stored
// authorization; every other token keeps the issuer-audience equality, and
// the BEARER path refuses a relay token outright.
func TestIntrospectToken_ParticipantTokenAudienceIsDeferredToTheStore(t *testing.T) {
	_, priv, pubPEM := ed25519Pair(t)
	const kid = "ed-ac"
	const issuer = "https://idp.test"
	const relay = "https://relay.example.test/session"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{ExpectedIssuer: issuer, ExpectedAudience: issuer})

	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"sub":       uuid.New().String(),
			"iss":       issuer,
			"aud":       relay,
			"exp":       time.Now().Add(5 * time.Minute).Unix(),
			"iat":       time.Now().Unix(),
			"jti":       uuid.New().String(),
			"client_id": "agent-a-client",
			"org_id":    uuid.New().String(),
		}
	}
	participant := base()
	participant["cnf"] = map[string]any{"jkt": "thumb"}
	participant["agent_communication"] = map[string]any{"authorization_id": "x", "aci": "y"}
	participant["authorization_details"] = []any{map[string]any{"type": "agent_communication"}}

	claims, err := v.IntrospectToken(context.Background(), signEdDSA(t, priv, kid, participant))
	if err != nil {
		t.Fatalf("participant token with the relay audience must reach the introspection service: %v", err)
	}
	if claims.Extra == nil || claims.Extra["cnf"] == nil || claims.Extra["agent_communication"] == nil || claims.Extra["authorization_details"] == nil {
		t.Fatalf("the signed cnf / agent_communication / authorization_details claims must be handed back in Extra: %+v", claims.Extra)
	}
	if len(claims.Aud) != 1 || claims.Aud[0] != relay {
		t.Errorf("aud must be handed back for the store-side judgement: %v", claims.Aud)
	}

	noCnf := base()
	noCnf["agent_communication"] = map[string]any{"authorization_id": "x"}
	if _, err := v.IntrospectToken(context.Background(), signEdDSA(t, priv, kid, noCnf)); err == nil {
		t.Errorf("agent_communication without cnf is not a participant token: the issuer-audience equality must still apply")
	}

	plain := base()
	if _, err := v.IntrospectToken(context.Background(), signEdDSA(t, priv, kid, plain)); err == nil {
		t.Errorf("a plain token addressed to a foreign audience must still be refused")
	}

	if _, err := v.VerifyBearerToken(context.Background(), signEdDSA(t, priv, kid, participant)); err == nil {
		t.Errorf("the bearer path must refuse a relay-addressed participant token on this server's own API")
	}
}
