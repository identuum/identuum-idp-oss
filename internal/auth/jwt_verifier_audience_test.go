package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// Audience-confinement VERIFY side (audience-confusion fix). With
// ExpectedAudience = issuer (as wired on the shared bearer verifier), the
// verifier admits tokens whose aud contains the issuer (user-session +
// IdP-destined machine, post-mint-stamp) and rejects resource-server tokens
// (aud = a downstream api_resource) and aud-absent tokens. The aud check is
// ordered AFTER signature + iss, so the other checks are untouched. Mint-side
// stamping is proven in internal/service (token_service_audience_test.go).
func TestVerifyBearerToken_AudienceConfinement(t *testing.T) {
	_, priv, pubPEM := ed25519Pair(t)
	const kid = "ed-aud"
	const issuer = "https://idp.test"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{
		ExpectedIssuer:   issuer,
		ExpectedAudience: issuer,
	})

	mk := func(aud any) string {
		claims := jwt.MapClaims{
			"sub": uuid.New().String(),
			"iss": issuer,
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"iat": time.Now().Unix(),
		}
		if aud != nil {
			claims["aud"] = aud
		}
		return signEdDSA(t, priv, kid, claims)
	}

	cases := []struct {
		name  string
		aud   any
		admit bool
	}{
		{"(a) IdP-destined aud=issuer (string)", issuer, true},
		{"aud=[issuer] (array)", []string{issuer}, true},
		{"aud=[foreign, issuer] (array contains issuer)", []string{"https://api.example.com", issuer}, true},
		{"(c/e) RS-destined aud=api_resource", "https://api.example.com", false},
		{"(f) aud absent", nil, false},
		{"aud=[only foreign]", []string{"https://api.example.com"}, false},
	}
	for _, tc := range cases {
		_, err := v.VerifyBearerToken(context.Background(), mk(tc.aud))
		admitted := err == nil
		t.Logf("EVIDENCE %s: admitted=%v (want %v)", tc.name, admitted, tc.admit)
		if admitted != tc.admit {
			t.Errorf("%s: admitted=%v, want %v (err=%v)", tc.name, admitted, tc.admit, err)
		}
	}
}

// (g-slice) Regression: with ExpectedAudience set, a token that is correctly
// aud=issuer but has a BAD issuer / expired / wrong alg is still rejected —
// the aud check is additive, not a replacement for the existing checks.
func TestVerifyBearerToken_AudiencePlusOtherChecksStillEnforced(t *testing.T) {
	_, priv, pubPEM := ed25519Pair(t)
	const kid = "ed-aud2"
	const issuer = "https://idp.test"
	repo := &stubKeyRepo{keys: []domain.SigningKey{
		{KID: kid, Algorithm: domain.KeyAlgorithmEdDSA, PublicKey: pubPEM},
	}}
	v := NewRepositoryVerifier(nil, repo, VerifierOptions{ExpectedIssuer: issuer, ExpectedAudience: issuer})

	// Correct aud=issuer but WRONG issuer → still rejected (iss check intact).
	wrongIss := signEdDSA(t, priv, kid, jwt.MapClaims{
		"sub": uuid.New().String(), "iss": "https://evil.test", "aud": issuer,
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
	})
	if _, err := v.VerifyBearerToken(context.Background(), wrongIss); err == nil {
		t.Errorf("aud=issuer but wrong iss was admitted; iss check must still apply")
	}
	// Correct aud=issuer but EXPIRED → still rejected (exp check intact).
	expired := signEdDSA(t, priv, kid, jwt.MapClaims{
		"sub": uuid.New().String(), "iss": issuer, "aud": issuer,
		"exp": time.Now().Add(-time.Minute).Unix(), "iat": time.Now().Add(-2 * time.Minute).Unix(),
	})
	if _, err := v.VerifyBearerToken(context.Background(), expired); err == nil {
		t.Errorf("aud=issuer but expired was admitted; exp check must still apply")
	}
	t.Logf("EVIDENCE (g) aud check is additive: wrong-iss and expired tokens still rejected with aud=issuer")
}
