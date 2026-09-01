package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// A-4 Phase 4 equivalence teeth: prove IDTokenService.Issue, rewired through
// the oidc.IDTokenIssuer seam, produces a BYTE-IDENTICAL id_token to the
// pre-A-4 inline claim map for the same inputs+key (EdDSA signing is
// deterministic, so equality is exact), in both the no-email and email
// shapes, and each verifies under the key.

const (
	idtokIssuer = "https://idp.test"
	idtokJTI    = "0192dddd-eeee-7fff-8000-111111111111"
)

func idtokFixedNow() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) }

// edIDTokenFixture builds an IDTokenService with a pinned clock+jti over a
// single fixed EdDSA key; returns the raw ed25519 keys + kid so the test can
// reconstruct the expected token independently.
func edIDTokenFixture(t *testing.T) (*IDTokenService, ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	kid := "kid-eddsa-idtok"
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID:        kid,
		Algorithm:  domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	svc := NewIDTokenService(nil, provider, IDTokenServiceOptions{Issuer: idtokIssuer, TTL: time.Hour})
	svc.now = idtokFixedNow
	svc.newJTI = func() (string, error) { return idtokJTI, nil }
	return svc, priv, pub, kid
}

// expectedInlineIDToken reproduces the pre-A-4 inline id-token claim map +
// signing path verbatim — the golden the seam must match byte-for-byte.
func expectedInlineIDToken(t *testing.T, priv ed25519.PrivateKey, kid string, now, exp time.Time, user *domain.User, session *domain.Session, audience, nonce, scope string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":       idtokIssuer,
		"sub":       user.ID.String(),
		"aud":       audience,
		"iat":       now.Unix(),
		"exp":       exp.Unix(),
		"jti":       idtokJTI,
		"auth_time": session.EffectiveAuthTime().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if acr := session.EffectiveACR(); acr != "" {
		claims["acr"] = acr
	}
	if len(session.Amr) > 0 {
		claims["amr"] = session.Amr
	}
	// THE-CONSENTED-SCOPE: the golden carries NO email under any scope —
	// scope-requested claims belong to userinfo in the code flow (OIDC Core
	// §5.4). `scope` stays a parameter so both shapes below still exercise
	// the same path the service takes.
	_ = scope
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("expected-token sign: %v", err)
	}
	return signed
}

func verifyIDToken(t *testing.T, token string, pub ed25519.PublicKey, kid string) {
	t.Helper()
	tok, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithTimeFunc(idtokFixedNow),
	).Parse(token, func(*jwt.Token) (any, error) { return pub, nil })
	if err != nil || !tok.Valid {
		t.Fatalf("verify: err=%v valid=%v", err, tok.Valid)
	}
	if tok.Header["kid"] != kid {
		t.Errorf("kid = %v, want %q", tok.Header["kid"], kid)
	}
}

// TestIDToken_Equivalence_NoEmailScope: "openid profile" (no email scope) ->
// no email/email_verified claims.
func TestIDToken_Equivalence_NoEmailScope(t *testing.T) {
	svc, priv, pub, kid := edIDTokenFixture(t)
	user, session := newIDTokenUser(), newIDTokenSession()
	const nonce, scope = "nonce-x", "openid profile"
	exp := idtokFixedNow().Add(time.Hour)

	resp, err := svc.Issue(context.Background(), IDTokenInput{
		User: user, Session: session, Audience: "cli-1", Nonce: nonce, Scope: scope,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	golden := expectedInlineIDToken(t, priv, kid, idtokFixedNow(), exp, user, session, "cli-1", nonce, scope)
	if resp.IDToken != golden {
		t.Fatalf("no-email id_token differs from pre-A-4 inline output:\n got  %s\n want %s", resp.IDToken, golden)
	}
	if resp.JTI != idtokJTI {
		t.Errorf("JTI = %q, want %q", resp.JTI, idtokJTI)
	}
	verifyIDToken(t, resp.IDToken, pub, kid)
}

// TestIDToken_Equivalence_WithEmailScope: "openid email" -> the id_token is
// byte-identical to the golden, which carries NO email/email_verified
// (THE-CONSENTED-SCOPE: those claims are released by userinfo under the
// email scope, never stamped into the id_token).
func TestIDToken_Equivalence_WithEmailScope(t *testing.T) {
	svc, priv, pub, kid := edIDTokenFixture(t)
	user, session := newIDTokenUser(), newIDTokenSession()
	const nonce, scope = "nonce-x", "openid email"
	exp := idtokFixedNow().Add(time.Hour)

	resp, err := svc.Issue(context.Background(), IDTokenInput{
		User: user, Session: session, Audience: "cli-1", Nonce: nonce, Scope: scope,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	golden := expectedInlineIDToken(t, priv, kid, idtokFixedNow(), exp, user, session, "cli-1", nonce, scope)
	if resp.IDToken != golden {
		t.Fatalf("email id_token differs from pre-A-4 inline output:\n got  %s\n want %s", resp.IDToken, golden)
	}
	verifyIDToken(t, resp.IDToken, pub, kid)
}

// authTimeDroppingIssuer wraps the real JWT issuer but deletes auth_time from
// Extra before delegating — the stand-in for a regressed issuer.
type authTimeDroppingIssuer struct{ inner oidc.IDTokenIssuer }

func (i authTimeDroppingIssuer) IssueIDToken(ctx context.Context, tc oidc.IDTokenClaims) (string, error) {
	if tc.Extra != nil {
		delete(tc.Extra, "auth_time")
	}
	return i.inner.IssueIDToken(ctx, tc)
}

// TestIDToken_Equivalence_DroppedClaimBreaksIt is the revert-proof: an issuer
// that drops the always-present auth_time claim produces a token that is NOT
// byte-identical to the golden in BOTH shapes — so each equivalence assertion
// above would fail. This proves the seam is load-bearing, not a hollow relabel.
func TestIDToken_Equivalence_DroppedClaimBreaksIt(t *testing.T) {
	exp := idtokFixedNow().Add(time.Hour)
	for _, scope := range []string{"openid profile", "openid email"} {
		t.Run(scope, func(t *testing.T) {
			svc, priv, _, kid := edIDTokenFixture(t)
			svc.idIssuer = authTimeDroppingIssuer{inner: newJWTIDTokenIssuer(svc.keys)}
			user, session := newIDTokenUser(), newIDTokenSession()
			resp, err := svc.Issue(context.Background(), IDTokenInput{
				User: user, Session: session, Audience: "cli-1", Nonce: "nonce-x", Scope: scope,
			})
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			golden := expectedInlineIDToken(t, priv, kid, idtokFixedNow(), exp, user, session, "cli-1", "nonce-x", scope)
			if resp.IDToken == golden {
				t.Fatalf("auth_time-dropping issuer still matched the golden — equivalence test not load-bearing")
			}
			claims, _ := parseIDToken(t, resp.IDToken)
			if _, present := claims["auth_time"]; present {
				t.Errorf("auth_time should be absent under the dropping issuer")
			}
		})
	}
}
