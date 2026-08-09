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

// edEquivFixture builds a UserTokenService whose clock AND jti are pinned,
// backed by a single fixed EdDSA key, and returns the raw ed25519 keys +
// kid so the test can independently reconstruct the expected token.
func edEquivFixture(t *testing.T, fixedNow time.Time, fixedJTI string) (*UserTokenService, ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	kid := "kid-eddsa-equiv"
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{{
		KID:        kid,
		Algorithm:  domain.KeyAlgorithmEdDSA,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
		State:      domain.KeyStateActive,
	}}}
	svc := NewUserTokenService(nil, provider, UserTokenServiceOptions{
		Issuer:         "https://idp.test",
		AccessTokenTTL: time.Hour,
	})
	svc.now = func() time.Time { return fixedNow }
	svc.newJTI = func() (string, error) { return fixedJTI, nil }
	return svc, priv, pub, kid
}

// expectedInlineToken reproduces the PRE-A-4 inline claim map + signing path
// verbatim: this is the golden the rewired seam must reproduce byte-for-byte.
func expectedInlineToken(t *testing.T, priv ed25519.PrivateKey, kid, issuer, jti string, now, exp time.Time, user *domain.User, session *domain.Session) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":        issuer,
		"sub":        user.ID.String(),
		"aud":        issuer, // Audience defaults to Issuer when unset.
		"iat":        now.Unix(),
		"exp":        exp.Unix(),
		"jti":        jti,
		"actor_type": ActorTypeUser,
		"session_id": session.ID.String(),
		"auth_time":  session.EffectiveAuthTime().Unix(),
	}
	if user.OrganizationID != (domain.User{}).OrganizationID {
		claims["org_id"] = user.OrganizationID.String()
	}
	if user.Email != "" {
		claims["email"] = user.Email
	}
	if user.Role != "" {
		claims["role"] = string(user.Role)
	}
	if acr := session.EffectiveACR(); acr != "" {
		claims["acr"] = acr
	}
	if len(session.Amr) > 0 {
		claims["amr"] = session.Amr
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("expected-token sign: %v", err)
	}
	return signed
}

// TestIssueForSession_Equivalence_ByteIdentical is the A-4 Phase 1 teeth: with
// a fixed clock and fixed jti, the token minted through the extracted
// AccessTokenMinter seam is BYTE-IDENTICAL to the pre-refactor inline output
// for the same user+session+key (EdDSA signing is deterministic, so equality
// is exact), and it verifies under the signing key. The response's JTI
// (storeKey) equals the fixed jti.
//
// REVERT-PROOF: swapping the default JWT minter for one that drops a claim
// (see TestIssueForSession_Equivalence_DroppedClaimBreaksIt) changes the
// claims segment, so this exact-equality assertion FAILS — the seam is proven
// load-bearing, not a hollow relabel.
func TestIssueForSession_Equivalence_ByteIdentical(t *testing.T) {
	fixedNow := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	fixedJTI := "0192aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"
	svc, priv, pub, kid := edEquivFixture(t, fixedNow, fixedJTI)
	user, session := newUserAndSession(t)

	resp, err := svc.IssueForSession(context.Background(), user, session)
	if err != nil {
		t.Fatalf("IssueForSession: %v", err)
	}

	golden := expectedInlineToken(t, priv, kid, "https://idp.test", fixedJTI, fixedNow, fixedNow.Add(time.Hour), user, session)
	if resp.AccessToken != golden {
		t.Fatalf("wire token differs from pre-A-4 inline output:\n got  %s\n want %s", resp.AccessToken, golden)
	}
	if resp.JTI != fixedJTI {
		t.Errorf("storeKey (JTI) = %q, want fixed jti %q", resp.JTI, fixedJTI)
	}
	if !resp.ExpiresAt.Equal(fixedNow.Add(time.Hour)) {
		t.Errorf("ExpiresAt = %v, want %v", resp.ExpiresAt, fixedNow.Add(time.Hour))
	}

	// And it still verifies under the key (alg+kid intact). Pin the
	// parser clock to fixedNow so the deliberately-fixed exp is not
	// treated as expired against wall-clock.
	tok, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithTimeFunc(func() time.Time { return fixedNow }),
	).Parse(resp.AccessToken, func(*jwt.Token) (any, error) { return pub, nil })
	if err != nil || !tok.Valid {
		t.Fatalf("verify: err=%v valid=%v", err, tok.Valid)
	}
	if tok.Header["kid"] != kid {
		t.Errorf("kid = %v, want %q", tok.Header["kid"], kid)
	}
}

// claimDroppingMinter wraps the real JWT minter but deletes one Extra claim
// before delegating — the stand-in for a regressed minter.
type claimDroppingMinter struct {
	inner oidc.AccessTokenMinter
	drop  string
}

func (m claimDroppingMinter) Mint(ctx context.Context, tc oidc.TokenClaims) (string, string, error) {
	if tc.Extra != nil {
		delete(tc.Extra, m.drop)
	}
	return m.inner.Mint(ctx, tc)
}

// TestIssueForSession_Equivalence_DroppedClaimBreaksIt makes the revert-proof
// explicit: with a minter that drops the `email` claim, the produced token is
// NOT byte-identical to the golden (and the email claim is gone) — so the
// equivalence assertion above would fail. This proves the teeth bite.
func TestIssueForSession_Equivalence_DroppedClaimBreaksIt(t *testing.T) {
	fixedNow := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	fixedJTI := "0192aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"
	svc, priv, _, kid := edEquivFixture(t, fixedNow, fixedJTI)
	// Swap in a minter that drops a claim, wrapping the real JWT minter.
	svc.minter = claimDroppingMinter{inner: newJWTAccessTokenMinter(svc.keys), drop: "email"}
	user, session := newUserAndSession(t)

	resp, err := svc.IssueForSession(context.Background(), user, session)
	if err != nil {
		t.Fatalf("IssueForSession: %v", err)
	}

	golden := expectedInlineToken(t, priv, kid, "https://idp.test", fixedJTI, fixedNow, fixedNow.Add(time.Hour), user, session)
	if resp.AccessToken == golden {
		t.Fatalf("dropped-claim minter still produced the golden token — the equivalence test is not load-bearing")
	}
	tok, _, _ := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	if _, present := tok.Claims.(jwt.MapClaims)["email"]; present {
		t.Errorf("email claim should be absent under the dropping minter")
	}
}
