package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// OIDC RP-Initiated Logout 1.0 §2: the OP SHOULD accept an id_token_hint whose
// exp has passed — the person is logging out because they have been away. The
// signature and the issuer are still verified; only the lifetime is not held
// against a hint used to END a session. The strict Verify is unchanged.

func TestVerifyForLogout_AcceptsAnExpiredHintButNothingElseWrong(t *testing.T) {
	ctx := context.Background()
	v, priv, kid := newVerifierHarness(t)
	sid, sub := uuid.New(), uuid.New()
	claims := func(mut func(jwt.MapClaims)) string {
		c := jwt.MapClaims{
			"iss": "https://idp.test", "sub": sub.String(), "aud": "cli-1", "sid": sid.String(),
			"exp": time.Now().Add(-48 * time.Hour).Unix(), "iat": time.Now().Add(-49 * time.Hour).Unix(),
		}
		if mut != nil {
			mut(c)
		}
		return mintIDToken(t, kid, priv, c)
	}

	expired := claims(nil)
	if _, err := v.Verify(ctx, expired); !errors.Is(err, ErrIDTokenHintExpired) {
		t.Fatalf("PREMISE: the strict Verify must still refuse an expired hint: %v", err)
	}
	got, err := v.VerifyForLogout(ctx, expired)
	if err != nil {
		t.Fatalf("VerifyForLogout(expired): %v", err)
	}
	if got.SessionID != sid || got.Subject != sub || len(got.Audience) != 1 || got.Audience[0] != "cli-1" {
		t.Errorf("claims = %+v; want the session, subject and audience of the hint", got)
	}

	if _, err := v.VerifyForLogout(ctx, claims(func(c jwt.MapClaims) { c["iss"] = "https://evil.test" })); !errors.Is(err, ErrIDTokenHintIssuerMismatch) {
		t.Errorf("a foreign issuer: err=%v, want ErrIDTokenHintIssuerMismatch", err)
	}
	if _, err := v.VerifyForLogout(ctx, expired[:len(expired)-4]+"AAAA"); err == nil {
		t.Error("a hint with a tampered signature must still be refused")
	}
	if _, err := v.VerifyForLogout(ctx, "not-a-jwt"); err == nil {
		t.Error("garbage must still be refused")
	}
	if _, err := v.VerifyForLogout(ctx, ""); !errors.Is(err, ErrIDTokenHintMalformed) {
		t.Errorf("empty: err=%v, want ErrIDTokenHintMalformed", err)
	}
}
