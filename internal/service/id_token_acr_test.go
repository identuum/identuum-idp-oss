package service

// id_token_acr_test.go — THE-HONEST-ACR: the id_token acr is the session's
// EFFECTIVE context — the stamped login rung, or the rung a recorded step-up
// uplifted it to — and is absent when the session carries none. A requested
// acr never reaches this path; nothing here can fabricate one.

import (
	"context"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/auth"
)

func TestIDToken_ACRIsThePerformedContext(t *testing.T) {
	svc, _ := newIDTokenSvc(t)
	user := newIDTokenUser()

	t.Run("password login → acr password, amr [pwd]", func(t *testing.T) {
		session := newIDTokenSession()
		session.Acr, session.Amr = auth.LoginContext(false)
		resp, err := svc.Issue(context.Background(), IDTokenInput{User: user, Session: session, Audience: "cli-1", Nonce: "n", Scope: "openid"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		claims, _ := parseIDToken(t, resp.IDToken)
		if claims["acr"] != auth.ACRPassword {
			t.Fatalf("acr = %v, want %q", claims["acr"], auth.ACRPassword)
		}
		amr, _ := claims["amr"].([]any)
		if len(amr) != 1 || amr[0] != auth.AMRPassword {
			t.Fatalf("amr = %v, want [pwd]", claims["amr"])
		}
	})

	t.Run("password+TOTP login → acr mfa, amr [pwd otp]", func(t *testing.T) {
		session := newIDTokenSession()
		session.Acr, session.Amr = auth.LoginContext(true)
		resp, err := svc.Issue(context.Background(), IDTokenInput{User: user, Session: session, Audience: "cli-1", Nonce: "n", Scope: "openid"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		claims, _ := parseIDToken(t, resp.IDToken)
		if claims["acr"] != auth.ACRMFA {
			t.Fatalf("acr = %v, want %q", claims["acr"], auth.ACRMFA)
		}
		amr, _ := claims["amr"].([]any)
		if len(amr) != 2 || amr[0] != auth.AMRPassword || amr[1] != auth.AMROTP {
			t.Fatalf("amr = %v, want [pwd otp]", claims["amr"])
		}
	})

	// RULE: ACR-HONEST-1 — a recorded step-up (LastACRUpliftAt/Value written
	// by the ceremony) is what raises the token's acr; the amr gains otp.
	t.Run("password session + recorded TOTP uplift → acr mfa, amr [pwd otp]", func(t *testing.T) {
		session := newIDTokenSession()
		session.Acr, session.Amr = auth.LoginContext(false)
		session.RecordACRUplift(time.Now().UTC(), auth.ACRMFA)
		resp, err := svc.Issue(context.Background(), IDTokenInput{User: user, Session: session, Audience: "cli-1", Nonce: "n", Scope: "openid"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		claims, _ := parseIDToken(t, resp.IDToken)
		if claims["acr"] != auth.ACRMFA {
			t.Fatalf("acr = %v, want %q after a recorded uplift", claims["acr"], auth.ACRMFA)
		}
		amr, _ := claims["amr"].([]any)
		if len(amr) != 2 || amr[1] != auth.AMROTP {
			t.Fatalf("amr = %v, want [pwd otp]", claims["amr"])
		}
	})

	t.Run("unstamped session → no acr claim (never fabricated)", func(t *testing.T) {
		session := newIDTokenSession()
		session.Acr, session.Amr = "", nil
		resp, err := svc.Issue(context.Background(), IDTokenInput{User: user, Session: session, Audience: "cli-1", Nonce: "n", Scope: "openid"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		claims, _ := parseIDToken(t, resp.IDToken)
		if v, present := claims["acr"]; present {
			t.Fatalf("acr = %v, want absent for a session with no performed context", v)
		}
	})
}
