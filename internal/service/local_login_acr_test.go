package service

// local_login_acr_test.go — THE-HONEST-ACR: the session a local login
// creates is stamped with the context ACTUALLY performed — password rung
// with amr [pwd], or the password+TOTP rung with amr [pwd otp] — and never
// anything else. Before this the session carried no acr and the id_token
// could not say how the user authenticated.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func TestLogin_PasswordOnlyStampsPasswordRung(t *testing.T) {
	svc, users := newLoginHarness(t)
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uuid.New(), Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"), EmailVerified: true,
	}}
	result, err := svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "correct"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.Session == nil {
		t.Fatal("no session on the result")
	}
	if result.Session.Acr != auth.ACRPassword {
		t.Fatalf("session acr = %q, want %q (the context performed)", result.Session.Acr, auth.ACRPassword)
	}
	if len(result.Session.Amr) != 1 || result.Session.Amr[0] != auth.AMRPassword {
		t.Fatalf("session amr = %v, want [pwd]", result.Session.Amr)
	}
	if result.Session.EffectiveACR() != auth.ACRPassword {
		t.Fatalf("EffectiveACR = %q", result.Session.EffectiveACR())
	}
}

// RULE: ACR-HONEST-1 — the performed acr always lands: a password+TOTP
// login stamps the TOTP rung, a password-only login never does.
func TestLogin_PasswordPlusTOTPStampsMFARung(t *testing.T) {
	svc, users := newLoginHarness(t)
	secret := freshTOTPSecret(t)
	users.byEmail["alice@example.com"] = []*domain.User{{
		ID: uuid.New(), Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"),
		EmailVerified: true, MFAEnabled: true, MFASecret: &secret,
	}}
	code, _ := computeHOTP(secret, uint64(time.Now().Unix())/uint64(defaultTOTPPeriod), 6)
	result, err := svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "correct", TOTPCode: code})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.Session.Acr != auth.ACRMFA {
		t.Fatalf("session acr = %q, want %q", result.Session.Acr, auth.ACRMFA)
	}
	if len(result.Session.Amr) != 2 || result.Session.Amr[0] != auth.AMRPassword || result.Session.Amr[1] != auth.AMROTP {
		t.Fatalf("session amr = %v, want [pwd otp]", result.Session.Amr)
	}
}
