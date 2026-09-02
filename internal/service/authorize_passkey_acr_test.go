package service

// authorize_passkey_acr_test.go — THE-PHISHING-RESISTANT-ACR: the acr_values
// gate offers the CHEAPEST ceremony that reaches the requested rung — TOTP
// for the mfa rung, a passkey for the phishing-resistant rung (or for the mfa
// rung when the user holds a passkey but no TOTP) — and refuses honestly
// when none does. Ranking covers downward only.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type fakePasskeyLookup struct{ creds map[uuid.UUID]int }

func (f fakePasskeyLookup) ListCredentials(_ context.Context, userID uuid.UUID) ([]*domain.WebAuthnCredential, error) {
	out := make([]*domain.WebAuthnCredential, f.creds[userID])
	for i := range out {
		out[i] = &domain.WebAuthnCredential{}
	}
	return out, nil
}

// passkeyHarness: a session at sessionACR for a user with (or without) TOTP
// and with n passkeys.
func passkeyHarness(t *testing.T, sessionACR string, totp bool, passkeys int) (*AuthorizeService, *inMemoryAuthCodeRepo, *domain.Principal) {
	t.Helper()
	svc, repo, principal := acrHarness(t, sessionACR, totp)
	svc.WithPasskeyLookup(fakePasskeyLookup{creds: map[uuid.UUID]int{principal.UserID: passkeys}})
	return svc, repo, principal
}

func wantStepUp(t *testing.T, err error, method string) {
	t.Helper()
	var su *StepUpRequiredError
	if !errors.As(err, &su) || !errors.Is(err, ErrAuthorizeStepUpRequired) {
		t.Fatalf("err = %v, want a StepUpRequiredError", err)
	}
	if su.Method != method {
		t.Fatalf("step-up method = %q, want %q", su.Method, method)
	}
}

func TestAuthorize_ACRValues_PasskeyStepUp(t *testing.T) {
	t.Run("phishing-resistant requested, password session, passkey held → passkey step-up, no code", func(t *testing.T) {
		svc, repo, principal := passkeyHarness(t, auth.ACRPassword, false, 1)
		_, err := authorizeWithACR(t, svc, principal, auth.ACRPhishingResistant)
		wantStepUp(t, err, StepUpMethodPasskey)
		if len(repo.byID) != 0 {
			t.Fatalf("codes=%d, want 0", len(repo.byID))
		}
	})
	t.Run("phishing-resistant requested, TOTP-only user → unmet, no code", func(t *testing.T) {
		svc, repo, principal := passkeyHarness(t, auth.ACRMFA, true, 0)
		if _, err := authorizeWithACR(t, svc, principal, auth.ACRPhishingResistant); !errors.Is(err, ErrAuthorizeUnmetAuthenticationRequirements) {
			t.Fatalf("err = %v, want unmet", err)
		}
		if len(repo.byID) != 0 {
			t.Fatalf("codes=%d, want 0", len(repo.byID))
		}
	})
	t.Run("phishing-resistant requested, no passkey lookup wired → unmet", func(t *testing.T) {
		svc, _, principal := acrHarness(t, auth.ACRPassword, true)
		if _, err := authorizeWithACR(t, svc, principal, auth.ACRPhishingResistant); !errors.Is(err, ErrAuthorizeUnmetAuthenticationRequirements) {
			t.Fatalf("err = %v, want unmet", err)
		}
	})
	t.Run("mfa requested, passkey-only user (no TOTP) → passkey step-up (higher covers lower)", func(t *testing.T) {
		svc, _, principal := passkeyHarness(t, auth.ACRPassword, false, 2)
		_, err := authorizeWithACR(t, svc, principal, auth.ACRMFA)
		wantStepUp(t, err, StepUpMethodPasskey)
	})
	t.Run("mfa requested, TOTP and passkey held → TOTP (the cheapest ceremony that reaches it)", func(t *testing.T) {
		svc, _, principal := passkeyHarness(t, auth.ACRPassword, true, 1)
		_, err := authorizeWithACR(t, svc, principal, auth.ACRMFA)
		wantStepUp(t, err, StepUpMethodTOTP)
	})
}

// RULE: ACR-HONEST-2 (ranking) — a higher performed rung covers a lower
// request; a lower one never covers a higher request.
func TestAuthorize_ACRValues_RankingCoversDownwardOnly(t *testing.T) {
	for _, requested := range []string{auth.ACRPassword, auth.ACRMFA, auth.ACRPhishingResistant} {
		svc, repo, principal := passkeyHarness(t, auth.ACRPhishingResistant, false, 0)
		if _, err := authorizeWithACR(t, svc, principal, requested); err != nil {
			t.Fatalf("phishing-resistant session, request %s: err = %v, want a code", requested, err)
		}
		if len(repo.byID) != 1 {
			t.Fatalf("codes=%d, want 1", len(repo.byID))
		}
	}
	// A recorded passkey uplift on a password session behaves the same.
	svc, repo, sess := newAuthorizeHarness(t, true)
	principal := authorizePrincipal(sess.session.ID)
	sess.session.Acr = auth.ACRPassword
	sess.session.RecordACRUplift(sess.session.CreatedAt, auth.ACRPhishingResistant)
	if _, err := authorizeWithACR(t, svc, principal, auth.ACRMFA); err != nil || len(repo.byID) != 1 {
		t.Fatalf("uplifted-to-phishing-resistant session, request mfa: err=%v codes=%d, want a code", err, len(repo.byID))
	}
	// Never the reverse: mfa does not cover phishing-resistant; password does
	// not cover mfa — with no ceremony available both are unmet, no code.
	for _, tc := range []struct{ session, requested string }{
		{auth.ACRMFA, auth.ACRPhishingResistant},
		{auth.ACRPassword, auth.ACRMFA},
	} {
		svc, repo, principal := passkeyHarness(t, tc.session, false, 0)
		if _, err := authorizeWithACR(t, svc, principal, tc.requested); !errors.Is(err, ErrAuthorizeUnmetAuthenticationRequirements) {
			t.Fatalf("%s session, request %s: err = %v, want unmet", tc.session, tc.requested, err)
		}
		if len(repo.byID) != 0 {
			t.Fatalf("codes=%d, want 0", len(repo.byID))
		}
	}
}
