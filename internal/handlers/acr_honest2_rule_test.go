package handlers

// acr_honest2_rule_test.go — RULE: ACR-HONEST-2 (THE-PHISHING-RESISTANT-ACR).
//
// One check, three prongs, against production wiring:
//
//  1. A phishing-resistant request never lands without a verified
//     assertion: /authorize mints NO code for it on a lower-rung session —
//     it asks for the passkey ceremony (passkey held) or refuses as unmet
//     (TOTP-only user); the ceremony's finish records the uplift ONLY for an
//     assertion that verifies for the session's own user.
//  2. The performed rung lands: the id_token acr is phishing-resistant for
//     a WebAuthn-login session and for a session uplifted by the ceremony.
//  3. Ranking covers downward only: a phishing-resistant session satisfies
//     requests for mfa and password; an mfa session does not satisfy a
//     phishing-resistant request, a password session does not satisfy mfa.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type acrRulePasskeys struct{ has map[uuid.UUID]bool }

func (p acrRulePasskeys) ListCredentials(_ context.Context, id uuid.UUID) ([]*domain.WebAuthnCredential, error) {
	if p.has[id] {
		return []*domain.WebAuthnCredential{{}}, nil
	}
	return nil, nil
}

// RULE: ACR-HONEST-2
func TestRuleACRHonest2_PhishingResistantNeverLandsUnverified_PerformedLands_RanksDownwardOnly(t *testing.T) {
	principal := authorizePrincipal()
	sessionAt := func(acr string) *domain.Session {
		return &domain.Session{
			ID: principal.SessionID, UserID: principal.UserID, IsValid: true, Acr: acr,
			CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
		}
	}
	client := &domain.Client{ClientID: "cli-1", Name: "Test", RedirectURIs: []string{"https://app.example.com/cb"}, SkipConsent: true, Scope: "openid"}
	authorize := func(t *testing.T, sess *domain.Session, user *domain.User, hasPasskey bool, acrValues string) (*service.AuthorizeResult, error) {
		t.Helper()
		codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
		svc := service.NewAuthorizeService(nil, &fakeAuthorizeClientLookup{client: client}, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"}).
			WithSessionLookup(&fakeSessionLookup{session: sess}).
			WithUserLookup(acrRuleUserLookup{user: user}).
			WithPasskeyLookup(acrRulePasskeys{has: map[uuid.UUID]bool{principal.UserID: hasPasskey}})
		return svc.Authorize(context.Background(), service.AuthorizeRequest{
			ResponseType: "code", ClientID: "cli-1", RedirectURI: "https://app.example.com/cb", Scope: "openid",
			State: "st", Nonce: "n", CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256",
			Principal: principal, AcrValues: acrValues,
		})
	}
	passkeyUser := &domain.User{ID: principal.UserID, Email: "alice@example.com", EmailVerified: true}
	totpOnlyUser := &domain.User{ID: principal.UserID, Email: "alice@example.com", EmailVerified: true, MFAEnabled: true}

	// ── Prong 1a: the gate never mints for a phishing-resistant request on
	// a lower-rung session.
	res, err := authorize(t, sessionAt(service.ACRPassword), passkeyUser, true, service.ACRPhishingResistant)
	var su *service.StepUpRequiredError
	if res != nil || !errors.As(err, &su) || su.Method != service.StepUpMethodPasskey {
		t.Fatalf("phishing-resistant requested, password session, passkey held: res=%v err=%v, want the passkey step-up and no code", res, err)
	}
	res, err = authorize(t, sessionAt(service.ACRMFA), totpOnlyUser, false, service.ACRPhishingResistant)
	if res != nil || !errors.Is(err, service.ErrAuthorizeUnmetAuthenticationRequirements) {
		t.Fatalf("phishing-resistant requested, TOTP-only user: res=%v err=%v, want unmet and no code", res, err)
	}

	// ── Prong 1b: the ceremony records the uplift ONLY for a verified
	// assertion by the session's own user.
	rFail, recFail, _, _ := newPasskeyStepUpEngine(t, &fakeAsserter{finishErr: service.ErrWebAuthnAssertionInvalid})
	if w := postPasskeyFinish(rFail, "live", "ceremony-1", "/api/v1/oauth/authorize?x=1"); w.Code != http.StatusUnauthorized || recFail.calls != 0 {
		t.Fatalf("failed assertion: status=%d uplift calls=%d, want 401 and 0", w.Code, recFail.calls)
	}
	rOther, recOther, _, _ := newPasskeyStepUpEngine(t, &fakeAsserter{finishUser: &domain.User{ID: uuid.New()}})
	if w := postPasskeyFinish(rOther, "live", "ceremony-1", "/api/v1/oauth/authorize?x=1"); w.Code != http.StatusUnauthorized || recOther.calls != 0 {
		t.Fatalf("another user's assertion: status=%d uplift calls=%d, want 401 and 0", w.Code, recOther.calls)
	}
	rOK, recOK, stepSess, _ := newPasskeyStepUpEngine(t, &fakeAsserter{})
	if w := postPasskeyFinish(rOK, "live", "ceremony-1", "/api/v1/oauth/authorize?x=1"); w.Code != http.StatusOK {
		t.Fatalf("verified assertion: status=%d, want 200", w.Code)
	}
	if recOK.calls != 1 || recOK.sessionID != stepSess.ID || recOK.value != service.ACRPhishingResistant || recOK.at.IsZero() {
		t.Fatalf("uplift = calls %d (%s, %s, %v), want 1 (%s, phishing-resistant, non-zero)", recOK.calls, recOK.sessionID, recOK.value, recOK.at, stepSess.ID)
	}

	// ── Prong 2: the performed rung lands in the id_token.
	keys := &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "kid-eddsa")}}
	idTokens := service.NewIDTokenService(nil, keys, service.IDTokenServiceOptions{Issuer: "https://idp.test", TTL: time.Hour})
	issue := func(t *testing.T, sess *domain.Session) map[string]any {
		t.Helper()
		out, err := idTokens.Issue(context.Background(), service.IDTokenInput{User: passkeyUser, Session: sess, Audience: "cli-1", Nonce: "n", Scope: "openid"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return acrRuleJWTClaims(t, out.IDToken)
	}
	if c := issue(t, sessionAt(service.ACRPhishingResistant)); c["acr"] != service.ACRPhishingResistant {
		t.Fatalf("WebAuthn-login session id_token acr = %v, want phishing-resistant", c["acr"])
	}
	uplifted := sessionAt(service.ACRPassword)
	uplifted.Amr = []string{service.AMRPassword}
	uplifted.RecordACRUplift(recOK.at, recOK.value)
	if c := issue(t, uplifted); c["acr"] != service.ACRPhishingResistant {
		t.Fatalf("passkey-uplifted session id_token acr = %v, want phishing-resistant", c["acr"])
	}
	if c := issue(t, sessionAt(service.ACRPassword)); c["acr"] != service.ACRPassword {
		t.Fatalf("password session id_token acr = %v, want password (never the requested rung)", c["acr"])
	}

	// ── Prong 3: ranking covers downward only.
	for _, requested := range []string{service.ACRMFA, service.ACRPassword} {
		if res, err := authorize(t, sessionAt(service.ACRPhishingResistant), totpOnlyUser, false, requested); err != nil || res == nil || res.Code == "" {
			t.Fatalf("phishing-resistant session, request %s: res=%v err=%v, want a code", requested, res, err)
		}
	}
	if res, err := authorize(t, uplifted, passkeyUser, true, service.ACRMFA); err != nil || res == nil || res.Code == "" {
		t.Fatalf("passkey-uplifted session, request mfa: res=%v err=%v, want a code", res, err)
	}
	if res, err := authorize(t, sessionAt(service.ACRMFA), totpOnlyUser, false, service.ACRPhishingResistant); res != nil || !errors.Is(err, service.ErrAuthorizeUnmetAuthenticationRequirements) {
		t.Fatalf("mfa session, request phishing-resistant, no passkey: res=%v err=%v, want unmet", res, err)
	}
	if res, err := authorize(t, sessionAt(service.ACRPassword), passkeyUser, false, service.ACRMFA); res != nil || !errors.Is(err, service.ErrAuthorizeUnmetAuthenticationRequirements) {
		t.Fatalf("password session, request mfa, no ceremony: res=%v err=%v, want unmet", res, err)
	}
}
