package handlers

// acr_honest_rule_test.go — RULE: ACR-HONEST-1 (THE-HONEST-ACR).
//
// One check, three prongs, all against production wiring:
//
//  1. A requested acr never lands unperformed: /authorize with acr_values
//     naming the TOTP rung on a password-rung session mints NO code — it
//     asks for a step-up (TOTP enrolled) or refuses with
//     unmet_authentication_requirements (not enrolled).
//  2. The performed acr always lands: the id_token's acr is the session's
//     effective context (password → password; a recorded uplift → mfa with
//     amr [pwd otp]); a session with no performed context carries no acr.
//  3. Uplift writes LastACRUpliftAt: the step-up ceremony records
//     (session, now, mfa) exactly when the code verifies, never otherwise.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type acrRuleUserLookup struct{ user *domain.User }

func (f acrRuleUserLookup) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if f.user == nil || f.user.ID != id {
		return nil, errors.New("not found")
	}
	return f.user, nil
}

func acrRuleJWTClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	return claims
}

// RULE: ACR-HONEST-1
func TestRuleACRHonest1_RequestedNeverLandsUnperformed_PerformedLands_UpliftWrites(t *testing.T) {
	principal := authorizePrincipal()
	passwordSession := func() *domain.Session {
		s := &domain.Session{
			ID: principal.SessionID, UserID: principal.UserID, IsValid: true,
			CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
		}
		s.Acr, s.Amr = service.LoginContext(false)
		return s
	}
	client := &domain.Client{ClientID: "cli-1", Name: "Test", RedirectURIs: []string{"https://app.example.com/cb"}, SkipConsent: true, Scope: "openid"}
	authorize := func(t *testing.T, sess *domain.Session, user *domain.User, acrValues string) (*service.AuthorizeResult, error) {
		t.Helper()
		codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
		svc := service.NewAuthorizeService(nil, &fakeAuthorizeClientLookup{client: client}, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"}).
			WithSessionLookup(&fakeSessionLookup{session: sess}).
			WithUserLookup(acrRuleUserLookup{user: user})
		return svc.Authorize(context.Background(), service.AuthorizeRequest{
			ResponseType: "code", ClientID: "cli-1", RedirectURI: "https://app.example.com/cb", Scope: "openid",
			State: "st", Nonce: "n", CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256",
			Principal: principal, AcrValues: acrValues,
		})
	}

	// ── Prong 1: requested above performed → no code, ever.
	enrolled := &domain.User{ID: principal.UserID, Email: "alice@example.com", EmailVerified: true, MFAEnabled: true}
	res, err := authorize(t, passwordSession(), enrolled, service.ACRMFA)
	if !errors.Is(err, service.ErrAuthorizeStepUpRequired) || res != nil {
		t.Fatalf("TOTP rung requested on a password session (enrolled): res=%v err=%v, want ErrAuthorizeStepUpRequired and no code", res, err)
	}
	notEnrolled := &domain.User{ID: principal.UserID, Email: "alice@example.com", EmailVerified: true}
	res, err = authorize(t, passwordSession(), notEnrolled, service.ACRMFA)
	if !errors.Is(err, service.ErrAuthorizeUnmetAuthenticationRequirements) || res != nil {
		t.Fatalf("TOTP rung requested on a password session (not enrolled): res=%v err=%v, want ErrAuthorizeUnmetAuthenticationRequirements and no code", res, err)
	}
	// Control: the performed rung satisfies its own request (and the suite's
	// both-advertised-values shape).
	if res, err = authorize(t, passwordSession(), notEnrolled, service.ACRPassword+" "+service.ACRMFA); err != nil || res == nil || res.Code == "" {
		t.Fatalf("password session, acr_values=[password mfa]: res=%v err=%v, want a code", res, err)
	}

	// ── Prong 2: the id_token acr is the performed context, nothing else.
	keys := &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "kid-eddsa")}}
	idTokens := service.NewIDTokenService(nil, keys, service.IDTokenServiceOptions{Issuer: "https://idp.test", TTL: time.Hour})
	issue := func(t *testing.T, sess *domain.Session) map[string]any {
		t.Helper()
		out, err := idTokens.Issue(context.Background(), service.IDTokenInput{User: enrolled, Session: sess, Audience: "cli-1", Nonce: "n", Scope: "openid"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return acrRuleJWTClaims(t, out.IDToken)
	}
	if c := issue(t, passwordSession()); c["acr"] != service.ACRPassword {
		t.Fatalf("password session id_token acr = %v, want %q", c["acr"], service.ACRPassword)
	}
	unstamped := passwordSession()
	unstamped.Acr, unstamped.Amr = "", nil
	if c := issue(t, unstamped); c["acr"] != nil {
		t.Fatalf("unstamped session id_token acr = %v, want absent (never fabricated)", c["acr"])
	}

	// ── Prong 3: the ceremony writes the uplift exactly when the code verifies.
	r, rec, stepSess := newStepUpEngine(t, true)
	if w := postStepUp(r, "live", "000000", "/api/v1/oauth/authorize?x=1"); w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "error=invalid_code") {
		t.Fatalf("wrong code: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	if rec.calls != 0 {
		t.Fatalf("wrong code wrote an uplift (%d call(s))", rec.calls)
	}
	if w := postStepUp(r, "live", "123456", "/api/v1/oauth/authorize?x=1"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/api/v1/oauth/authorize?x=1" {
		t.Fatalf("right code: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	if rec.calls != 1 || rec.sessionID != stepSess.ID || rec.value != service.ACRMFA || rec.at.IsZero() {
		t.Fatalf("uplift record = calls %d (%s, %s, %v), want 1 (%s, %s, non-zero)", rec.calls, rec.sessionID, rec.value, rec.at, stepSess.ID, service.ACRMFA)
	}
	// …and what was written is what the token then carries (prong 2 closes
	// the loop): the same session, uplifted, mints acr mfa / amr [pwd otp].
	uplifted := passwordSession()
	uplifted.RecordACRUplift(rec.at, rec.value)
	if uplifted.LastACRUpliftAt == nil {
		t.Fatal("RecordACRUplift did not set LastACRUpliftAt")
	}
	c := issue(t, uplifted)
	if c["acr"] != service.ACRMFA {
		t.Fatalf("uplifted session id_token acr = %v, want %q", c["acr"], service.ACRMFA)
	}
	amr, _ := c["amr"].([]any)
	if len(amr) != 2 || amr[0] != service.AMRPassword || amr[1] != service.AMROTP {
		t.Fatalf("uplifted session id_token amr = %v, want [pwd otp]", c["amr"])
	}
	// The uplifted session now satisfies the TOTP rung request — the ONLY way
	// a TOTP-rung id_token is ever reached from a password login.
	if res, err = authorize(t, uplifted, enrolled, service.ACRMFA); err != nil || res == nil || res.Code == "" {
		t.Fatalf("uplifted session, acr_values=mfa: res=%v err=%v, want a code", res, err)
	}
}
