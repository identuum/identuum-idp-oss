package service

// OSS-PUBLIC-CLIENT-PKCE-OPTION (owner decision 2026-10-10): "PKCE required" is
// a per-client setting, on by default for every client. An org_admin may turn
// it off for one public client; that client may then omit the code challenge,
// while a challenge it sends is still S256-only and verified at the token
// endpoint. Confidential clients are unchanged, and the zero value of the
// domain field keeps PKCE required.

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// newAuthorizePKCEOptOutHarness returns the service, its code service and a
// principal whose consent for the client is on record (a public client never
// skips consent, D-026).
func newAuthorizePKCEOptOutHarness(t *testing.T, isPublic, optOut bool) (*AuthorizeService, *AuthorizationCodeService, *domain.Principal) {
	t.Helper()
	codes := NewAuthorizationCodeService(nil, newAuthCodeRepo(), AuthorizationCodeServiceOptions{TTL: time.Hour})
	clients := &fakeAuthorizeClientLookup{client: &domain.Client{
		ClientID:     "cli-1",
		Name:         "Test client",
		RedirectURIs: []string{"https://app.example.com/cb"},
		SkipConsent:  true,
		IsPublic:     isPublic,
		PKCEOptOut:   optOut,
	}}
	sess := &fakeAuthorizeSessionLookup{session: &domain.Session{
		ID: uuid.New(), UserID: uuid.New(), IsValid: true,
		CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
	}}
	consent := NewConsentService(nil, newConsentRepo())
	svc := NewAuthorizeService(nil, clients, codes, AuthorizeServiceOptions{Issuer: "https://idp.test"}).
		WithSessionLookup(sess).WithConsentService(consent)
	principal := authorizePrincipal(sess.session.ID)
	if _, err := consent.Grant(context.Background(), GrantConsentInput{UserID: principal.UserID, ClientID: "cli-1", Scope: "openid profile"}); err != nil {
		t.Fatalf("grant consent: %v", err)
	}
	return svc, codes, principal
}

func TestAuthorize_PublicClientWithPKCEOffGetsACodeWithoutAChallenge(t *testing.T) {
	svc, codes, p := newAuthorizePKCEOptOutHarness(t, true, true)
	req := newAuthorizeRequest("", p)
	req.CodeChallengeMethod = ""
	req.State = "st-1"
	result, err := svc.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("authorize: %v — a public client with PKCE off may omit the challenge", err)
	}
	if !result.PublicClientWithoutPKCE {
		t.Error("PublicClientWithoutPKCE = false; the code_issued audit must name a code issued without PKCE")
	}
	u, _ := url.Parse(result.RedirectURL)
	if u.Query().Get("state") != "st-1" || u.Query().Get("code") != result.Code {
		t.Errorf("redirect = %q; want the code and the state", result.RedirectURL)
	}
	// The code is bound to no challenge: it redeems with no verifier and
	// refuses a gratuitous one.
	if _, err := codes.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code: result.Code, ClientID: "cli-1", RedirectURI: "https://app.example.com/cb", CodeVerifier: "gratuitous",
	}); !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Errorf("gratuitous verifier: err = %v, want ErrAuthCodeInvalidGrant", err)
	}
}

func TestAuthorize_PublicClientWithPKCEOffStillHasItsChallengeJudgedAndVerified(t *testing.T) {
	svc, codes, p := newAuthorizePKCEOptOutHarness(t, true, true)

	plain := newAuthorizeRequest("some-challenge", p)
	plain.CodeChallengeMethod = "plain"
	if _, err := svc.Authorize(context.Background(), plain); !errors.Is(err, ErrAuthorizeUnsupportedChallenge) {
		t.Errorf("plain: err = %v, want ErrAuthorizeUnsupportedChallenge", err)
	}
	methodOnly := newAuthorizeRequest("", p)
	methodOnly.CodeChallengeMethod = "S256"
	if _, err := svc.Authorize(context.Background(), methodOnly); !errors.Is(err, ErrAuthorizeMissingParameters) {
		t.Errorf("method without challenge: err = %v, want ErrAuthorizeMissingParameters", err)
	}

	verifier, challenge := pkceVerifierAndChallenge(t)
	result, err := svc.Authorize(context.Background(), newAuthorizeRequest(challenge, p))
	if err != nil {
		t.Fatalf("authorize with S256: %v", err)
	}
	if result.PublicClientWithoutPKCE {
		t.Error("PublicClientWithoutPKCE = true for a code bound to a challenge")
	}
	if _, err := codes.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code: result.Code, ClientID: "cli-1", RedirectURI: "https://app.example.com/cb",
	}); !errors.Is(err, ErrAuthCodeInvalidGrant) {
		t.Errorf("bound challenge, no verifier: err = %v, want ErrAuthCodeInvalidGrant", err)
	}
	result, err = svc.Authorize(context.Background(), newAuthorizeRequest(challenge, p))
	if err != nil {
		t.Fatalf("authorize with S256: %v", err)
	}
	if _, err := codes.Consume(context.Background(), ConsumeAuthorizationCodeInput{
		Code: result.Code, ClientID: "cli-1", RedirectURI: "https://app.example.com/cb", CodeVerifier: verifier,
	}); err != nil {
		t.Errorf("bound challenge, right verifier: %v", err)
	}
}

func TestAuthorize_PublicClientWithPKCEOffStillNeedsAnExactRedirectURI(t *testing.T) {
	svc, _, p := newAuthorizePKCEOptOutHarness(t, true, true)
	req := newAuthorizeRequest("", p)
	req.CodeChallengeMethod = ""
	req.RedirectURI = "https://app.example.com/cb/other"
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeInvalidRedirectURI) {
		t.Errorf("err = %v, want ErrAuthorizeInvalidRedirectURI", err)
	}
}

// The default — the zero value of domain.Client.PKCEOptOut — keeps PKCE
// required for a public client; a confidential client is unchanged whatever
// the field says.
func TestAuthorize_PKCERequiredByDefault_ConfidentialUnchanged(t *testing.T) {
	svc, _, p := newAuthorizePKCEOptOutHarness(t, true, false)
	req := newAuthorizeRequest("", p)
	req.CodeChallengeMethod = ""
	if _, err := svc.Authorize(context.Background(), req); !errors.Is(err, ErrAuthorizeMissingParameters) {
		t.Errorf("default public client: err = %v, want ErrAuthorizeMissingParameters", err)
	}
	for _, optOut := range []bool{false, true} {
		svc, _, p := newAuthorizePKCEOptOutHarness(t, false, optOut)
		req := newAuthorizeRequest("", p)
		req.CodeChallengeMethod = ""
		result, err := svc.Authorize(context.Background(), req)
		if err != nil {
			t.Fatalf("confidential (opt-out=%v): %v", optOut, err)
		}
		if result.PublicClientWithoutPKCE {
			t.Errorf("confidential (opt-out=%v): PublicClientWithoutPKCE = true", optOut)
		}
		plain := newAuthorizeRequest("c", p)
		plain.CodeChallengeMethod = "plain"
		if _, err := svc.Authorize(context.Background(), plain); !errors.Is(err, ErrAuthorizeUnsupportedChallenge) {
			t.Errorf("confidential (opt-out=%v) plain: err = %v", optOut, err)
		}
	}
}
