package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// D-026: an app an org_admin marked "skip consent" signs the user in silently
// only for identity — openid, profile, email — and only when it is a
// confidential app created in the console. Anything else shows the consent
// screen: a public app, an app created through dynamic client registration, a
// scope beyond identity, an API resource (audience).
func TestAuthorize_SkipConsentCoversOnlyIdentity(t *testing.T) {
	_, challenge := authorizeChallenge(t)

	harness := func(t *testing.T, mutate func(*domain.Client)) (*AuthorizeService, *domain.Principal) {
		t.Helper()
		codes := NewAuthorizationCodeService(nil, newAuthCodeRepo(), AuthorizationCodeServiceOptions{TTL: time.Hour})
		client := &domain.Client{
			ClientID:     "cli-1",
			Name:         "Test client",
			RedirectURIs: []string{"https://app.example.com/cb"},
			SkipConsent:  true,
		}
		mutate(client)
		sess := &fakeAuthorizeSessionLookup{session: &domain.Session{
			ID: uuid.New(), UserID: uuid.New(), IsValid: true,
			CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
		}}
		// No consent service is wired: anything that does not skip consent is
		// ErrAuthorizeConsentRequired.
		svc := NewAuthorizeService(nil, &fakeAuthorizeClientLookup{client: client}, codes,
			AuthorizeServiceOptions{Issuer: "https://idp.test"}).WithSessionLookup(sess)
		return svc, authorizePrincipal(sess.session.ID)
	}

	cases := []struct {
		name         string
		mutate       func(*domain.Client)
		scope        string
		audience     string
		claims       string // the OIDC Core §5.5 claims parameter
		wantSkipped  bool
		wantConsentD bool // consent screen expected
	}{
		{name: "a claims request for profile and email claims is silent", mutate: func(*domain.Client) {}, scope: "openid", claims: `{"userinfo":{"name":null,"email":null},"id_token":{"email_verified":null}}`, wantSkipped: true},
		{name: "a claims request for the phone number shows consent", mutate: func(*domain.Client) {}, scope: "openid", claims: `{"userinfo":{"phone_number":null}}`, wantConsentD: true},
		{name: "a claims request for the address in the id_token shows consent", mutate: func(*domain.Client) {}, scope: "openid profile", claims: `{"id_token":{"address":null}}`, wantConsentD: true},
		{name: "identity scopes are silent", mutate: func(*domain.Client) {}, scope: "openid profile email", wantSkipped: true},
		{name: "openid alone is silent", mutate: func(*domain.Client) {}, scope: "openid", wantSkipped: true},
		{name: "offline_access shows consent", mutate: func(*domain.Client) {}, scope: "openid offline_access", wantConsentD: true},
		{name: "an API scope shows consent", mutate: func(*domain.Client) {}, scope: "openid profile read:orders", wantConsentD: true},
		{name: "an API resource shows consent", mutate: func(*domain.Client) {}, scope: "openid", audience: "https://api.example.com", wantConsentD: true},
		{name: "a public app shows consent", mutate: func(c *domain.Client) { c.IsPublic = true }, scope: "openid profile", wantConsentD: true},
		{name: "a dynamically registered app shows consent", mutate: func(c *domain.Client) { c.DynamicallyRegistered = true }, scope: "openid profile", wantConsentD: true},
		{name: "an app not marked skip shows consent", mutate: func(c *domain.Client) { c.SkipConsent = false }, scope: "openid profile", wantConsentD: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, principal := harness(t, tc.mutate)
			req := newAuthorizeRequest(challenge, principal)
			req.Scope = tc.scope
			req.Audience = tc.audience
			req.Claims = tc.claims
			res, err := svc.Authorize(context.Background(), req)
			if tc.wantConsentD {
				if !errors.Is(err, ErrAuthorizeConsentRequired) {
					t.Fatalf("err=%v, want ErrAuthorizeConsentRequired", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("a silent sign-in: %v", err)
			}
			if res.ConsentSkipped != tc.wantSkipped {
				t.Errorf("ConsentSkipped=%v, want %v", res.ConsentSkipped, tc.wantSkipped)
			}
		})
	}
}
