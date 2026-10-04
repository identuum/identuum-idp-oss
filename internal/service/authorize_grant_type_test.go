package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// An app that registered its grant types without authorization_code (for
// example client_credentials only) gets no code at /authorize: the token
// endpoint would refuse to exchange it, so issuing one only leaves a live
// code behind. The refusal is redirect-safe unauthorized_client (RFC 6749
// §4.1.2.1). An app that names no grant types (console apps, apps
// registered before grant types were stored) is unrestricted.
func TestAuthorize_AnAppNotRegisteredForTheCodeGrantGetsNoCode(t *testing.T) {
	_, challenge := authorizeChallenge(t)
	for _, tc := range []struct {
		name   string
		grants []string
		want   error
	}{
		{"client_credentials only", []string{"client_credentials"}, ErrAuthorizeUnauthorizedClient},
		{"refresh_token only", []string{"refresh_token"}, ErrAuthorizeUnauthorizedClient},
		{"authorization_code registered", []string{"authorization_code", "refresh_token"}, nil},
		{"no grant types stored", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			codes := NewAuthorizationCodeService(nil, newAuthCodeRepo(), AuthorizationCodeServiceOptions{TTL: time.Hour})
			client := &domain.Client{
				ClientID: "cli-1", Name: "Test client", RedirectURIs: []string{"https://app.example.com/cb"},
				SkipConsent: true, GrantTypes: tc.grants,
			}
			sess := &fakeAuthorizeSessionLookup{session: &domain.Session{
				ID: uuid.New(), UserID: uuid.New(), IsValid: true,
				CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
			}}
			svc := NewAuthorizeService(nil, &fakeAuthorizeClientLookup{client: client}, codes,
				AuthorizeServiceOptions{Issuer: "https://idp.test"}).WithSessionLookup(sess)
			req := newAuthorizeRequest(challenge, authorizePrincipal(sess.session.ID))
			req.Scope = "openid"
			_, err := svc.Authorize(context.Background(), req)
			if tc.want == nil {
				if errors.Is(err, ErrAuthorizeUnauthorizedClient) {
					t.Fatalf("err = %v, want the grant check passed", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
