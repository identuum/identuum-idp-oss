package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// A code for an API resource (the audience parameter) is minted only for an
// active resource of the app's own organization — the rule client_credentials
// applies. The audience is carried onto the refresh token, so an app of one
// tenant asking here for another tenant's API would reach it at its first
// refresh.
func TestAuthorize_AnAudienceMustBeAnActiveResourceOfTheAppsOrganization(t *testing.T) {
	_, challenge := authorizeChallenge(t)
	orgA, orgB := uuid.New(), uuid.New()

	authorize := func(t *testing.T, appOrg *uuid.UUID, resource *domain.APIResource) error {
		t.Helper()
		codes := NewAuthorizationCodeService(nil, newAuthCodeRepo(), AuthorizationCodeServiceOptions{TTL: time.Hour})
		client := &domain.Client{ClientID: "cli-1", Name: "Test client", RedirectURIs: []string{"https://app.example.com/cb"}, OrganizationID: appOrg}
		sess := &fakeAuthorizeSessionLookup{session: &domain.Session{
			ID: uuid.New(), UserID: uuid.New(), IsValid: true,
			CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
		}}
		// No consent service is wired: a request that passes every check
		// before consent answers ErrAuthorizeConsentRequired.
		svc := NewAuthorizeService(nil, &fakeAuthorizeClientLookup{client: client}, codes, AuthorizeServiceOptions{Issuer: "https://idp.test"}).
			WithSessionLookup(sess).
			WithAudienceLookup(&fakeAudienceLookup{resource: resource})
		principal := authorizePrincipal(sess.session.ID)
		principal.OrganizationID = orgA
		req := newAuthorizeRequest(challenge, principal)
		req.Audience = "https://api.example.com"
		_, err := svc.Authorize(context.Background(), req)
		return err
	}

	if err := authorize(t, &orgA, &domain.APIResource{OrganizationID: orgB, Active: true}); !errors.Is(err, ErrAuthorizeInvalidTarget) {
		t.Errorf("another tenant's API: err=%v, want ErrAuthorizeInvalidTarget", err)
	}
	if err := authorize(t, &orgA, &domain.APIResource{OrganizationID: orgA, Active: false}); !errors.Is(err, ErrAuthorizeInvalidTarget) {
		t.Errorf("an inactive API resource: err=%v, want ErrAuthorizeInvalidTarget", err)
	}
	if err := authorize(t, nil, &domain.APIResource{OrganizationID: orgA, Active: true}); !errors.Is(err, ErrAuthorizeInvalidTarget) {
		t.Errorf("an app of no organization asking for a tenant's API: err=%v, want ErrAuthorizeInvalidTarget", err)
	}
	if err := authorize(t, &orgA, &domain.APIResource{OrganizationID: orgA, Active: true}); !errors.Is(err, ErrAuthorizeConsentRequired) {
		t.Errorf("the app's own active API: err=%v, want to pass to the consent step", err)
	}
}
