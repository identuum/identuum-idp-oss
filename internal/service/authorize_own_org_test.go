package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func ownOrgHarness(t *testing.T, clientOrg *uuid.UUID) (*AuthorizeService, *fakeAuthorizeSessionLookup) {
	t.Helper()
	codes := NewAuthorizationCodeService(nil, newAuthCodeRepo(), AuthorizationCodeServiceOptions{TTL: time.Hour})
	clients := &fakeAuthorizeClientLookup{client: &domain.Client{
		ClientID:       "cli-1",
		Name:           "Test client",
		RedirectURIs:   []string{"https://app.example.com/cb"},
		SkipConsent:    true,
		OrganizationID: clientOrg,
	}}
	sess := &fakeAuthorizeSessionLookup{session: &domain.Session{
		ID: uuid.New(), UserID: uuid.New(), IsValid: true,
		CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
	}}
	svc := NewAuthorizeService(nil, clients, codes, AuthorizeServiceOptions{Issuer: "https://idp.test"}).
		WithSessionLookup(sess)
	return svc, sess
}

// D-027: a user signs in only to apps of their own organization. A code is
// never issued for an app registered by another organization, and the refusal
// is the same answer as an unknown client, so it names nothing about the
// other tenant. An app with no organization (registered by the site
// administrator) is not tenant-owned and stays available.
func TestAuthorize_AppOfAnotherOrganizationRefused(t *testing.T) {
	appOrg, userOrg := uuid.New(), uuid.New()
	_, challenge := authorizeChallenge(t)

	svc, sess := ownOrgHarness(t, &appOrg)
	p := authorizePrincipal(sess.session.ID)
	p.OrganizationID = userOrg
	if _, err := svc.Authorize(context.Background(), newAuthorizeRequest(challenge, p)); !errors.Is(err, ErrAuthorizeInvalidClient) {
		t.Errorf("a user of another organization: err=%v, want ErrAuthorizeInvalidClient", err)
	}

	svc, sess = ownOrgHarness(t, &appOrg)
	p = authorizePrincipal(sess.session.ID)
	p.OrganizationID = appOrg
	if _, err := svc.Authorize(context.Background(), newAuthorizeRequest(challenge, p)); err != nil {
		t.Errorf("a user of the app's own organization must be served: %v", err)
	}

	svc, sess = ownOrgHarness(t, nil)
	p = authorizePrincipal(sess.session.ID)
	if _, err := svc.Authorize(context.Background(), newAuthorizeRequest(challenge, p)); err != nil {
		t.Errorf("an app with no organization must stay available: %v", err)
	}
}
