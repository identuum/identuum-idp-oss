package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// H8: a client_credentials request names the API resource its token is for.
// The client's allowed audiences were stored and shown but never enforced, so
// any client could mint a token for any active resource of any tenant. The
// audience must be in the client's allowed list AND belong to the client's own
// organization.
func TestIssueClientCredentials_AudienceMustBeAllowedAndOwnedByTheClientsOrganization(t *testing.T) {
	orgA, orgB := uuid.New(), uuid.New()
	const aud = "https://billing.example.com"

	run := func(t *testing.T, clientOrg uuid.UUID, allowed []string, resourceOrg uuid.UUID) error {
		t.Helper()
		ed := genEdDSAKey(t, "kid-eddsa")
		provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
		res := newActiveResource(t, aud, "billing:read")
		res.OrganizationID = resourceOrg
		lookup := &stubAudienceLookup{resources: map[string]*domain.APIResource{aud: res}}
		svc := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).WithAudienceLookup(lookup)
		client := newConfidentialOAuthClient()
		client.OrganizationID = clientOrg
		client.AllowedAudiences = allowed
		_, err := svc.IssueClientCredentials(context.Background(), client, ClientCredentialsRequest{
			GrantType: "client_credentials", RequestedAudience: aud, RequestedScope: "billing:read",
		})
		return err
	}

	t.Run("allowed and owned by the client's organization", func(t *testing.T) {
		if err := run(t, orgA, []string{aud}, orgA); err != nil {
			t.Errorf("a permitted audience: %v", err)
		}
	})
	t.Run("not in the client's allowed list", func(t *testing.T) {
		if err := run(t, orgA, []string{"https://other.example.com"}, orgA); !errors.Is(err, ErrTokenServiceInvalidTarget) {
			t.Errorf("err=%v, want ErrTokenServiceInvalidTarget", err)
		}
	})
	t.Run("no allowed list at all", func(t *testing.T) {
		if err := run(t, orgA, nil, orgA); !errors.Is(err, ErrTokenServiceInvalidTarget) {
			t.Errorf("err=%v, want ErrTokenServiceInvalidTarget", err)
		}
	})
	t.Run("allowed by the client but another organization's resource", func(t *testing.T) {
		if err := run(t, orgA, []string{aud}, orgB); !errors.Is(err, ErrTokenServiceInvalidTarget) {
			t.Errorf("err=%v, want ErrTokenServiceInvalidTarget", err)
		}
	})
	t.Run("a client with no organization cannot reach a tenant's resource", func(t *testing.T) {
		if err := run(t, uuid.Nil, []string{aud}, orgA); !errors.Is(err, ErrTokenServiceInvalidTarget) {
			t.Errorf("err=%v, want ErrTokenServiceInvalidTarget", err)
		}
	})
}
