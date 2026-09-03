package api

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Never-called stubs: discovery only asks TokenService whether the
// agent-communication path is WIRED.
type acDiscoveryAuthRepo struct{}

func (acDiscoveryAuthRepo) Create(context.Context, *domain.AgentCommunicationAuthorization) error {
	return nil
}
func (acDiscoveryAuthRepo) GetByID(context.Context, uuid.UUID, uuid.UUID) (*domain.AgentCommunicationAuthorization, error) {
	return nil, domain.ErrAgentCommunicationAuthorizationNotFound
}
func (acDiscoveryAuthRepo) ListByOrganization(context.Context, uuid.UUID) ([]*domain.AgentCommunicationAuthorization, error) {
	return nil, nil
}
func (acDiscoveryAuthRepo) Revoke(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, *string, time.Time) (bool, error) {
	return false, nil
}

type acDiscoverySAs struct{}

func (acDiscoverySAs) GetByID(context.Context, uuid.UUID) (*domain.ServiceAccount, error) {
	return nil, domain.ErrServiceAccountNotFound
}

type acDiscoveryClients struct{}

func (acDiscoveryClients) GetClientByClientID(context.Context, string) (*domain.Client, error) {
	return nil, domain.ErrClientNotFound
}

type acDiscoveryReplays struct{}

func (acDiscoveryReplays) Mark(context.Context, string, string) (bool, error) { return true, nil }

type acDiscoveryTokens struct{}

func (acDiscoveryTokens) Insert(context.Context, *domain.AgentCommunicationToken) error { return nil }
func (acDiscoveryTokens) ListActiveByAuthorization(context.Context, uuid.UUID, time.Time) ([]domain.AgentCommunicationToken, error) {
	return nil, nil
}
func (acDiscoveryTokens) DeleteExpiredBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}

// TestDiscovery_AdvertisesDPoPAndAuthorizationDetailsOnlyWhenWired pins RFC
// 9449 §5.1 / RFC 9396 §10 advertisement to the presence of the
// agent-communication issuance path (AYGHU-4): absent without it, exact
// values with it, and the closed type list never widens.
func TestDiscovery_AdvertisesDPoPAndAuthorizationDetailsOnlyWhenWired(t *testing.T) {
	without := fullChainDiscovery(t)
	_, hasDPoP := without["dpop_signing_alg_values_supported"]
	_, hasAD := without["authorization_details_types_supported"]
	assert.False(t, hasDPoP, "not advertised when the issuance path is not wired")
	assert.False(t, hasAD)

	intro := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	tokenSvc := service.NewTokenService(nil, stubKeyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"}).
		WithAgentCommunication(service.AgentCommunicationIssuanceDeps{
			Authorizations:   acDiscoveryAuthRepo{},
			ServiceAccounts:  acDiscoverySAs{},
			Clients:          acDiscoveryClients{},
			Replays:          acDiscoveryReplays{},
			IssuedTokens:     acDiscoveryTokens{},
			TokenEndpointURL: "https://idp.test/api/v1/oauth/token",
		})
	require.True(t, tokenSvc.HasAgentCommunication())
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: intro,
		TokenService:         tokenSvc,
		OAuthClientAuth:      stubClientAuth{},
	})
	algs, ok := body["dpop_signing_alg_values_supported"].([]any)
	require.True(t, ok, "dpop_signing_alg_values_supported advertised: %v", body["dpop_signing_alg_values_supported"])
	assert.Contains(t, algs, "ES256")
	assert.Contains(t, algs, "EdDSA")
	assert.Contains(t, algs, "RS256")
	assert.NotContains(t, algs, "HS256")
	assert.NotContains(t, algs, "none")
	assert.Equal(t, []any{"agent_communication"}, body["authorization_details_types_supported"], "exactly the one closed type")
	for _, banned := range []string{"mode", "build", "tier"} {
		_, present := body[banned]
		assert.False(t, present)
	}
}
