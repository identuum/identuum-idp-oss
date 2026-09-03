package api

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Never-called stubs: discovery only asks TokenService whether the
// agent-communication path is WIRED. (internal/api may not import testify —
// the boundary policy — so the assertions below are plain testing.)
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
func (acDiscoveryAuthRepo) HasLiveParticipant(context.Context, uuid.UUID, uuid.UUID, time.Time) (bool, error) {
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

func stringsOf(t *testing.T, v any, key string) []string {
	t.Helper()
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("%s: expected a JSON array, got %T (%v)", key, v, v)
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("%s: non-string member %v", key, item)
		}
		out = append(out, s)
	}
	return out
}

// TestDiscovery_AdvertisesDPoPAndAuthorizationDetailsOnlyWhenWired pins RFC
// 9449 §5.1 / RFC 9396 §10 advertisement to the presence of the
// agent-communication issuance path (AYGHU-4): absent without it, exact
// values with it, and the closed type list never widens.
func TestDiscovery_AdvertisesDPoPAndAuthorizationDetailsOnlyWhenWired(t *testing.T) {
	without := fullChainDiscovery(t)
	if _, has := without["dpop_signing_alg_values_supported"]; has {
		t.Errorf("dpop_signing_alg_values_supported advertised without the issuance path wired")
	}
	if _, has := without["authorization_details_types_supported"]; has {
		t.Errorf("authorization_details_types_supported advertised without the issuance path wired")
	}

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
	if !tokenSvc.HasAgentCommunication() {
		t.Fatalf("token service must report the agent-communication path as wired")
	}
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: intro,
		TokenService:         tokenSvc,
		OAuthClientAuth:      stubClientAuth{},
	})
	algs := stringsOf(t, body["dpop_signing_alg_values_supported"], "dpop_signing_alg_values_supported")
	for _, want := range []string{"ES256", "EdDSA", "RS256"} {
		if !slices.Contains(algs, want) {
			t.Errorf("dpop_signing_alg_values_supported missing %s: %v", want, algs)
		}
	}
	for _, banned := range []string{"HS256", "none"} {
		if slices.Contains(algs, banned) {
			t.Errorf("dpop_signing_alg_values_supported must not list %s: %v", banned, algs)
		}
	}
	types := stringsOf(t, body["authorization_details_types_supported"], "authorization_details_types_supported")
	if len(types) != 1 || types[0] != "agent_communication" {
		t.Errorf("authorization_details_types_supported = %v, want exactly [agent_communication]", types)
	}
	for _, banned := range []string{"mode", "build", "tier"} {
		if _, present := body[banned]; present {
			t.Errorf("non-standard top-level discovery key %q present", banned)
		}
	}
}
