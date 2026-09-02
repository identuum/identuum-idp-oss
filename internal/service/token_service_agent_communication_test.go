package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// acReplayFake is an in-memory DPoPProofReplayMarker.
type acReplayFake struct {
	mu   sync.Mutex
	seen map[string]bool
	fail error
	mark int
}

func (f *acReplayFake) Mark(_ context.Context, jkt, jti string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mark++
	if f.fail != nil {
		return false, f.fail
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	k := jkt + "|" + jti
	if f.seen[k] {
		return false, nil
	}
	f.seen[k] = true
	return true, nil
}

// acIssuanceWorld: an AYGHU-1 fixture (org, owner, two agents), one active
// authorization whose participants are enrolled with fresh DPoP keys, and a
// TokenService with the agent-communication path wired.
type acIssuanceWorld struct {
	f       *acFixture
	auth    *domain.AgentCommunicationAuthorization
	keyA    dpopTestKey // initiator (saA / clientA)
	keyB    dpopTestKey // responder (saB / clientB)
	replays *acReplayFake
	tokens  *TokenService
	now     time.Time
}

const acIssuanceTokenEndpoint = "https://idp.test/api/v1/oauth/token"

func newACIssuanceWorld(t *testing.T) *acIssuanceWorld {
	t.Helper()
	f := newACFixture(t)
	w := &acIssuanceWorld{f: f, keyA: newEdDSAProofKey(t), keyB: newES256ProofKey(t), replays: &acReplayFake{}, now: f.now}
	in := f.input()
	in.Participants[0].ProofKeyThumbprint = w.keyA.jkt
	in.Participants[1].ProofKeyThumbprint = w.keyB.jkt
	a, err := f.svc.Create(context.Background(), in)
	require.NoError(t, err)
	w.auth = a

	ed := genEdDSAKey(t, "kid-ac")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	w.tokens = NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).
		WithAgentCommunication(AgentCommunicationIssuanceDeps{
			Authorizations:   f.repo,
			ServiceAccounts:  f.sas,
			Clients:          f.clients,
			Replays:          w.replays,
			TokenEndpointURL: acIssuanceTokenEndpoint,
		})
	w.tokens.now = func() time.Time { return w.now }
	return w
}

func (w *acIssuanceWorld) clientA() *AuthenticatedClient {
	return &AuthenticatedClient{Kind: AuthenticatedClientKindOAuth, ClientID: w.f.clientA.ClientID, AuthRecordID: w.f.clientA.ID, OrganizationID: w.f.org}
}

func (w *acIssuanceWorld) clientB() *AuthenticatedClient {
	return &AuthenticatedClient{Kind: AuthenticatedClientKindOAuth, ClientID: w.f.clientB.ClientID, AuthRecordID: w.f.clientB.ID, OrganizationID: w.f.org}
}

func (w *acIssuanceWorld) aciA() uuid.UUID {
	return w.auth.Participant(domain.AgentCommunicationRoleInitiator).ACI
}
func (w *acIssuanceWorld) aciB() uuid.UUID {
	return w.auth.Participant(domain.AgentCommunicationRoleResponder).ACI
}

func acDetails(authID, aci uuid.UUID) string {
	return fmt.Sprintf(`[{"type":"agent_communication","authorization_id":%q,"aci":%q}]`, authID.String(), aci.String())
}

func (w *acIssuanceWorld) request(t *testing.T, key dpopTestKey, aci uuid.UUID) AgentCommunicationTokenRequest {
	t.Helper()
	return AgentCommunicationTokenRequest{
		GrantType:            "client_credentials",
		RequestedAudience:    w.auth.RelayAudience,
		AuthorizationDetails: acDetails(w.auth.ID, aci),
		DPoPProof:            mintProof(t, key, "POST", acIssuanceTokenEndpoint, w.now, nil),
		HTTPMethod:           "POST",
	}
}

func decodeClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	tok, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	return tok.Claims.(jwt.MapClaims)
}

func TestIssueAgentCommunication_HappyPath_DPoPBoundNoRefresh(t *testing.T) {
	w := newACIssuanceWorld(t)
	resp, rec, err := w.tokens.IssueAgentCommunication(context.Background(), w.clientA(), w.request(t, w.keyA, w.aciA()))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "DPoP", resp.TokenType, "never Bearer")
	assert.Empty(t, resp.RefreshToken, "no refresh token, ever")
	assert.Empty(t, resp.IDToken)
	assert.Equal(t, AgentCommunicationScope, resp.Scope)
	assert.EqualValues(t, 300, resp.ExpiresIn, "default TTL 5 minutes")
	assert.Equal(t, w.auth.ID, rec.AuthorizationID)
	assert.Equal(t, w.aciA(), rec.ACI)
	assert.Equal(t, "initiator", rec.Role)

	c := decodeClaims(t, resp.AccessToken)
	assert.Equal(t, "https://idp.test", c["iss"])
	assert.Equal(t, w.f.saA.ID.String(), c["sub"], "sub is the service-account id")
	assert.Equal(t, w.auth.RelayAudience, c["aud"])
	assert.Equal(t, w.f.clientA.ClientID, c["client_id"])
	assert.Equal(t, AgentCommunicationScope, c["scope"])
	assert.EqualValues(t, w.now.Unix(), c["iat"])
	assert.EqualValues(t, w.now.Unix(), c["nbf"])
	assert.EqualValues(t, w.now.Add(5*time.Minute).Unix(), c["exp"])
	jti, err := uuid.Parse(c["jti"].(string))
	require.NoError(t, err)
	assert.Equal(t, uuid.Version(7), jti.Version())
	cnf, ok := c["cnf"].(map[string]any)
	require.True(t, ok, "cnf present")
	assert.Equal(t, w.keyA.jkt, cnf["jkt"], "cnf.jkt is the enrolled proof-key thumbprint")
	ac := c["agent_communication"].(map[string]any)
	assert.Equal(t, w.auth.ID.String(), ac["authorization_id"])
	assert.Equal(t, w.auth.SessionID.String(), ac["session_id"])
	assert.Equal(t, w.aciA().String(), ac["aci"])
	assert.Equal(t, "initiator", ac["role"])
	assert.Equal(t, "v1", ac["policy_version"])
	assert.Equal(t, w.auth.PolicyDigest, ac["policy_digest"])
	assert.EqualValues(t, w.auth.MaxMessages, ac["max_messages"])
	assert.EqualValues(t, w.auth.MaxMessageSizeBytes, ac["max_message_size_bytes"])
	assert.EqualValues(t, w.auth.ExpiresAt.Unix(), ac["authorization_expires_at"])
	details := c["authorization_details"].([]any)
	require.Len(t, details, 1)
	d := details[0].(map[string]any)
	assert.Equal(t, "agent_communication", d["type"])
	assert.Equal(t, w.aciA().String(), d["aci"])
	for _, forbidden := range []string{"email", "client_secret", "private_key", "capabilities"} {
		_, present := c[forbidden]
		assert.False(t, present, "token must not carry %q", forbidden)
	}

	// The other participant, with its own key, gets its own token.
	respB, recB, err := w.tokens.IssueAgentCommunication(context.Background(), w.clientB(), w.request(t, w.keyB, w.aciB()))
	require.NoError(t, err)
	assert.Equal(t, "DPoP", respB.TokenType)
	assert.Equal(t, w.aciB(), recB.ACI)
	assert.Equal(t, w.keyB.jkt, decodeClaims(t, respB.AccessToken)["cnf"].(map[string]any)["jkt"])
}

func TestIssueAgentCommunication_TTLNeverPastAuthorizationExpiry(t *testing.T) {
	w := newACIssuanceWorld(t)
	w.now = w.auth.ExpiresAt.Add(-90 * time.Second)
	resp, _, err := w.tokens.IssueAgentCommunication(context.Background(), w.clientA(), w.request(t, w.keyA, w.aciA()))
	require.NoError(t, err)
	assert.EqualValues(t, 90, resp.ExpiresIn, "capped at the authorization's expiry")
	assert.EqualValues(t, w.auth.ExpiresAt.Unix(), decodeClaims(t, resp.AccessToken)["exp"])

	// Configured TTL above the hard maximum is clamped.
	w2 := newACIssuanceWorld(t)
	w2.tokens.WithAgentCommunication(AgentCommunicationIssuanceDeps{
		Authorizations: w2.f.repo, ServiceAccounts: w2.f.sas, Clients: w2.f.clients, Replays: w2.replays,
		TokenEndpointURL: acIssuanceTokenEndpoint, TTL: time.Hour,
	})
	assert.Equal(t, MaxAgentCommunicationTokenTTL, w2.tokens.AgentCommunicationTokenTTL())
}

func TestIssueAgentCommunication_Refusals(t *testing.T) {
	type tc struct {
		name       string
		mutate     func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, client *AuthenticatedClient)
		wantErr    error
		wantReason string
	}
	cases := []tc{
		{"no DPoP proof → refused, never Bearer", func(_ *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) { r.DPoPProof = "" }, ErrDPoPProofRequired, "dpop_missing"},
		{"malformed proof", func(_ *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.DPoPProof = "a.b.c"
		}, ErrDPoPProofInvalid, "dpop_invalid"},
		{"proof for another endpoint", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.DPoPProof = mintProof(t, w.keyA, "POST", "https://idp.test/api/v1/oauth/introspection", w.now, nil)
		}, ErrDPoPProofInvalid, "dpop_invalid"},
		{"foreign proof key (not the enrolled thumbprint)", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.DPoPProof = mintProof(t, newEdDSAProofKey(t), "POST", acIssuanceTokenEndpoint, w.now, nil)
		}, ErrDPoPProofInvalid, "thumbprint_mismatch"},
		{"the other participant's key", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.DPoPProof = mintProof(t, w.keyB, "POST", acIssuanceTokenEndpoint, w.now, nil)
		}, ErrDPoPProofInvalid, "thumbprint_mismatch"},
		{"other participant's ACI", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.AuthorizationDetails = acDetails(w.auth.ID, w.aciB())
		}, ErrAgentCommunicationGrantInvalid, "client_not_participant"},
		{"absent authorization", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			id, _ := uuid.NewV7()
			r.AuthorizationDetails = acDetails(id, w.aciA())
		}, ErrAgentCommunicationGrantInvalid, "authorization_not_found"},
		{"ACI not in the authorization", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			id, _ := uuid.NewV7()
			r.AuthorizationDetails = acDetails(w.auth.ID, id)
		}, ErrAgentCommunicationGrantInvalid, "aci_not_in_authorization"},
		{"revoked authorization", func(w *acIssuanceWorld, _ *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			_, err := w.f.svc.Revoke(context.Background(), w.f.org, w.auth.ID, w.f.owner, "emergency")
			require.NoError(t, err)
		}, ErrAgentCommunicationGrantInvalid, "authorization_revoked"},
		{"expired authorization", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			w.now = w.auth.ExpiresAt.Add(time.Second)
			r.DPoPProof = mintProof(t, w.keyA, "POST", acIssuanceTokenEndpoint, w.now, nil)
		}, ErrAgentCommunicationGrantInvalid, "authorization_expired"},
		{"audience mismatch", func(_ *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.RequestedAudience = "https://other-relay.example.test/x"
		}, ErrTokenServiceInvalidTarget, "audience_mismatch"},
		{"audience missing", func(_ *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.RequestedAudience = ""
		}, ErrTokenServiceInvalidTarget, "audience_mismatch"},
		{"foreign scope", func(_ *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.RequestedScope = "openid"
		}, ErrTokenServiceInvalidScope, "scope_invalid"},
		{"wrong grant type", func(_ *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.GrantType = "authorization_code"
		}, ErrTokenServiceUnsupportedGrant, "unsupported_grant"},
		{"unknown detail type", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.AuthorizationDetails = fmt.Sprintf(`[{"type":"payment_initiation","authorization_id":%q,"aci":%q}]`, w.auth.ID, w.aciA())
		}, ErrTokenServiceInvalidAuthorizationDetails, "invalid_authorization_details"},
		{"unknown field", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.AuthorizationDetails = fmt.Sprintf(`[{"type":"agent_communication","authorization_id":%q,"aci":%q,"actions":["read"]}]`, w.auth.ID, w.aciA())
		}, ErrTokenServiceInvalidAuthorizationDetails, "invalid_authorization_details"},
		{"missing field", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.AuthorizationDetails = fmt.Sprintf(`[{"type":"agent_communication","authorization_id":%q}]`, w.auth.ID)
		}, ErrTokenServiceInvalidAuthorizationDetails, "invalid_authorization_details"},
		{"two details", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			one := acDetails(w.auth.ID, w.aciA())
			r.AuthorizationDetails = "[" + one[1:len(one)-1] + "," + one[1:len(one)-1] + "]"
		}, ErrTokenServiceInvalidAuthorizationDetails, "invalid_authorization_details"},
		{"malformed identifier", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.AuthorizationDetails = fmt.Sprintf(`[{"type":"agent_communication","authorization_id":"not-a-uuid","aci":%q}]`, w.aciA())
		}, ErrTokenServiceInvalidAuthorizationDetails, "invalid_authorization_details"},
		{"non-v7 identifier", func(w *acIssuanceWorld, r *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			r.AuthorizationDetails = acDetails(uuid.New(), w.aciA())
		}, ErrTokenServiceInvalidAuthorizationDetails, "invalid_authorization_details"},
		{"client not private_key_jwt", func(w *acIssuanceWorld, _ *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			w.f.clientA.TokenEndpointAuthMethod = "client_secret_basic"
		}, ErrTokenServiceUnauthorizedClient, "client_auth_not_asymmetric"},
		{"api-resource caller", func(_ *acIssuanceWorld, _ *AgentCommunicationTokenRequest, c *AuthenticatedClient) {
			c.Kind = AuthenticatedClientKindAPIResource
		}, ErrTokenServiceUnauthorizedClient, "client_kind"},
		{"participant service account disabled", func(w *acIssuanceWorld, _ *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			w.f.saA.Active = false
		}, ErrAgentCommunicationGrantInvalid, "participant_not_usable"},
		{"client re-bound to another service account", func(w *acIssuanceWorld, _ *AgentCommunicationTokenRequest, _ *AuthenticatedClient) {
			other := uuid.New()
			w.f.clientA.ServiceAccountID = &other
		}, ErrAgentCommunicationGrantInvalid, "participant_binding_invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newACIssuanceWorld(t)
			client := w.clientA()
			req := w.request(t, w.keyA, w.aciA())
			c.mutate(w, &req, client)
			resp, rec, err := w.tokens.IssueAgentCommunication(context.Background(), client, req)
			require.Error(t, err)
			assert.Nil(t, resp, "no token on refusal")
			assert.Nil(t, rec)
			assert.ErrorIs(t, err, c.wantErr)
			assert.Equal(t, c.wantReason, AgentCommunicationRefusalReason(err))
			assert.False(t, domain.IsAuthStoreUnavailable(err))
		})
	}
}

func TestIssueAgentCommunication_ReplayRefused(t *testing.T) {
	w := newACIssuanceWorld(t)
	req := w.request(t, w.keyA, w.aciA())
	_, _, err := w.tokens.IssueAgentCommunication(context.Background(), w.clientA(), req)
	require.NoError(t, err, "first use")

	_, _, err = w.tokens.IssueAgentCommunication(context.Background(), w.clientA(), req)
	require.Error(t, err, "the same proof again")
	assert.ErrorIs(t, err, ErrDPoPProofReplayed)
	assert.Equal(t, "dpop_replay", AgentCommunicationRefusalReason(err))

	// A fresh proof (new jti) from the same key is fine.
	_, _, err = w.tokens.IssueAgentCommunication(context.Background(), w.clientA(), w.request(t, w.keyA, w.aciA()))
	require.NoError(t, err)

	// The replay store is consulted ONLY after the proof verified and the
	// thumbprint matched: a foreign-key proof never reaches it.
	before := w.replays.mark
	bad := w.request(t, newEdDSAProofKey(t), w.aciA())
	_, _, err = w.tokens.IssueAgentCommunication(context.Background(), w.clientA(), bad)
	assert.ErrorIs(t, err, ErrDPoPProofInvalid)
	assert.Equal(t, before, w.replays.mark)
}

func TestIssueAgentCommunication_StoreErrorsAreUnavailabilityNotVerdicts(t *testing.T) {
	ctx := context.Background()
	t.Run("authorization store", func(t *testing.T) {
		w := newACIssuanceWorld(t)
		w.f.repo.getErr = errors.New("dial tcp: connection refused")
		_, _, err := w.tokens.IssueAgentCommunication(ctx, w.clientA(), w.request(t, w.keyA, w.aciA()))
		require.Error(t, err)
		assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
		assert.NotErrorIs(t, err, ErrAgentCommunicationGrantInvalid)
		assert.NotErrorIs(t, err, ErrTokenServiceUnauthorizedClient)
	})
	t.Run("client store", func(t *testing.T) {
		w := newACIssuanceWorld(t)
		w.f.clients.err = errors.New("read tcp: i/o timeout")
		_, _, err := w.tokens.IssueAgentCommunication(ctx, w.clientA(), w.request(t, w.keyA, w.aciA()))
		assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
	})
	t.Run("service-account store", func(t *testing.T) {
		w := newACIssuanceWorld(t)
		w.f.sas.err = errors.New("pq: the database system is shutting down")
		_, _, err := w.tokens.IssueAgentCommunication(ctx, w.clientA(), w.request(t, w.keyA, w.aciA()))
		assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
	})
	t.Run("replay store", func(t *testing.T) {
		w := newACIssuanceWorld(t)
		w.replays.fail = errors.New("connection reset by peer")
		_, _, err := w.tokens.IssueAgentCommunication(ctx, w.clientA(), w.request(t, w.keyA, w.aciA()))
		assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
		assert.NotErrorIs(t, err, ErrDPoPProofReplayed, "an unanswered replay check is not a verdict")
	})
}

func TestIssueAgentCommunication_NotWired(t *testing.T) {
	ed := genEdDSAKey(t, "kid-x")
	svc := NewTokenService(nil, &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}, TokenServiceOptions{Issuer: "https://idp.test"})
	assert.False(t, svc.HasAgentCommunication())
	_, _, err := svc.IssueAgentCommunication(context.Background(), &AuthenticatedClient{Kind: AuthenticatedClientKindOAuth, ClientID: "x"}, AgentCommunicationTokenRequest{GrantType: "client_credentials", AuthorizationDetails: "[]"})
	assert.ErrorIs(t, err, ErrTokenServiceInvalidAuthorizationDetails)

	// A partial dependency set leaves the feature off.
	svc.WithAgentCommunication(AgentCommunicationIssuanceDeps{TokenEndpointURL: "https://idp.test/api/v1/oauth/token"})
	assert.False(t, svc.HasAgentCommunication())
}

func TestParseAgentCommunicationAuthorizationDetails(t *testing.T) {
	a, _ := uuid.NewV7()
	b, _ := uuid.NewV7()
	authID, aci, detail, err := ParseAgentCommunicationAuthorizationDetails(acDetails(a, b))
	require.NoError(t, err)
	assert.Equal(t, a, authID)
	assert.Equal(t, b, aci)
	raw, _ := json.Marshal(detail)
	assert.JSONEq(t, fmt.Sprintf(`{"type":"agent_communication","authorization_id":%q,"aci":%q}`, a, b), string(raw))

	for _, bad := range []string{"", "{}", "[]", "null", `[{"type":"agent_communication"}]`, `["x"]`, `[{"type":1,"authorization_id":"a","aci":"b"}]`} {
		_, _, _, err := ParseAgentCommunicationAuthorizationDetails(bad)
		assert.ErrorIs(t, err, ErrTokenServiceInvalidAuthorizationDetails, "%q", bad)
	}
}
