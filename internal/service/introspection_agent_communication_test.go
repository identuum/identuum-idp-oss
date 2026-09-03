package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// acIntrospectionWorld: an AYGHU-1 fixture with one active authorization,
// an introspection service wired to its stores, and a claims builder for a
// participant token of the initiator.
type acIntrospectionWorld struct {
	f     *acFixture
	auth  *domain.AgentCommunicationAuthorization
	intro *IntrospectionService
	jkt   string
}

func newACIntrospectionWorld(t *testing.T) *acIntrospectionWorld {
	t.Helper()
	f := newACFixture(t)
	a, err := f.svc.Create(context.Background(), f.input())
	require.NoError(t, err)
	w := &acIntrospectionWorld{f: f, auth: a, jkt: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}
	w.intro = NewIntrospectionService(nil, &fakeIntrospector{}, nil).WithAgentCommunication(f.repo, f.clients)
	w.intro.now = func() time.Time { return f.now }
	return w
}

// participantClaims are the verified claims of a token this server issued
// for the initiator (as the verifier would hand them back).
func (w *acIntrospectionWorld) participantClaims() *IntrospectionClaims {
	p := w.auth.Participant(domain.AgentCommunicationRoleInitiator)
	return &IntrospectionClaims{
		Sub:       p.ServiceAccountID.String(),
		ClientID:  w.f.clientA.ClientID,
		Scope:     AgentCommunicationScope,
		Iss:       "https://idp.test",
		Aud:       []string{w.auth.RelayAudience},
		Exp:       w.f.now.Add(5 * time.Minute).Unix(),
		Iat:       w.f.now.Unix(),
		Nbf:       w.f.now.Unix(),
		Jti:       uuid.NewString(),
		OrgID:     w.auth.OrganizationID,
		ActorType: ActorTypeServiceAccount,
		Extra: map[string]any{
			"cnf": map[string]any{"jkt": w.jkt},
			"agent_communication": map[string]any{
				"authorization_id": w.auth.ID.String(),
				"session_id":       w.auth.SessionID.String(),
				"aci":              p.ACI.String(),
				"role":             "initiator",
				"policy_version":   "v1",
				"policy_digest":    w.auth.PolicyDigest,
			},
			"authorization_details": []any{map[string]any{"type": "agent_communication", "authorization_id": w.auth.ID.String(), "aci": p.ACI.String()}},
		},
	}
}

func (w *acIntrospectionWorld) introspect(t *testing.T, claims *IntrospectionClaims) (IntrospectionResponse, error) {
	t.Helper()
	w.intro.verifier = &fakeIntrospector{claims: claims}
	return w.intro.IntrospectVerdict(context.Background(), "wire-token")
}

func TestIntrospectAgentCommunication_ActiveTokenCarriesSafeFieldsOnly(t *testing.T) {
	w := newACIntrospectionWorld(t)
	resp, err := w.introspect(t, w.participantClaims())
	require.NoError(t, err)
	assert.True(t, resp.Active)
	assert.Equal(t, "DPoP", resp.TokenType)
	assert.Equal(t, map[string]any{"jkt": w.jkt}, resp.Cnf, "cnf carries the thumbprint only")
	require.NotNil(t, resp.AgentCommunication)
	ac := resp.AgentCommunication
	assert.Equal(t, w.auth.ID.String(), ac.AuthorizationID)
	assert.Equal(t, w.auth.SessionID.String(), ac.SessionID)
	assert.Equal(t, w.auth.Participant(domain.AgentCommunicationRoleInitiator).ACI.String(), ac.ACI)
	assert.Equal(t, "initiator", ac.Role)
	assert.Equal(t, "v1", ac.PolicyVersion)
	assert.Equal(t, w.auth.PolicyDigest, ac.PolicyDigest)
	assert.Equal(t, w.auth.MaxMessages, ac.MaxMessages)
	assert.Equal(t, w.auth.MaxMessageSizeBytes, ac.MaxMessageSizeBytes)
	assert.Equal(t, w.auth.ExpiresAt.Unix(), ac.AuthorizationExpiresAt)
	assert.NotNil(t, resp.AuthorizationDetails)
	assert.Equal(t, w.f.saA.ID.String(), resp.Sub)
	assert.Equal(t, w.f.clientA.ClientID, resp.ClientID)
	assert.Equal(t, AgentCommunicationScope, resp.Scope)
}

func TestIntrospectAgentCommunication_PlainTokensAreUntouched(t *testing.T) {
	w := newACIntrospectionWorld(t)
	resp, err := w.introspect(t, &IntrospectionClaims{Sub: uuid.NewString(), ClientID: "plain", Jti: "j", Exp: w.f.now.Add(time.Hour).Unix()})
	require.NoError(t, err)
	assert.True(t, resp.Active)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Nil(t, resp.Cnf)
	assert.Nil(t, resp.AgentCommunication)
}

func TestIntrospectAgentCommunication_InactiveVerdicts(t *testing.T) {
	cases := []struct {
		name string
		mut  func(w *acIntrospectionWorld, c *IntrospectionClaims)
	}{
		{"authorization revoked", func(w *acIntrospectionWorld, _ *IntrospectionClaims) {
			_, err := w.f.svc.Revoke(context.Background(), w.f.org, w.auth.ID, w.f.owner, "emergency")
			require.NoError(t, err)
		}},
		{"authorization expired", func(w *acIntrospectionWorld, _ *IntrospectionClaims) {
			w.intro.now = func() time.Time { return w.auth.ExpiresAt.Add(time.Second) }
		}},
		{"authorization absent", func(_ *acIntrospectionWorld, c *IntrospectionClaims) {
			id, _ := uuid.NewV7()
			c.Extra["agent_communication"].(map[string]any)["authorization_id"] = id.String()
		}},
		{"another organization", func(_ *acIntrospectionWorld, c *IntrospectionClaims) { c.OrgID = uuid.New() }},
		{"audience is not the relay audience", func(_ *acIntrospectionWorld, c *IntrospectionClaims) { c.Aud = []string{"https://idp.test"} }},
		{"no audience", func(_ *acIntrospectionWorld, c *IntrospectionClaims) { c.Aud = nil }},
		{"aci not in the authorization", func(_ *acIntrospectionWorld, c *IntrospectionClaims) {
			id, _ := uuid.NewV7()
			c.Extra["agent_communication"].(map[string]any)["aci"] = id.String()
		}},
		{"sub is not the participant's service account", func(_ *acIntrospectionWorld, c *IntrospectionClaims) { c.Sub = uuid.NewString() }},
		{"role does not match the binding", func(_ *acIntrospectionWorld, c *IntrospectionClaims) {
			c.Extra["agent_communication"].(map[string]any)["role"] = "responder"
		}},
		{"policy digest does not match (no widening)", func(_ *acIntrospectionWorld, c *IntrospectionClaims) {
			c.Extra["agent_communication"].(map[string]any)["policy_digest"] = "deadbeef"
		}},
		{"session id does not match", func(_ *acIntrospectionWorld, c *IntrospectionClaims) {
			c.Extra["agent_communication"].(map[string]any)["session_id"] = uuid.NewString()
		}},
		{"client no longer exists", func(_ *acIntrospectionWorld, c *IntrospectionClaims) { c.ClientID = "gone" }},
		{"client is the other participant's", func(w *acIntrospectionWorld, c *IntrospectionClaims) { c.ClientID = w.f.clientB.ClientID }},
		{"client re-bound to another service account", func(w *acIntrospectionWorld, _ *IntrospectionClaims) {
			other := uuid.New()
			w.f.clientA.ServiceAccountID = &other
		}},
		{"no cnf", func(_ *acIntrospectionWorld, c *IntrospectionClaims) { delete(c.Extra, "cnf") }},
		{"malformed authorization id", func(_ *acIntrospectionWorld, c *IntrospectionClaims) {
			c.Extra["agent_communication"].(map[string]any)["authorization_id"] = "nope"
		}},
		{"introspection not wired for agent communication", func(w *acIntrospectionWorld, _ *IntrospectionClaims) {
			w.intro.WithAgentCommunication(nil, nil)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newACIntrospectionWorld(t)
			claims := w.participantClaims()
			c.mut(w, claims)
			resp, err := w.introspect(t, claims)
			require.NoError(t, err, "a verdict, not a store failure")
			assert.False(t, resp.Active)
			assert.Nil(t, resp.Cnf)
			assert.Nil(t, resp.AgentCommunication)
			assert.Empty(t, resp.Sub, "an inactive answer carries nothing else")
		})
	}
}

func TestIntrospectAgentCommunication_StoreErrorsAreUnavailabilityNeverInactive(t *testing.T) {
	t.Run("authorization store", func(t *testing.T) {
		w := newACIntrospectionWorld(t)
		w.f.repo.getErr = errors.New("dial tcp: connection refused")
		_, err := w.introspect(t, w.participantClaims())
		require.Error(t, err)
		assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
	})
	t.Run("client store", func(t *testing.T) {
		w := newACIntrospectionWorld(t)
		w.f.clients.err = errors.New("read tcp: i/o timeout")
		_, err := w.introspect(t, w.participantClaims())
		require.Error(t, err)
		assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
	})
}
