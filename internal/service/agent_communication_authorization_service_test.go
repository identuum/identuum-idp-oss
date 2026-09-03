package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// acRepoFake is an in-memory AgentCommunicationAuthorizationRepository.
type acRepoFake struct {
	mu          sync.Mutex
	rows        map[uuid.UUID]*domain.AgentCommunicationAuthorization
	createErr   error
	getErr      error
	listErr     error
	revokeErr   error
	createCalls int
	revokeCalls int
}

func cloneAC(a *domain.AgentCommunicationAuthorization) *domain.AgentCommunicationAuthorization {
	c := *a
	c.Participants = append([]domain.AgentCommunicationParticipant(nil), a.Participants...)
	for i := range c.Participants {
		caps := make([]domain.AgentCommunicationCapability, len(a.Participants[i].Capabilities))
		copy(caps, a.Participants[i].Capabilities)
		c.Participants[i].Capabilities = caps
	}
	return &c
}

func (f *acRepoFake) Create(_ context.Context, a *domain.AgentCommunicationAuthorization) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	if f.createErr != nil {
		return f.createErr
	}
	f.rows[a.ID] = cloneAC(a)
	return nil
}

func (f *acRepoFake) GetByID(_ context.Context, org, id uuid.UUID) (*domain.AgentCommunicationAuthorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	row, ok := f.rows[id]
	if !ok || row.OrganizationID != org {
		return nil, domain.ErrAgentCommunicationAuthorizationNotFound
	}
	return cloneAC(row), nil
}

func (f *acRepoFake) ListByOrganization(_ context.Context, org uuid.UUID) ([]*domain.AgentCommunicationAuthorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []*domain.AgentCommunicationAuthorization
	for _, row := range f.rows {
		if row.OrganizationID == org {
			out = append(out, cloneAC(row))
		}
	}
	return out, nil
}

func (f *acRepoFake) Revoke(_ context.Context, org, id, by uuid.UUID, reason *string, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeCalls++
	if f.revokeErr != nil {
		return false, f.revokeErr
	}
	row, ok := f.rows[id]
	if !ok || row.OrganizationID != org || row.RevokedAt != nil {
		return false, nil
	}
	row.RevokedAt = &at
	row.RevokedBy = &by
	row.RevocationReason = reason
	return true, nil
}

// HasLiveParticipant mirrors the pgx EXISTS query (THE-OWNERLESS-ACCOUNT):
// an authorization of the organization, neither revoked nor expired at
// `now`, naming the service account.
func (f *acRepoFake) HasLiveParticipant(_ context.Context, org, serviceAccountID uuid.UUID, now time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return false, f.getErr
	}
	for _, row := range f.rows {
		if row.OrganizationID != org || row.RevokedAt != nil || !row.ExpiresAt.After(now) {
			continue
		}
		for _, p := range row.Participants {
			if p.ServiceAccountID == serviceAccountID {
				return true, nil
			}
		}
	}
	return false, nil
}

type acSAFake struct {
	rows  map[uuid.UUID]*domain.ServiceAccount
	err   error
	calls int
}

func (f *acSAFake) GetByID(_ context.Context, id uuid.UUID) (*domain.ServiceAccount, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	sa, ok := f.rows[id]
	if !ok {
		return nil, domain.ErrServiceAccountNotFound
	}
	return sa, nil
}

type acClientFake struct {
	rows map[string]*domain.Client
	err  error
}

func (f *acClientFake) GetClientByClientID(_ context.Context, clientID string) (*domain.Client, error) {
	if f.err != nil {
		return nil, f.err
	}
	c, ok := f.rows[clientID]
	if !ok {
		return nil, domain.ErrClientNotFound
	}
	return c, nil
}

type acFixture struct {
	svc     *AgentCommunicationAuthorizationService
	repo    *acRepoFake
	sas     *acSAFake
	clients *acClientFake
	org     uuid.UUID
	owner   uuid.UUID
	now     time.Time
	saA     *domain.ServiceAccount
	saB     *domain.ServiceAccount
	clientA *domain.Client
	clientB *domain.Client
}

func newACFixture(t *testing.T) *acFixture {
	t.Helper()
	f := &acFixture{
		repo:    &acRepoFake{rows: map[uuid.UUID]*domain.AgentCommunicationAuthorization{}},
		sas:     &acSAFake{rows: map[uuid.UUID]*domain.ServiceAccount{}},
		clients: &acClientFake{rows: map[string]*domain.Client{}},
		org:     uuid.New(),
		owner:   uuid.New(),
		now:     time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
	}
	mkSA := func(name string) *domain.ServiceAccount {
		owner := f.owner
		sa := &domain.ServiceAccount{ID: uuid.New(), OrganizationID: f.org, Name: name, Active: true, OwnerUserID: &owner}
		f.sas.rows[sa.ID] = sa
		return sa
	}
	mkClient := func(clientID string, sa *domain.ServiceAccount) *domain.Client {
		org := f.org
		saID := sa.ID
		c := &domain.Client{ID: uuid.New(), ClientID: clientID, OrganizationID: &org, ServiceAccountID: &saID,
			TokenEndpointAuthMethod: "private_key_jwt", JWKS: `{"keys":[]}`}
		f.clients.rows[clientID] = c
		return c
	}
	f.saA = mkSA("agent-a")
	f.saB = mkSA("agent-b")
	f.clientA = mkClient("agent-a-client", f.saA)
	f.clientB = mkClient("agent-b-client", f.saB)
	report := lifecycle.NewStartupReport()
	f.svc = NewAgentCommunicationAuthorizationService(report, f.repo, f.sas, f.clients,
		AgentCommunicationAuthorizationServiceOptions{Now: func() time.Time { return f.now }})
	require.False(t, report.HasFatal())
	return f
}

func (f *acFixture) input() CreateAgentCommunicationAuthorizationInput {
	return CreateAgentCommunicationAuthorizationInput{
		OrganizationID:      f.org,
		OwnerID:             f.owner,
		RelayAudience:       "https://relay.example.test/session",
		ExpiresAt:           f.now.Add(time.Hour),
		MaxMessages:         10,
		MaxMessageSizeBytes: 4096,
		Participants: []AgentCommunicationParticipantInput{
			{ServiceAccountID: f.saA.ID, ClientID: f.clientA.ClientID, Role: domain.AgentCommunicationRoleInitiator,
				ProofKeyThumbprint: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", Capabilities: []string{"repository.read", "communication.discuss"}},
			{ServiceAccountID: f.saB.ID, ClientID: f.clientB.ClientID, Role: domain.AgentCommunicationRoleResponder,
				ProofKeyThumbprint: "0ZO2hCQ7O9O3HrCMNDbdb-MRyhAg8CTt3xfsq5c5C1w"},
		},
	}
}

func TestNewAgentCommunicationAuthorizationService_NilDepsRecordFatal(t *testing.T) {
	f := newACFixture(t)
	// The clock seam is injected here too (clock-fuse gate): a constructor
	// test must not leave a service on the wall clock.
	opts := AgentCommunicationAuthorizationServiceOptions{Now: func() time.Time { return f.now }}
	cases := map[string]func(rep *lifecycle.StartupReport){
		"repo": func(rep *lifecycle.StartupReport) {
			NewAgentCommunicationAuthorizationService(rep, nil, f.sas, f.clients, opts)
		},
		"sas": func(rep *lifecycle.StartupReport) {
			NewAgentCommunicationAuthorizationService(rep, f.repo, nil, f.clients, opts)
		},
		"clients": func(rep *lifecycle.StartupReport) {
			NewAgentCommunicationAuthorizationService(rep, f.repo, f.sas, nil, opts)
		},
	}
	for name, build := range cases {
		rep := lifecycle.NewStartupReport()
		require.NotPanics(t, func() { build(rep) }, name)
		assert.True(t, rep.HasFatal(), "nil %s must record a fatal fault, never panic", name)
	}
}

func TestAgentCommAuth_Create_HappyPath(t *testing.T) {
	f := newACFixture(t)
	in := f.input()
	in.RelayAudience = "  HTTPS://Relay.Example.TEST/session "
	a, err := f.svc.Create(context.Background(), in)
	require.NoError(t, err)

	assert.Equal(t, uuid.Version(7), a.ID.Version())
	assert.Equal(t, uuid.Version(7), a.SessionID.Version())
	assert.NotEqual(t, a.ID, a.SessionID)
	assert.Equal(t, f.org, a.OrganizationID)
	assert.Equal(t, f.owner, a.OwnerID)
	assert.Equal(t, "https://relay.example.test/session", a.RelayAudience, "audience normalized")
	assert.Equal(t, f.now, a.CreatedAt)
	assert.Equal(t, in.ExpiresAt, a.ExpiresAt)
	assert.Equal(t, domain.AgentCommunicationPolicyVersion, a.PolicyVersion)
	assert.Nil(t, a.RevokedAt)
	assert.Equal(t, domain.AgentCommunicationStatusActive, a.Status(f.now))

	require.Len(t, a.Participants, 2)
	initiator := a.Participant(domain.AgentCommunicationRoleInitiator)
	responder := a.Participant(domain.AgentCommunicationRoleResponder)
	require.NotNil(t, initiator)
	require.NotNil(t, responder)
	assert.Equal(t, f.saA.ID, initiator.ServiceAccountID)
	assert.Equal(t, f.clientA.ID, initiator.OAuthClientID, "the participant stores the oauth_clients row id")
	assert.Equal(t, f.saB.ID, responder.ServiceAccountID)
	assert.Equal(t, f.clientB.ID, responder.OAuthClientID)
	for _, p := range a.Participants {
		assert.Equal(t, a.ID, p.AuthorizationID)
		assert.Equal(t, uuid.Version(7), p.ID.Version())
		assert.Equal(t, uuid.Version(7), p.ACI.Version())
		assert.NotEqual(t, p.ACI, p.ID)
		assert.NotEqual(t, p.ACI, a.ID)
		assert.NotEqual(t, p.ACI, a.SessionID)
	}
	assert.NotEqual(t, initiator.ACI, responder.ACI)
	assert.Equal(t, []domain.AgentCommunicationCapability{domain.AgentCapabilityCommunicationDiscuss, domain.AgentCapabilityRepositoryRead},
		initiator.Capabilities, "capabilities stored canonical")
	assert.NotNil(t, responder.Capabilities)
	assert.Empty(t, responder.Capabilities, "empty = communication only")

	digest, err := a.ComputePolicyDigest()
	require.NoError(t, err)
	assert.Equal(t, digest, a.PolicyDigest)
	require.NoError(t, a.Validate(f.now))

	stored := f.repo.rows[a.ID]
	require.NotNil(t, stored)
	assert.Equal(t, a, stored)
}

func TestAgentCommAuth_Create_StructuralRefusalsHappenBeforeLookups(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		mut  func(in *CreateAgentCommunicationAuthorizationInput)
		want error
	}{
		{"unknown capability", func(in *CreateAgentCommunicationAuthorizationInput) {
			in.Participants[0].Capabilities = []string{"repository.read", "repository.delete"}
		}, domain.ErrAgentCommunicationUnknownCapability},
		{"invalid role", func(in *CreateAgentCommunicationAuthorizationInput) {
			in.Participants[1].Role = "observer"
		}, domain.ErrAgentCommunicationInvalidRole},
		{"duplicate client", func(in *CreateAgentCommunicationAuthorizationInput) {
			in.Participants[1].ClientID = in.Participants[0].ClientID
		}, domain.ErrAgentCommunicationDuplicateClient},
		{"zero limit", func(in *CreateAgentCommunicationAuthorizationInput) { in.MaxMessageSizeBytes = 0 }, domain.ErrAgentCommunicationLimitNotPositive},
		{"expiry in the past", func(in *CreateAgentCommunicationAuthorizationInput) { in.ExpiresAt = in.ExpiresAt.Add(-2 * time.Hour) }, domain.ErrAgentCommunicationExpiryNotFuture},
		{"empty audience", func(in *CreateAgentCommunicationAuthorizationInput) { in.RelayAudience = " " }, domain.ErrAgentCommunicationRelayAudienceRequired},
		{"bad thumbprint", func(in *CreateAgentCommunicationAuthorizationInput) { in.Participants[0].ProofKeyThumbprint = "x/y" }, domain.ErrAgentCommunicationProofKeyThumbprintInvalid},
		{"missing owner", func(in *CreateAgentCommunicationAuthorizationInput) { in.OwnerID = uuid.Nil }, domain.ErrAgentCommunicationIdentifierRequired},
		{"missing client id", func(in *CreateAgentCommunicationAuthorizationInput) { in.Participants[0].ClientID = "" }, domain.ErrAgentCommunicationIdentifierRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newACFixture(t)
			in := f.input()
			tc.mut(&in)
			_, err := f.svc.Create(ctx, in)
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.want)
			assert.Equal(t, 0, f.sas.calls, "refused before any store lookup")
			assert.Equal(t, 0, f.repo.createCalls)
		})
	}
}

func TestAgentCommAuth_Create_ServiceAccountVerdictsAndStoreErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown service account is a typed verdict", func(t *testing.T) {
		f := newACFixture(t)
		in := f.input()
		in.Participants[1].ServiceAccountID = uuid.New()
		_, err := f.svc.Create(ctx, in)
		assert.ErrorIs(t, err, domain.ErrServiceAccountNotFound)
		assert.False(t, domain.IsAuthStoreUnavailable(err))
	})

	t.Run("another organization's service account is indistinguishable from absent", func(t *testing.T) {
		f := newACFixture(t)
		f.saB.OrganizationID = uuid.New()
		_, err := f.svc.Create(ctx, f.input())
		assert.ErrorIs(t, err, domain.ErrServiceAccountNotFound)
		assert.Equal(t, 0, f.repo.createCalls)
	})

	t.Run("inactive or expired participant is refused", func(t *testing.T) {
		f := newACFixture(t)
		f.saA.Active = false
		_, err := f.svc.Create(ctx, f.input())
		assert.ErrorIs(t, err, domain.ErrAgentCommunicationParticipantNotUsable)

		g := newACFixture(t)
		past := g.now.Add(-time.Second)
		g.saB.ExpiresAt = &past
		_, err = g.svc.Create(ctx, g.input())
		assert.ErrorIs(t, err, domain.ErrAgentCommunicationParticipantNotUsable)
	})

	t.Run("service-account store error is unavailability, not a verdict", func(t *testing.T) {
		f := newACFixture(t)
		f.sas.err = errors.New("dial tcp: connection refused")
		_, err := f.svc.Create(ctx, f.input())
		require.Error(t, err)
		assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
		assert.NotErrorIs(t, err, domain.ErrServiceAccountNotFound)
		assert.Equal(t, 0, f.repo.createCalls)
	})
}

func TestAgentCommAuth_Create_ClientVerdictsAndStoreErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown client is a typed verdict", func(t *testing.T) {
		f := newACFixture(t)
		in := f.input()
		in.Participants[0].ClientID = "nobody"
		_, err := f.svc.Create(ctx, in)
		assert.ErrorIs(t, err, domain.ErrClientNotFound)
		assert.False(t, domain.IsAuthStoreUnavailable(err))
	})

	t.Run("client not bound to the participant is refused", func(t *testing.T) {
		f := newACFixture(t)
		in := f.input()
		in.Participants[0].ClientID = f.clientB.ClientID
		in.Participants[1].ClientID = f.clientA.ClientID
		_, err := f.svc.Create(ctx, in)
		assert.ErrorIs(t, err, domain.ErrAgentCommunicationClientNotBound)
	})

	t.Run("client without private_key_jwt is refused", func(t *testing.T) {
		f := newACFixture(t)
		f.clientB.TokenEndpointAuthMethod = "client_secret_basic"
		_, err := f.svc.Create(ctx, f.input())
		assert.ErrorIs(t, err, domain.ErrAgentCommunicationClientAuthNotAsymmetric)
	})

	t.Run("client store error is unavailability", func(t *testing.T) {
		f := newACFixture(t)
		f.clients.err = errors.New("read tcp: i/o timeout")
		_, err := f.svc.Create(ctx, f.input())
		require.Error(t, err)
		assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
		assert.Equal(t, 0, f.repo.createCalls)
	})

	t.Run("persistence error is unavailability", func(t *testing.T) {
		f := newACFixture(t)
		f.repo.createErr = errors.New("failed to commit: connection reset")
		_, err := f.svc.Create(ctx, f.input())
		require.Error(t, err)
		assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
	})
}

func TestAgentCommAuth_GetListRevoke(t *testing.T) {
	ctx := context.Background()
	f := newACFixture(t)
	a, err := f.svc.Create(ctx, f.input())
	require.NoError(t, err)

	got, err := f.svc.Get(ctx, f.org, a.ID)
	require.NoError(t, err)
	assert.Equal(t, a, got)

	_, err = f.svc.Get(ctx, uuid.New(), a.ID)
	assert.ErrorIs(t, err, domain.ErrAgentCommunicationAuthorizationNotFound, "foreign organization: not found, no oracle")
	_, err = f.svc.Get(ctx, f.org, uuid.New())
	assert.ErrorIs(t, err, domain.ErrAgentCommunicationAuthorizationNotFound)

	list, err := f.svc.List(ctx, f.org)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	empty, err := f.svc.List(ctx, uuid.New())
	require.NoError(t, err)
	assert.NotNil(t, empty)
	assert.Empty(t, empty)

	f.now = f.now.Add(10 * time.Minute)
	revoked, err := f.svc.Revoke(ctx, f.org, a.ID, f.owner, "  operator request  ")
	require.NoError(t, err)
	require.NotNil(t, revoked.RevokedAt)
	assert.Equal(t, f.now, *revoked.RevokedAt)
	require.NotNil(t, revoked.RevokedBy)
	assert.Equal(t, f.owner, *revoked.RevokedBy)
	require.NotNil(t, revoked.RevocationReason)
	assert.Equal(t, "operator request", *revoked.RevocationReason)
	assert.Equal(t, domain.AgentCommunicationStatusRevoked, revoked.Status(f.now))
	assert.Equal(t, 1, f.repo.revokeCalls)

	// Terminal + idempotent: the first stamp wins, the store is not written again.
	f.now = f.now.Add(time.Hour)
	again, err := f.svc.Revoke(ctx, f.org, a.ID, uuid.New(), "later")
	require.NoError(t, err)
	assert.Equal(t, revoked.RevokedAt, again.RevokedAt)
	assert.Equal(t, revoked.RevokedBy, again.RevokedBy)
	assert.Equal(t, "operator request", *again.RevocationReason)
	assert.Equal(t, 1, f.repo.revokeCalls)
	assert.Equal(t, domain.AgentCommunicationStatusRevoked, again.Status(a.ExpiresAt.Add(time.Hour)), "revoked wins over expiry")

	_, err = f.svc.Revoke(ctx, uuid.New(), a.ID, f.owner, "")
	assert.ErrorIs(t, err, domain.ErrAgentCommunicationAuthorizationNotFound)
	_, err = f.svc.Revoke(ctx, f.org, a.ID, uuid.Nil, "")
	assert.ErrorIs(t, err, domain.ErrAgentCommunicationIdentifierRequired)
	long := make([]byte, domain.AgentCommunicationRevocationReasonMaxLen+1)
	for i := range long {
		long[i] = 'x'
	}
	_, err = f.svc.Revoke(ctx, f.org, a.ID, f.owner, string(long))
	assert.ErrorIs(t, err, domain.ErrAgentCommunicationRevocationReasonTooLong)
}

func TestAgentCommAuth_ReadPathStoreErrorsAreUnavailability(t *testing.T) {
	ctx := context.Background()
	f := newACFixture(t)
	a, err := f.svc.Create(ctx, f.input())
	require.NoError(t, err)

	f.repo.getErr = errors.New("connection reset by peer")
	_, err = f.svc.Get(ctx, f.org, a.ID)
	assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
	_, err = f.svc.Revoke(ctx, f.org, a.ID, f.owner, "x")
	assert.True(t, domain.IsAuthStoreUnavailable(err), "revoke reads first: got %v", err)
	f.repo.getErr = nil

	f.repo.listErr = errors.New("connection reset by peer")
	_, err = f.svc.List(ctx, f.org)
	assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
	f.repo.listErr = nil

	f.repo.revokeErr = errors.New("connection reset by peer")
	_, err = f.svc.Revoke(ctx, f.org, a.ID, f.owner, "x")
	assert.True(t, domain.IsAuthStoreUnavailable(err), "got %v", err)
}
