package domain

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func v7(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	require.NoError(t, err)
	return id
}

// agentCommFixture returns a fully valid aggregate at `now`.
func agentCommFixture(t *testing.T, now time.Time) *AgentCommunicationAuthorization {
	t.Helper()
	id := v7(t)
	a := &AgentCommunicationAuthorization{
		ID:                  id,
		OrganizationID:      uuid.New(),
		OwnerID:             uuid.New(),
		SessionID:           v7(t),
		RelayAudience:       "https://relay.example.test/session",
		MaxMessages:         10,
		MaxMessageSizeBytes: 1024,
		ExpiresAt:           now.Add(time.Hour),
		CreatedAt:           now,
		PolicyVersion:       AgentCommunicationPolicyVersion,
		Participants: []AgentCommunicationParticipant{
			{
				ID: v7(t), AuthorizationID: id, ACI: v7(t), ServiceAccountID: uuid.New(), OAuthClientID: uuid.New(),
				Role: AgentCommunicationRoleInitiator, ProofKeyThumbprint: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
				Capabilities: []AgentCommunicationCapability{AgentCapabilityRepositoryRead}, CreatedAt: now,
			},
			{
				ID: v7(t), AuthorizationID: id, ACI: v7(t), ServiceAccountID: uuid.New(), OAuthClientID: uuid.New(),
				Role: AgentCommunicationRoleResponder, ProofKeyThumbprint: "0ZO2hCQ7O9O3HrCMNDbdb-MRyhAg8CTt3xfsq5c5C1w",
				Capabilities: []AgentCommunicationCapability{}, CreatedAt: now,
			},
		},
	}
	digest, err := a.ComputePolicyDigest()
	require.NoError(t, err)
	a.PolicyDigest = digest
	require.NoError(t, a.Validate(now))
	return a
}

func TestAgentCommunicationCapabilities_ClosedVocabulary(t *testing.T) {
	got := AgentCommunicationCapabilities()
	want := []AgentCommunicationCapability{
		"command.execute", "communication.discuss", "network.access", "report.final.required",
		"repository.read", "repository.write", "test.execute",
	}
	assert.Equal(t, want, got, "vocabulary must be exactly the seven members in byte order")

	for _, raw := range []string{"", "repository.admin", " repository.read", "Repository.Read", "repository.read ", "*"} {
		_, err := ParseAgentCommunicationCapability(raw)
		assert.ErrorIs(t, err, ErrAgentCommunicationUnknownCapability, "%q must fail closed", raw)
	}
	for _, c := range want {
		parsed, err := ParseAgentCommunicationCapability(string(c))
		require.NoError(t, err)
		assert.Equal(t, c, parsed)
	}
}

func TestCanonicalizeAgentCommunicationCapabilities(t *testing.T) {
	got, err := CanonicalizeAgentCommunicationCapabilities([]AgentCommunicationCapability{
		AgentCapabilityTestExecute, AgentCapabilityRepositoryRead, AgentCapabilityTestExecute, AgentCapabilityCommandExecute,
	})
	require.NoError(t, err)
	assert.Equal(t, []AgentCommunicationCapability{AgentCapabilityCommandExecute, AgentCapabilityRepositoryRead, AgentCapabilityTestExecute}, got)

	empty, err := CanonicalizeAgentCommunicationCapabilities(nil)
	require.NoError(t, err)
	assert.NotNil(t, empty)
	assert.Empty(t, empty, "empty list = communication only")

	_, err = CanonicalizeAgentCommunicationCapabilities([]AgentCommunicationCapability{AgentCapabilityRepositoryRead, "repository.delete"})
	assert.ErrorIs(t, err, ErrAgentCommunicationUnknownCapability)

	// repository.write does not imply repository.read.
	only, err := CanonicalizeAgentCommunicationCapabilities([]AgentCommunicationCapability{AgentCapabilityRepositoryWrite})
	require.NoError(t, err)
	assert.Equal(t, []AgentCommunicationCapability{AgentCapabilityRepositoryWrite}, only)
}

func TestAgentCommunicationPolicy_CanonicalForm(t *testing.T) {
	p := AgentCommunicationPolicy{
		PolicyVersion: "v1", MaxMessages: 10, MaxMessageSizeBytes: 1024,
		Participants: []AgentCommunicationParticipantPolicy{
			{Role: "responder", Capabilities: nil},
			{Role: "initiator", Capabilities: []string{"repository.read"}},
		},
	}
	b, err := p.Canonical()
	require.NoError(t, err)
	assert.Equal(t,
		`{"policy_version":"v1","max_messages":10,"max_message_size_bytes":1024,"participants":[{"role":"initiator","capabilities":["repository.read"]},{"role":"responder","capabilities":[]}]}`,
		string(b), "canonical bytes: fixed field order, participants sorted by role, nil capabilities as []")
}

func TestAgentCommunicationPolicyDigest_IsOrderIndependentAndTyped(t *testing.T) {
	base := AgentCommunicationPolicy{
		PolicyVersion: "v1", MaxMessages: 10, MaxMessageSizeBytes: 1024,
		Participants: []AgentCommunicationParticipantPolicy{
			{Role: "initiator", Capabilities: []string{"repository.read", "test.execute", "command.execute"}},
			{Role: "responder", Capabilities: []string{"repository.write"}},
		},
	}
	shuffled := AgentCommunicationPolicy{
		PolicyVersion: "v1", MaxMessages: 10, MaxMessageSizeBytes: 1024,
		Participants: []AgentCommunicationParticipantPolicy{
			{Role: "responder", Capabilities: []string{"repository.write", "repository.write"}},
			{Role: "initiator", Capabilities: []string{"test.execute", "command.execute", "repository.read", "test.execute"}},
		},
	}
	d1, err := base.Digest()
	require.NoError(t, err)
	d2, err := shuffled.Digest()
	require.NoError(t, err)
	assert.Equal(t, d1, d2, "capability order, participant order and duplicates must not change the digest")

	raw, err := hex.DecodeString(d1)
	require.NoError(t, err)
	assert.Len(t, raw, 32, "SHA-256 hex")
	assert.Equal(t, strings.ToLower(d1), d1)

	// Each typed input participates.
	v := base
	v.PolicyVersion = "v2"
	dv, _ := v.Digest()
	assert.NotEqual(t, d1, dv, "policy version is a digest input")
	m := base
	m.MaxMessages = 11
	dm, _ := m.Digest()
	assert.NotEqual(t, d1, dm, "max_messages is a digest input")
	sz := base
	sz.MaxMessageSizeBytes = 2048
	ds, _ := sz.Digest()
	assert.NotEqual(t, d1, ds, "max_message_size_bytes is a digest input")
	c := base
	c.Participants = []AgentCommunicationParticipantPolicy{
		{Role: "initiator", Capabilities: []string{"repository.read", "test.execute"}},
		{Role: "responder", Capabilities: []string{"repository.write"}},
	}
	dc, _ := c.Digest()
	assert.NotEqual(t, d1, dc, "a participant's capability set is a digest input")
	swap := base
	swap.Participants = []AgentCommunicationParticipantPolicy{
		{Role: "initiator", Capabilities: []string{"repository.write"}},
		{Role: "responder", Capabilities: []string{"repository.read", "test.execute", "command.execute"}},
	}
	dsw, _ := swap.Digest()
	assert.NotEqual(t, d1, dsw, "capabilities are participant-specific: swapping roles changes the digest")
}

func TestAgentCommunicationPolicyDigest_IgnoresIdentifiersTimestampsAndAudience(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	a := agentCommFixture(t, now)
	d1, err := a.ComputePolicyDigest()
	require.NoError(t, err)

	b := *a
	b.ID, b.SessionID = v7(t), v7(t)
	b.CreatedAt = now.Add(time.Minute)
	b.ExpiresAt = now.Add(2 * time.Hour)
	b.RelayAudience = "https://other.example.test/x"
	b.Participants = []AgentCommunicationParticipant{a.Participants[1], a.Participants[0]}
	for i := range b.Participants {
		b.Participants[i].ACI = v7(t)
		b.Participants[i].ID = v7(t)
		b.Participants[i].ProofKeyThumbprint = "different-thumbprint"
		b.Participants[i].CreatedAt = now.Add(time.Minute)
	}
	d2, err := b.ComputePolicyDigest()
	require.NoError(t, err)
	assert.Equal(t, d1, d2, "ids, ACIs, thumbprints, timestamps, audience and row order are not digest inputs")
}

func TestNormalizeAgentCommunicationRelayAudience(t *testing.T) {
	cases := []struct {
		in, want string
		err      error
	}{
		{"  HTTPS://Relay.Example.TEST/Session/Path  ", "https://relay.example.test/Session/Path", nil},
		{"urn:identuum:relay:alpha", "urn:identuum:relay:alpha", nil},
		{"relay-alpha", "relay-alpha", nil},
		{"", "", ErrAgentCommunicationRelayAudienceRequired},
		{"   ", "", ErrAgentCommunicationRelayAudienceRequired},
		{"https://relay.example.test/a b", "", ErrAgentCommunicationRelayAudienceInvalid},
		{"https://relay.example.test/a\tb", "", ErrAgentCommunicationRelayAudienceInvalid},
		{"https://relay.example.test/a#frag", "", ErrAgentCommunicationRelayAudienceInvalid},
		{"https://user:pw@relay.example.test/a", "", ErrAgentCommunicationRelayAudienceInvalid},
		{strings.Repeat("a", AgentCommunicationRelayAudienceMaxLen+1), "", ErrAgentCommunicationRelayAudienceInvalid},
	}
	for _, tc := range cases {
		got, err := NormalizeAgentCommunicationRelayAudience(tc.in)
		if tc.err != nil {
			assert.ErrorIs(t, err, tc.err, "input %q", tc.in)
			continue
		}
		require.NoError(t, err, "input %q", tc.in)
		assert.Equal(t, tc.want, got, "input %q", tc.in)
	}
}

func TestAgentCommunicationAuthorization_Status(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	a := agentCommFixture(t, now)
	assert.Equal(t, AgentCommunicationStatusActive, a.Status(now))
	assert.Equal(t, AgentCommunicationStatusExpired, a.Status(a.ExpiresAt), "expiry is derived at use time")
	rev := now.Add(time.Minute)
	a.RevokedAt = &rev
	assert.Equal(t, AgentCommunicationStatusRevoked, a.Status(now))
	assert.Equal(t, AgentCommunicationStatusRevoked, a.Status(a.ExpiresAt.Add(time.Hour)), "revocation is terminal and wins over expiry")
}

func TestAgentCommunicationAuthorization_Validate(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	mut := func(name string, want error, f func(a *AgentCommunicationAuthorization)) {
		t.Run(name, func(t *testing.T) {
			a := agentCommFixture(t, now)
			f(a)
			err := a.Validate(now)
			require.Error(t, err)
			assert.ErrorIs(t, err, want)
		})
	}
	mut("one participant", ErrAgentCommunicationParticipantCount, func(a *AgentCommunicationAuthorization) {
		a.Participants = a.Participants[:1]
	})
	mut("three participants", ErrAgentCommunicationParticipantCount, func(a *AgentCommunicationAuthorization) {
		third := a.Participants[0]
		third.ID, third.ACI, third.ServiceAccountID, third.OAuthClientID = v7(t), v7(t), uuid.New(), uuid.New()
		a.Participants = append(a.Participants, third)
	})
	mut("duplicate ACI", ErrAgentCommunicationDuplicateACI, func(a *AgentCommunicationAuthorization) {
		a.Participants[1].ACI = a.Participants[0].ACI
	})
	mut("duplicate service account", ErrAgentCommunicationDuplicateServiceAccount, func(a *AgentCommunicationAuthorization) {
		a.Participants[1].ServiceAccountID = a.Participants[0].ServiceAccountID
	})
	mut("duplicate client", ErrAgentCommunicationDuplicateClient, func(a *AgentCommunicationAuthorization) {
		a.Participants[1].OAuthClientID = a.Participants[0].OAuthClientID
	})
	mut("duplicate role", ErrAgentCommunicationDuplicateRole, func(a *AgentCommunicationAuthorization) {
		a.Participants[1].Role = AgentCommunicationRoleInitiator
	})
	mut("unknown role", ErrAgentCommunicationInvalidRole, func(a *AgentCommunicationAuthorization) {
		a.Participants[1].Role = "observer"
	})
	mut("unknown capability", ErrAgentCommunicationUnknownCapability, func(a *AgentCommunicationAuthorization) {
		a.Participants[0].Capabilities = []AgentCommunicationCapability{"repository.delete"}
	})
	mut("capabilities not canonical", ErrAgentCommunicationCapabilitiesNotCanonical, func(a *AgentCommunicationAuthorization) {
		a.Participants[0].Capabilities = []AgentCommunicationCapability{AgentCapabilityTestExecute, AgentCapabilityRepositoryRead}
		a.PolicyDigest, _ = a.ComputePolicyDigest()
	})
	mut("authorization id not v7", ErrAgentCommunicationIdentifierNotV7, func(a *AgentCommunicationAuthorization) {
		a.ID = uuid.New()
		for i := range a.Participants {
			a.Participants[i].AuthorizationID = a.ID
		}
	})
	mut("session id not v7", ErrAgentCommunicationIdentifierNotV7, func(a *AgentCommunicationAuthorization) {
		a.SessionID = uuid.New()
	})
	mut("aci not v7", ErrAgentCommunicationIdentifierNotV7, func(a *AgentCommunicationAuthorization) {
		a.Participants[0].ACI = uuid.New()
	})
	mut("participant of another authorization", ErrAgentCommunicationIdentifierRequired, func(a *AgentCommunicationAuthorization) {
		a.Participants[0].AuthorizationID = v7(t)
	})
	mut("audience not normalized", ErrAgentCommunicationRelayAudienceInvalid, func(a *AgentCommunicationAuthorization) {
		a.RelayAudience = "HTTPS://Relay.Example.TEST/session"
	})
	mut("audience empty", ErrAgentCommunicationRelayAudienceRequired, func(a *AgentCommunicationAuthorization) {
		a.RelayAudience = ""
	})
	mut("zero max_messages", ErrAgentCommunicationLimitNotPositive, func(a *AgentCommunicationAuthorization) {
		a.MaxMessages = 0
	})
	mut("negative max size", ErrAgentCommunicationLimitNotPositive, func(a *AgentCommunicationAuthorization) {
		a.MaxMessageSizeBytes = -1
	})
	mut("expiry not future", ErrAgentCommunicationExpiryNotFuture, func(a *AgentCommunicationAuthorization) {
		a.ExpiresAt = now
	})
	mut("policy version unsupported", ErrAgentCommunicationPolicyVersionUnsupported, func(a *AgentCommunicationAuthorization) {
		a.PolicyVersion = "v0"
	})
	mut("digest mismatch", ErrAgentCommunicationPolicyDigestMismatch, func(a *AgentCommunicationAuthorization) {
		a.MaxMessages++
	})
	mut("thumbprint invalid", ErrAgentCommunicationProofKeyThumbprintInvalid, func(a *AgentCommunicationAuthorization) {
		a.Participants[0].ProofKeyThumbprint = "not/base64url+"
	})
	mut("thumbprint empty", ErrAgentCommunicationProofKeyThumbprintInvalid, func(a *AgentCommunicationAuthorization) {
		a.Participants[1].ProofKeyThumbprint = ""
	})
	t.Run("nil aggregate", func(t *testing.T) {
		var a *AgentCommunicationAuthorization
		assert.ErrorIs(t, a.Validate(now), ErrAgentCommunicationIdentifierRequired)
	})
}

func TestCheckAgentCommunicationSameOwner(t *testing.T) {
	owner := uuid.New()
	other := uuid.New()
	mine1 := &ServiceAccount{ID: uuid.New(), OwnerUserID: &owner}
	mine2 := &ServiceAccount{ID: uuid.New(), OwnerUserID: &owner}
	theirs := &ServiceAccount{ID: uuid.New(), OwnerUserID: &other}
	ownerless := &ServiceAccount{ID: uuid.New()}
	nilOwner := uuid.Nil
	nilOwned := &ServiceAccount{ID: uuid.New(), OwnerUserID: &nilOwner}

	assert.NoError(t, CheckAgentCommunicationSameOwner(owner, mine1, mine2))
	assert.ErrorIs(t, CheckAgentCommunicationSameOwner(owner, mine1, theirs), ErrAgentCommunicationOwnerMismatch, "cross-owner is refused (deferred, not built)")
	assert.ErrorIs(t, CheckAgentCommunicationSameOwner(owner, theirs, mine1), ErrAgentCommunicationOwnerMismatch)
	assert.ErrorIs(t, CheckAgentCommunicationSameOwner(owner, mine1, ownerless), ErrAgentCommunicationOwnerlessParticipant)
	assert.ErrorIs(t, CheckAgentCommunicationSameOwner(owner, nilOwned, mine1), ErrAgentCommunicationOwnerlessParticipant)
	assert.ErrorIs(t, CheckAgentCommunicationSameOwner(uuid.Nil, mine1, mine2), ErrAgentCommunicationIdentifierRequired)
	assert.ErrorIs(t, CheckAgentCommunicationSameOwner(owner, mine1, nil), ErrAgentCommunicationIdentifierRequired)
}

func TestCheckAgentCommunicationParticipantClient(t *testing.T) {
	org := uuid.New()
	otherOrg := uuid.New()
	sa := &ServiceAccount{ID: uuid.New(), OrganizationID: org}
	good := func() *Client {
		saID := sa.ID
		o := org
		return &Client{ID: uuid.New(), ClientID: "agent-a", OrganizationID: &o, ServiceAccountID: &saID,
			TokenEndpointAuthMethod: "private_key_jwt", JWKS: `{"keys":[]}`}
	}
	assert.NoError(t, CheckAgentCommunicationParticipantClient(sa, good()))

	withURI := good()
	withURI.JWKS = ""
	withURI.JWKSUri = "https://agent-a.example.test/jwks.json"
	assert.NoError(t, CheckAgentCommunicationParticipantClient(sa, withURI))

	unbound := good()
	unbound.ServiceAccountID = nil
	assert.ErrorIs(t, CheckAgentCommunicationParticipantClient(sa, unbound), ErrAgentCommunicationClientNotBound)

	otherSA := good()
	x := uuid.New()
	otherSA.ServiceAccountID = &x
	assert.ErrorIs(t, CheckAgentCommunicationParticipantClient(sa, otherSA), ErrAgentCommunicationClientNotBound)

	foreignOrg := good()
	foreignOrg.OrganizationID = &otherOrg
	assert.ErrorIs(t, CheckAgentCommunicationParticipantClient(sa, foreignOrg), ErrAgentCommunicationClientNotBound)

	basic := good()
	basic.TokenEndpointAuthMethod = "client_secret_basic"
	assert.ErrorIs(t, CheckAgentCommunicationParticipantClient(sa, basic), ErrAgentCommunicationClientAuthNotAsymmetric)

	defaulted := good()
	defaulted.TokenEndpointAuthMethod = ""
	assert.ErrorIs(t, CheckAgentCommunicationParticipantClient(sa, defaulted), ErrAgentCommunicationClientAuthNotAsymmetric, "the default method is client_secret_basic")

	public := good()
	public.IsPublic = true
	assert.ErrorIs(t, CheckAgentCommunicationParticipantClient(sa, public), ErrAgentCommunicationClientAuthNotAsymmetric)

	noKeys := good()
	noKeys.JWKS = " "
	assert.ErrorIs(t, CheckAgentCommunicationParticipantClient(sa, noKeys), ErrAgentCommunicationClientAuthNotAsymmetric)

	assert.ErrorIs(t, CheckAgentCommunicationParticipantClient(sa, nil), ErrAgentCommunicationIdentifierRequired)
	assert.True(t, errors.Is(CheckAgentCommunicationParticipantClient(nil, good()), ErrAgentCommunicationIdentifierRequired))
}

func TestValidateAgentCommunicationProofKeyThumbprint(t *testing.T) {
	assert.NoError(t, ValidateAgentCommunicationProofKeyThumbprint("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"))
	assert.ErrorIs(t, ValidateAgentCommunicationProofKeyThumbprint(""), ErrAgentCommunicationProofKeyThumbprintInvalid)
	assert.ErrorIs(t, ValidateAgentCommunicationProofKeyThumbprint("abc="), ErrAgentCommunicationProofKeyThumbprintInvalid, "padding is not base64url-unpadded")
	assert.ErrorIs(t, ValidateAgentCommunicationProofKeyThumbprint(strings.Repeat("a", 129)), ErrAgentCommunicationProofKeyThumbprintInvalid)
}
