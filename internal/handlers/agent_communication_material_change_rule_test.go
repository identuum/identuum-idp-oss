package handlers

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AYGHU-6 SPEC RE-BASELINE. The rewritten Ayghu file names the material
// changes that require renewed consent — "Participants, Session limits,
// Relay audience, Expiration, Proof keys, Capabilities, Other authorization
// semantics" — and states that changing capabilities "requires a new
// authorization". This rule pins that an authorization is never edited: no
// route mutates one, the store refuses every non-revocation UPDATE, and a
// materially different policy is a different digest, so an old token can
// never speak for a changed policy.

// materialChangeSQL reads the shipped 0037 migration text. The store is the
// last line of defence: even a direct writer with database access cannot
// widen an authorization.
func materialChangeSQL(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../migrations/0037_agent_communication_authorizations.sql")
	require.NoError(t, err, "the agent-communication migration must be readable")
	return string(b)
}

// RULE: AYGHU-MATERIAL-CHANGE-1
func TestRule_AYGHU_MATERIAL_CHANGE_1(t *testing.T) {
	// (1) No route edits an authorization. The mounted surface is exactly
	// four routes and none of them is an update verb.
	engine := newACWorld(t).engine(nil)
	methods := map[string]int{}
	for _, r := range engine.Routes() {
		require.True(t, strings.HasPrefix(r.Path, "/api/v1/agent-communication-authorizations"), "unexpected route %s %s", r.Method, r.Path)
		methods[r.Method]++
		assert.NotEqual(t, http.MethodPut, r.Method, "no edit route may exist: %s", r.Path)
		assert.NotEqual(t, http.MethodPatch, r.Method, "no edit route may exist: %s", r.Path)
		assert.NotEqual(t, http.MethodDelete, r.Method, "no delete route may exist: %s", r.Path)
	}
	assert.Equal(t, map[string]int{http.MethodPost: 2, http.MethodGet: 2}, methods,
		"create, list, read and revoke — nothing else")

	// (2) The store refuses every material UPDATE. The authorization changes
	// only through its revocation columns; each material dimension is named
	// in the guard.
	sql := materialChangeSQL(t)
	require.Contains(t, sql, "CREATE TRIGGER trg_aca_revocation_only")
	require.Contains(t, sql, "BEFORE UPDATE ON agent_communication_authorizations")
	guardStart := strings.Index(sql, "agent_communication_authorizations_revocation_only()")
	require.Positive(t, guardStart, "the revocation-only guard must exist")
	guardEnd := strings.Index(sql[guardStart:], "CREATE TRIGGER trg_aca_revocation_only")
	require.Positive(t, guardEnd, "the guard must be followed by its trigger")
	guard := sql[guardStart : guardStart+guardEnd]
	for dimension, column := range map[string]string{
		"session limits (count)": "NEW.max_messages IS DISTINCT FROM OLD.max_messages",
		"session limits (size)":  "NEW.max_message_size_bytes IS DISTINCT FROM OLD.max_message_size_bytes",
		"relay audience":         "NEW.relay_audience IS DISTINCT FROM OLD.relay_audience",
		"expiration":             "NEW.expires_at IS DISTINCT FROM OLD.expires_at",
		"session identity":       "NEW.session_id IS DISTINCT FROM OLD.session_id",
		"owner":                  "NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id",
		"organization":           "NEW.organization_id IS DISTINCT FROM OLD.organization_id",
		"policy digest":          "NEW.policy_digest IS DISTINCT FROM OLD.policy_digest",
		"policy version":         "NEW.policy_version IS DISTINCT FROM OLD.policy_version",
	} {
		assert.Contains(t, guard, column, "a material change to the %s must be refused by the store", dimension)
	}

	// (3) Participants — and with them proof keys and capabilities — are
	// immutable rows: ANY update raises, and the pair is closed.
	require.Contains(t, sql, "CREATE OR REPLACE FUNCTION agent_communication_participants_immutable()")
	require.Contains(t, sql, "CREATE TRIGGER trg_acp_immutable")
	immutableStart := strings.Index(sql, "CREATE TRIGGER trg_acp_immutable")
	assert.Contains(t, sql[immutableStart:immutableStart+120], "BEFORE UPDATE ON agent_communication_participants",
		"every participant column — proof key and capabilities included — is immutable")
	assert.Contains(t, sql, "RAISE EXCEPTION 'agent communication participant % is immutable'")
	assert.Contains(t, sql, "CREATE CONSTRAINT TRIGGER trg_acp_two_participants",
		"a participant may not be added or removed either")

	// (4) A materially different policy is a DIFFERENT authorization: the
	// digest the token carries changes with the limits, the capabilities and
	// the participant roles, so a token minted under the old policy can never
	// pass for the new one.
	base := newACPolicyFixture()
	baseDigest, err := base.Digest()
	require.NoError(t, err)
	for name, mutate := range map[string]func(p *domain.AgentCommunicationPolicy){
		"message count limit": func(p *domain.AgentCommunicationPolicy) { p.MaxMessages += 1 },
		"message size limit":  func(p *domain.AgentCommunicationPolicy) { p.MaxMessageSizeBytes += 1 },
		"capabilities": func(p *domain.AgentCommunicationPolicy) {
			p.Participants[0].Capabilities = append(p.Participants[0].Capabilities, string(domain.AgentCapabilityNetworkAccess))
		},
		"participant set": func(p *domain.AgentCommunicationPolicy) {
			p.Participants[1].Capabilities = []string{string(domain.AgentCapabilityCommandExecute)}
		},
		"policy version": func(p *domain.AgentCommunicationPolicy) { p.PolicyVersion = "v2" },
	} {
		changed := newACPolicyFixture()
		mutate(&changed)
		got, err := changed.Digest()
		require.NoError(t, err)
		assert.NotEqual(t, baseDigest, got, "a change of the %s must be a new policy, never an edit", name)
	}

	// Re-ordering is NOT a material change: the same authorization digests
	// identically however its rows are ordered.
	reordered := newACPolicyFixture()
	reordered.Participants[0], reordered.Participants[1] = reordered.Participants[1], reordered.Participants[0]
	reorderedDigest, err := reordered.Digest()
	require.NoError(t, err)
	assert.Equal(t, baseDigest, reorderedDigest, "row order is not a material change")
}

// newACPolicyFixture is a two-participant policy with one capability on the
// initiator: the smallest policy that can show a material change.
func newACPolicyFixture() domain.AgentCommunicationPolicy {
	return domain.AgentCommunicationPolicy{
		PolicyVersion:       domain.AgentCommunicationPolicyVersion,
		MaxMessages:         10,
		MaxMessageSizeBytes: 1024,
		Participants: []domain.AgentCommunicationParticipantPolicy{
			{Role: string(domain.AgentCommunicationRoleInitiator), Capabilities: []string{string(domain.AgentCapabilityRepositoryRead)}},
			{Role: string(domain.AgentCommunicationRoleResponder), Capabilities: []string{}},
		},
	}
}
