package domain

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AYGHU-6 SPEC RE-BASELINE. The rewritten Ayghu file states capability
// non-implication as a list of ordered pairs and adds two clauses this
// repository had only in prose: report.final.required is a reporting
// OBLIGATION, not tool authority, and an empty capability list means
// communication only. This rule pins all of it, in BOTH directions, over
// the whole vocabulary — a future implication table would have to break
// this test to exist.

// policyDigestForCaps builds a two-participant policy whose initiator holds
// caps and whose responder holds nothing, and returns its canonical digest.
func policyDigestForCaps(t *testing.T, caps ...AgentCommunicationCapability) string {
	t.Helper()
	strs := make([]string, 0, len(caps))
	for _, c := range caps {
		strs = append(strs, string(c))
	}
	p := AgentCommunicationPolicy{
		PolicyVersion:       AgentCommunicationPolicyVersion,
		MaxMessages:         10,
		MaxMessageSizeBytes: 1024,
		Participants: []AgentCommunicationParticipantPolicy{
			{Role: string(AgentCommunicationRoleInitiator), Capabilities: strs},
			{Role: string(AgentCommunicationRoleResponder), Capabilities: []string{}},
		},
	}
	d, err := p.Digest()
	require.NoError(t, err)
	return d
}

// RULE: AYGHU-CAP-NO-IMPLICATION-1
func TestRule_AYGHU_CAP_NO_IMPLICATION_1(t *testing.T) {
	vocabulary := AgentCommunicationCapabilities()
	require.Len(t, vocabulary, 7, "the closed vocabulary is the seven members the specification names")

	// (1) No member implies any other, in either direction: granting one
	// capability grants exactly that capability and nothing else.
	for _, granted := range vocabulary {
		got, err := CanonicalizeAgentCommunicationCapabilities([]AgentCommunicationCapability{granted})
		require.NoError(t, err)
		require.Equal(t, []AgentCommunicationCapability{granted}, got, "%s must grant itself alone", granted)
		for _, other := range vocabulary {
			if other == granted {
				continue
			}
			assert.NotContains(t, got, other, "%s must not imply %s", granted, other)
			// The two sets are also different POLICIES: a peer or relay that
			// compares digests can never mistake one for the other.
			assert.NotEqual(t, policyDigestForCaps(t, granted), policyDigestForCaps(t, granted, other),
				"holding %s and %s must digest differently from %s alone", granted, other, granted)
		}
	}

	// (2) The ordered pairs the specification names, verbatim.
	for _, pair := range [][2]AgentCommunicationCapability{
		{AgentCapabilityRepositoryRead, AgentCapabilityRepositoryWrite},
		{AgentCapabilityRepositoryWrite, AgentCapabilityCommandExecute},
		{AgentCapabilityTestExecute, AgentCapabilityCommandExecute},
		{AgentCapabilityCommandExecute, AgentCapabilityNetworkAccess},
		{AgentCapabilityNetworkAccess, AgentCapabilityCommandExecute},
	} {
		got, err := CanonicalizeAgentCommunicationCapabilities([]AgentCommunicationCapability{pair[0]})
		require.NoError(t, err)
		assert.NotContains(t, got, pair[1], "%s does not imply %s", pair[0], pair[1])
	}

	// (3) report.final.required is an obligation, never tool authority: alone
	// it carries no repository, command, test or network authority.
	obligation, err := CanonicalizeAgentCommunicationCapabilities(
		[]AgentCommunicationCapability{AgentCapabilityReportFinalRequired})
	require.NoError(t, err)
	require.Equal(t, []AgentCommunicationCapability{AgentCapabilityReportFinalRequired}, obligation)
	for _, c := range obligation {
		for _, toolPrefix := range []string{"repository.", "command.", "test.", "network."} {
			assert.False(t, strings.HasPrefix(string(c), toolPrefix),
				"report.final.required must not carry %s authority", toolPrefix)
		}
	}

	// (4) An empty capability list is communication only: it canonicalizes to
	// an empty (non-nil) set, it is a VALID authorization, and it grants no
	// vocabulary member at all.
	empty, err := CanonicalizeAgentCommunicationCapabilities(nil)
	require.NoError(t, err)
	require.NotNil(t, empty)
	assert.Empty(t, empty, "an empty list means communication only")
	now := time.Now().UTC()
	a := agentCommFixture(t, now)
	for i := range a.Participants {
		a.Participants[i].Capabilities = []AgentCommunicationCapability{}
	}
	digest, err := a.ComputePolicyDigest()
	require.NoError(t, err)
	a.PolicyDigest = digest
	require.NoError(t, a.Validate(now), "a communication-only authorization is valid")
	for _, p := range a.Participants {
		assert.Empty(t, p.Capabilities)
	}

	// (5) Unknown capabilities fail closed, and a set containing one is
	// refused whole — never partially granted.
	for _, unknown := range []string{"repository.delete", "command.*", "REPOSITORY.READ", "repository.read.write", "admin"} {
		_, err := ParseAgentCommunicationCapability(unknown)
		assert.ErrorIs(t, err, ErrAgentCommunicationUnknownCapability, "%q must fail closed", unknown)
	}
	partial, err := CanonicalizeAgentCommunicationCapabilities([]AgentCommunicationCapability{
		AgentCapabilityRepositoryRead, "repository.delete",
	})
	assert.ErrorIs(t, err, ErrAgentCommunicationUnknownCapability)
	assert.Nil(t, partial, "an unknown member refuses the whole set")

	// (6) Nothing widens a set: canonicalization only sorts and deduplicates,
	// so the output is always a subset of the input.
	input := []AgentCommunicationCapability{
		AgentCapabilityRepositoryWrite, AgentCapabilityRepositoryWrite, AgentCapabilityTestExecute,
	}
	out, err := CanonicalizeAgentCommunicationCapabilities(input)
	require.NoError(t, err)
	assert.Equal(t, []AgentCommunicationCapability{AgentCapabilityRepositoryWrite, AgentCapabilityTestExecute}, out)
	for _, c := range out {
		assert.Contains(t, input, c, "canonicalization never adds a capability")
	}
}
