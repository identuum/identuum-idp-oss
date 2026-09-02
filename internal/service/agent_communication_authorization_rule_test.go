package service

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AYGHU-1 FOUNDATION ledger teeth. Each test below is the armed check of
// one ledger row; the fixtures live in agent_communication_authorization_service_test.go.

// RULE: AYGHU-SAME-OWNER-1
func TestRule_AYGHU_SAME_OWNER_1(t *testing.T) {
	ctx := context.Background()

	t.Run("ownerless participant is refused", func(t *testing.T) {
		f := newACFixture(t)
		f.saB.OwnerUserID = nil
		_, err := f.svc.Create(ctx, f.input())
		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrAgentCommunicationOwnerlessParticipant)
		assert.Equal(t, 0, f.repo.createCalls, "nothing persisted")
	})

	t.Run("participant owned by someone else is refused", func(t *testing.T) {
		f := newACFixture(t)
		other := uuid.New()
		f.saA.OwnerUserID = &other
		_, err := f.svc.Create(ctx, f.input())
		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrAgentCommunicationOwnerMismatch)
		assert.Equal(t, 0, f.repo.createCalls, "nothing persisted")
	})

	t.Run("creating owner who owns neither participant is refused", func(t *testing.T) {
		f := newACFixture(t)
		in := f.input()
		in.OwnerID = uuid.New()
		_, err := f.svc.Create(ctx, in)
		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrAgentCommunicationOwnerMismatch)
		assert.Equal(t, 0, f.repo.createCalls, "nothing persisted")
	})

	t.Run("both participants owned by the creating owner are accepted", func(t *testing.T) {
		f := newACFixture(t)
		a, err := f.svc.Create(ctx, f.input())
		require.NoError(t, err)
		assert.Equal(t, f.owner, a.OwnerID)
		require.Len(t, a.Participants, 2)
		for _, p := range a.Participants {
			sa := f.sas.rows[p.ServiceAccountID]
			require.NotNil(t, sa)
			require.NotNil(t, sa.OwnerUserID)
			assert.Equal(t, f.owner, *sa.OwnerUserID)
		}
		assert.Equal(t, 1, f.repo.createCalls)
	})
}

// RULE: AYGHU-TWO-PARTICIPANTS-1
func TestRule_AYGHU_TWO_PARTICIPANTS_1(t *testing.T) {
	ctx := context.Background()

	for _, n := range []int{0, 1, 3} {
		f := newACFixture(t)
		in := f.input()
		switch n {
		case 0:
			in.Participants = nil
		case 1:
			in.Participants = in.Participants[:1]
		case 3:
			third := in.Participants[0]
			third.Role = "observer"
			in.Participants = append(in.Participants, third)
		}
		_, err := f.svc.Create(ctx, in)
		require.Error(t, err, "%d participants", n)
		assert.ErrorIs(t, err, domain.ErrAgentCommunicationParticipantCount, "%d participants", n)
		assert.Equal(t, 0, f.sas.calls, "%d participants: refused before any lookup", n)
		assert.Equal(t, 0, f.repo.createCalls, "%d participants: nothing persisted", n)
	}

	t.Run("two participants with the same role are refused", func(t *testing.T) {
		f := newACFixture(t)
		in := f.input()
		in.Participants[1].Role = domain.AgentCommunicationRoleInitiator
		_, err := f.svc.Create(ctx, in)
		assert.ErrorIs(t, err, domain.ErrAgentCommunicationDuplicateRole)
		assert.Equal(t, 0, f.repo.createCalls)
	})

	t.Run("the same service account twice is refused", func(t *testing.T) {
		f := newACFixture(t)
		in := f.input()
		in.Participants[1].ServiceAccountID = in.Participants[0].ServiceAccountID
		_, err := f.svc.Create(ctx, in)
		assert.ErrorIs(t, err, domain.ErrAgentCommunicationDuplicateServiceAccount)
		assert.Equal(t, 0, f.repo.createCalls)
	})

	t.Run("exactly two distinct participants are persisted atomically", func(t *testing.T) {
		f := newACFixture(t)
		a, err := f.svc.Create(ctx, f.input())
		require.NoError(t, err)
		stored := f.repo.rows[a.ID]
		require.NotNil(t, stored)
		require.Len(t, stored.Participants, 2)
		assert.NotEqual(t, stored.Participants[0].ACI, stored.Participants[1].ACI)
		assert.NotEqual(t, stored.Participants[0].ServiceAccountID, stored.Participants[1].ServiceAccountID)
		assert.NotNil(t, stored.Participant(domain.AgentCommunicationRoleInitiator))
		assert.NotNil(t, stored.Participant(domain.AgentCommunicationRoleResponder))
		assert.Equal(t, 1, f.repo.createCalls, "one atomic write")

		// The aggregate itself refuses any other count.
		clone := *stored
		clone.Participants = stored.Participants[:1]
		assert.ErrorIs(t, clone.Validate(f.now), domain.ErrAgentCommunicationParticipantCount)
	})
}

// RULE: AYGHU-POLICY-DIGEST-1
func TestRule_AYGHU_POLICY_DIGEST_1(t *testing.T) {
	ctx := context.Background()
	f := newACFixture(t)

	in := f.input()
	in.Participants[0].Capabilities = []string{"test.execute", "repository.read", "test.execute", "command.execute"}
	in.Participants[1].Capabilities = []string{"repository.write"}
	a, err := f.svc.Create(ctx, in)
	require.NoError(t, err)

	raw, err := hex.DecodeString(a.PolicyDigest)
	require.NoError(t, err)
	assert.Len(t, raw, 32, "SHA-256, lowercase hex")

	recomputed, err := a.ComputePolicyDigest()
	require.NoError(t, err)
	assert.Equal(t, recomputed, a.PolicyDigest, "the persisted digest is the digest of the canonical policy")

	canonical, err := a.Policy().Canonical()
	require.NoError(t, err)
	assert.Equal(t,
		`{"policy_version":"v1","max_messages":10,"max_message_size_bytes":4096,"participants":[{"role":"initiator","capabilities":["command.execute","repository.read","test.execute"]},{"role":"responder","capabilities":["repository.write"]}]}`,
		string(canonical), "canonical bytes: version, limits, participants by role, capabilities sorted and deduplicated")

	// The typed policy canonicalizes by itself: an unsorted, duplicated
	// capability list digests identically to the stored canonical one.
	unsorted := a.Policy()
	unsorted.Participants[0].Capabilities = []string{"test.execute", "repository.read", "command.execute", "test.execute"}
	du, err := unsorted.Digest()
	require.NoError(t, err)
	assert.Equal(t, a.PolicyDigest, du, "Canonical() sorts and deduplicates capabilities itself")

	// The same policy given in another order, with fresh identifiers and a
	// later clock, digests identically.
	f.now = f.now.Add(time.Minute)
	shuffled := f.input()
	shuffled.Participants = []AgentCommunicationParticipantInput{in.Participants[1], in.Participants[0]}
	shuffled.Participants[1].Capabilities = []string{"command.execute", "test.execute", "repository.read"}
	shuffled.RelayAudience = "https://another-relay.example.test/x"
	b, err := f.svc.Create(ctx, shuffled)
	require.NoError(t, err)
	assert.NotEqual(t, a.ID, b.ID)
	assert.NotEqual(t, a.Participants[0].ACI, b.Participants[0].ACI)
	assert.Equal(t, a.PolicyDigest, b.PolicyDigest, "input order, identifiers, timestamps and audience are not digest inputs")

	// Widening one participant's capabilities changes the digest.
	wider := f.input()
	wider.Participants[0].Capabilities = []string{"test.execute", "repository.read", "command.execute", "network.access"}
	wider.Participants[1].Capabilities = []string{"repository.write"}
	c, err := f.svc.Create(ctx, wider)
	require.NoError(t, err)
	assert.NotEqual(t, a.PolicyDigest, c.PolicyDigest)

	// So does a session limit or the policy version.
	limit := a.Policy()
	limit.MaxMessages++
	dl, err := limit.Digest()
	require.NoError(t, err)
	assert.NotEqual(t, a.PolicyDigest, dl)
	ver := a.Policy()
	ver.PolicyVersion = "v2"
	dv, err := ver.Digest()
	require.NoError(t, err)
	assert.NotEqual(t, a.PolicyDigest, dv)
}
