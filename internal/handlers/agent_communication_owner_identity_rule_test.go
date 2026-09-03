package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AYGHU-6 SPEC RE-BASELINE. "Ayghu must not infer owner identity from
// messages", "Owner identity must never be trusted because a remote
// participant asserted it" and "Peers must never compare asserted owner
// identities in messages — the identity layer establishes participant
// authorization."
//
// The identity provider makes that rule enforceable by never handing peers
// an owner identity to compare in the first place: neither a participant
// token nor an introspection answer carries the owner. What a peer receives
// is the participant binding — authorization, session, ACI, role, client,
// service account, proof key.

// ownerIdentityKeys are claim / response key names that would hand a peer an
// owner identity to compare.
var ownerIdentityKeys = []string{
	"owner", "owner_id", "owner_user_id", "owner_email", "owner_name",
	"email", "username", "preferred_username", "name", "given_name",
	"family_name", "user_id", "human", "created_by", "revoked_by",
}

func assertNoOwnerIdentityKeys(t *testing.T, where string, keys []string) {
	t.Helper()
	for _, k := range keys {
		lower := strings.ToLower(k)
		for _, forbidden := range ownerIdentityKeys {
			assert.NotEqual(t, forbidden, lower, "%s must not carry an owner identity (%s)", where, k)
		}
	}
}

// RULE: AYGHU-NO-OWNER-IDENTITY-1
func TestRule_AYGHU_NO_OWNER_IDENTITY_1(t *testing.T) {
	// (1) The participant token. The owner of this authorization is the
	// org_admin who created it; nothing in the signed claim set names them.
	w := newACTokenWorld(t)
	rec := postToken(t, w.engine(w.authClient(w.clA1)), w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	claims := w.minter.last
	owner := w.adminA.UserID.String()
	ownerEmail := w.adminA.Email
	require.NotEmpty(t, ownerEmail)

	keys := make([]string, 0, len(claims.Extra))
	for k := range claims.Extra {
		keys = append(keys, k)
	}
	assertNoOwnerIdentityKeys(t, "the token claim set", keys)
	ac, ok := claims.Extra["agent_communication"].(map[string]any)
	require.True(t, ok)
	acKeys := make([]string, 0, len(ac))
	for k := range ac {
		acKeys = append(acKeys, k)
	}
	assertNoOwnerIdentityKeys(t, "the agent_communication claim", acKeys)

	// The subject is the participant's own service account — never the owner.
	assert.Equal(t, w.saA1.ID.String(), claims.Subject)
	assert.NotEqual(t, owner, claims.Subject)

	// And no owner value hides anywhere in the serialized claim set.
	encoded, err := json.Marshal(claims)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), owner, "the owner's id must not appear in a token")
	assert.NotContains(t, string(encoded), ownerEmail, "the owner's email must not appear in a token")

	// (2) The introspection answer a relay or peer receives. Both
	// participants introspect active, and neither answer names the owner.
	w2 := newACIntrospectWorld(t)
	owner2 := w2.adminA.UserID.String()
	for _, role := range []domain.AgentCommunicationParticipantRole{
		domain.AgentCommunicationRoleInitiator,
		domain.AgentCommunicationRoleResponder,
	} {
		client, key := w2.clA1, w2.keyA
		if role == domain.AgentCommunicationRoleResponder {
			client, key = w2.clA2, w2.keyB
		}
		token := w2.issueFor(t, client, key, w2.aci(role))
		introRec := postIntrospect(t, w2.introspectEngine(), token)
		require.Equal(t, http.StatusOK, introRec.Code)
		raw := introRec.Body.String()

		var body map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &body))
		require.Equal(t, true, body["active"], raw)

		var collect func(v any) []string
		collect = func(v any) []string {
			out := []string{}
			switch typed := v.(type) {
			case map[string]any:
				for k, sub := range typed {
					out = append(out, k)
					out = append(out, collect(sub)...)
				}
			case []any:
				for _, sub := range typed {
					out = append(out, collect(sub)...)
				}
			}
			return out
		}
		assertNoOwnerIdentityKeys(t, "the introspection answer ("+string(role)+")", collect(body))
		assert.NotContains(t, raw, owner2, "the owner's id must not appear in an introspection answer")
		assert.NotContains(t, raw, w2.adminA.Email, "the owner's email must not appear in an introspection answer")

		// What the peer DOES get is the participant binding.
		acProjection, ok := body["agent_communication"].(map[string]any)
		require.True(t, ok, raw)
		assert.Equal(t, w2.aci(role).String(), acProjection["aci"])
		assert.Equal(t, string(role), acProjection["role"])
		assert.Equal(t, w2.auth.SessionID.String(), acProjection["session_id"])
	}
}
