package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// AYGHU-3 ISSUANCE + DPoP ledger teeth over POST /api/v1/oauth/token with
// authorization_details type agent_communication. Fixtures live in
// token_agent_communication_test.go.

// RULE: AYGHU-NO-BEARER-1
func TestRule_AYGHU_NO_BEARER_1(t *testing.T) {
	w := newACTokenWorld(t)
	r := w.engine(w.authClient(w.clA1))

	t.Run("agent_communication details without a DPoP proof: refused, no token of any type", func(t *testing.T) {
		rec := postToken(t, r, w.tokenForm(), "")
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		body := tokenJSON(t, rec)
		assert.Equal(t, "invalid_dpop_proof", body["error"])
		_, hasToken := body["access_token"]
		assert.False(t, hasToken)
		assert.NotEqual(t, "Bearer", body["token_type"])
		assert.Equal(t, 0, w.minter.calls, "nothing was minted")
	})

	t.Run("an invalid proof is a refusal too, never a Bearer fallback", func(t *testing.T) {
		rec := postToken(t, r, w.tokenForm(), "not.a.proof")
		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "invalid_dpop_proof", tokenJSON(t, rec)["error"])
		assert.Equal(t, 0, w.minter.calls)
	})

	t.Run("a valid proof yields token_type DPoP with cnf.jkt and no refresh token", func(t *testing.T) {
		rec := postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		body := tokenJSON(t, rec)
		assert.Equal(t, "DPoP", body["token_type"])
		assert.NotEmpty(t, body["access_token"])
		_, hasRefresh := body["refresh_token"]
		assert.False(t, hasRefresh, "no refresh token is ever issued for a participant")
		require.Equal(t, 1, w.minter.calls)
		cnf, ok := w.minter.last.Extra["cnf"].(map[string]any)
		require.True(t, ok, "cnf claim present")
		assert.Equal(t, w.keyA.jkt, cnf["jkt"])
		assert.Equal(t, "agent_communication", w.minter.last.Scope)
	})

	t.Run("CONTROL: a request WITHOUT authorization_details still takes the pre-existing Bearer path", func(t *testing.T) {
		plain := w.engine(&service.AuthenticatedClient{Kind: service.AuthenticatedClientKindOAuth, ClientID: "plain-client", AllowedScopes: []string{"read"}})
		rec := postToken(t, plain, url.Values{"grant_type": {"client_credentials"}}, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "Bearer", tokenJSON(t, rec)["token_type"])
	})
}

// RULE: AYGHU-DPOP-THUMBPRINT-1
func TestRule_AYGHU_DPOP_THUMBPRINT_1(t *testing.T) {
	w := newACTokenWorld(t)
	r := w.engine(w.authClient(w.clA1))

	t.Run("a proof signed by a key that is not the enrolled one is refused", func(t *testing.T) {
		foreign := newDPoPKey(t)
		rec := postToken(t, r, w.tokenForm(), mintDPoP(t, foreign, uuid.NewString()))
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Equal(t, "invalid_dpop_proof", tokenJSON(t, rec)["error"])
		assert.Equal(t, 0, w.minter.calls)
		refusals := w.refusals()
		require.Len(t, refusals, 1)
		assert.Equal(t, "thumbprint_mismatch", refusals[0].Metadata["reason"])
	})

	t.Run("the OTHER participant's enrolled key is refused for this participant", func(t *testing.T) {
		rec := postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyB, uuid.NewString()))
		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "invalid_dpop_proof", tokenJSON(t, rec)["error"])
		assert.Equal(t, 0, w.minter.calls)
	})

	t.Run("the enrolled key is accepted and its thumbprint is the token's cnf.jkt", func(t *testing.T) {
		rec := postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, 1, w.minter.calls)
		cnf := w.minter.last.Extra["cnf"].(map[string]any)
		enrolled := w.auth.Participant(domain.AgentCommunicationRoleInitiator).ProofKeyThumbprint
		assert.Equal(t, enrolled, cnf["jkt"])
		assert.Equal(t, w.keyA.jkt, cnf["jkt"])
	})
}

// RULE: AYGHU-REVOKE-STOPS-ISSUANCE-1
func TestRule_AYGHU_REVOKE_STOPS_ISSUANCE_1(t *testing.T) {
	w := newACTokenWorld(t)
	rA := w.engine(w.authClient(w.clA1))
	rB := w.engine(w.authClient(w.clA2))
	formB := w.tokenForm()
	formB.Set("authorization_details", acTokenDetails(w.auth.ID, w.aci(domain.AgentCommunicationRoleResponder)))

	// Both participants can obtain a token while the authorization is active.
	require.Equal(t, http.StatusOK, postToken(t, rA, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString())).Code)
	require.Equal(t, http.StatusOK, postToken(t, rB, formB, mintDPoP(t, w.keyB, uuid.NewString())).Code)
	require.Equal(t, 2, w.minter.calls)

	// Revoke through the admin surface (the org_admin's emergency revocation).
	_, revokedNow, err := w.svc.RevokeForActor(context.Background(), w.adminA, w.auth.ID, "compromised")
	require.NoError(t, err)
	require.True(t, revokedNow)

	// Neither participant gets a token any more — for both, invalid_grant.
	for name, probe := range map[string]func() int{
		"initiator": func() int { return postToken(t, rA, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString())).Code },
		"responder": func() int { return postToken(t, rB, formB, mintDPoP(t, w.keyB, uuid.NewString())).Code },
	} {
		code := probe()
		assert.Equal(t, http.StatusBadRequest, code, "%s after revocation", name)
	}
	assert.Equal(t, 2, w.minter.calls, "no token minted after revocation")
	refusals := w.refusals()
	require.Len(t, refusals, 2)
	for _, ev := range refusals {
		assert.Equal(t, "authorization_revoked", ev.Metadata["reason"])
	}
	rec := postToken(t, rA, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	assert.Equal(t, "invalid_grant", tokenJSON(t, rec)["error"])
}

// RULE: AYGHU-DPOP-REPLAY-1
func TestRule_AYGHU_DPOP_REPLAY_1(t *testing.T) {
	w := newACTokenWorld(t)
	r := w.engine(w.authClient(w.clA1))
	proof := mintDPoP(t, w.keyA, uuid.NewString())

	first := postToken(t, r, w.tokenForm(), proof)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.Equal(t, 1, w.minter.calls)

	second := postToken(t, r, w.tokenForm(), proof)
	require.Equal(t, http.StatusBadRequest, second.Code, "the same proof presented again is refused")
	assert.Equal(t, "invalid_dpop_proof", tokenJSON(t, second)["error"])
	assert.Equal(t, 1, w.minter.calls, "no second token")
	refusals := w.refusals()
	require.Len(t, refusals, 1)
	assert.Equal(t, "dpop_replay", refusals[0].Metadata["reason"])

	// A fresh jti from the same key is a new proof.
	third := postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusOK, third.Code)
	assert.Equal(t, 2, w.minter.calls)

	// When the replay store cannot answer, the request is NOT judged: 503
	// with a correlation id, never invalid_dpop_proof, and no token.
	w.replays.fail = fmt.Errorf("connection reset by peer")
	outage := postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusServiceUnavailable, outage.Code, outage.Body.String())
	body := tokenJSON(t, outage)
	assert.Equal(t, "temporarily_unavailable", body["error"])
	assert.Equal(t, "auth_store_error", body["reason"])
	assert.Equal(t, body["correlation_id"], outage.Header().Get(mw.CorrelationIDHeader))
	assert.Equal(t, 2, w.minter.calls)
	assert.Len(t, w.refusals(), 1, "an outage is not audited as a refusal")
}
