package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AYGHU-5 INTEGRATION: the spec-named rules the build slices had not yet
// pinned as their own ledger rows. Fixtures live in
// token_agent_communication_test.go and introspection_agent_communication_test.go.

// RULE: AYGHU-OWNER-AT-ISSUANCE-1
func TestRule_AYGHU_OWNER_AT_ISSUANCE_1(t *testing.T) {
	w := newACTokenWorld(t)
	r := w.engine(w.authClient(w.clA1))

	rec := postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusOK, rec.Code, "the owner binding stands: %s", rec.Body.String())

	// Ownership changed after creation: the participant's service account
	// now belongs to someone else — no token, invalid_grant, audited reason.
	other := uuid.New()
	w.saA1.OwnerUserID = &other
	rec = postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "invalid_grant", tokenJSON(t, rec)["error"])
	refusals := w.refusals()
	require.Len(t, refusals, 1)
	assert.Equal(t, "participant_owner_mismatch", refusals[0].Metadata["reason"])

	// An owner binding that disappeared is refused the same way.
	w.saA1.OwnerUserID = nil
	rec = postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "invalid_grant", tokenJSON(t, rec)["error"])
	assert.Equal(t, 1, w.minter.calls, "nothing minted after the owner binding changed")

	// Restored binding issues again (the authorization itself is untouched).
	w.saA1.OwnerUserID = &w.adminA.UserID
	rec = postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusOK, rec.Code)
}

// RULE: AYGHU-ACI-ADDRESS-1
func TestRule_AYGHU_ACI_ADDRESS_1(t *testing.T) {
	w := newACTokenWorld(t)

	// The ACIs are addresses: they are PUBLIC to the owner (the admin surface
	// returns them) and carry nothing that authenticates anyone.
	adminRec := acDo(t, w.acTestWorld.engine(w.adminA), http.MethodGet, acBase+"/"+w.auth.ID.String(), nil)
	require.Equal(t, http.StatusOK, adminRec.Code)
	body := acJSON(t, adminRec)
	parts := body["participants"].([]any)
	require.Len(t, parts, 2)
	aciA := w.aci(domain.AgentCommunicationRoleInitiator)
	aciB := w.aci(domain.AgentCommunicationRoleResponder)
	assert.Equal(t, uuid.Version(7), aciA.Version())
	assert.Equal(t, uuid.Version(7), aciB.Version())

	// Knowing the authorization id and BOTH ACIs yields no token:
	// (a) the other participant's installation naming A's ACI …
	rB := w.engine(w.authClient(w.clA2))
	rec := postToken(t, rB, w.tokenForm(), mintDPoP(t, w.keyB, uuid.NewString()))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "invalid_grant", tokenJSON(t, rec)["error"])
	// (b) … the right installation with a key that is not the enrolled one …
	rA := w.engine(w.authClient(w.clA1))
	rec = postToken(t, rA, w.tokenForm(), mintDPoP(t, newDPoPKey(t), uuid.NewString()))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "invalid_dpop_proof", tokenJSON(t, rec)["error"])
	// (c) … or no authenticated client at all.
	rec = postToken(t, w.engine(nil), w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, 0, w.minter.calls, "an ACI is never a credential")

	// An ACI presented AS a credential is worthless everywhere: as a bearer
	// on the admin surface and as a token at introspection.
	w2 := newACIntrospectWorld(t)
	introRec := postIntrospect(t, w2.introspectEngine(), aciA.String())
	require.Equal(t, http.StatusOK, introRec.Code)
	assert.Equal(t, map[string]any{"active": false}, introspectJSON(t, introRec))

	// Only the participant's own installation with its enrolled key succeeds.
	rec = postToken(t, rA, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, w.minter.calls)
}

// RULE: AYGHU-NO-WIDENING-1
func TestRule_AYGHU_NO_WIDENING_1(t *testing.T) {
	w := newACIntrospectWorld(t)
	admin := w.acTestWorld.engine(w.adminA)
	id := w.auth.ID.String()

	// No update surface exists: PUT / PATCH / DELETE on an authorization are
	// not routes (404), whatever the body.
	widen := map[string]any{"max_messages": 1000, "participants": []map[string]any{{"capabilities": []string{"network.access"}}}}
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := acDo(t, admin, method, acBase+"/"+id, widen)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s must not exist", method)
	}
	stored, err := w.svc.Get(context.Background(), w.orgA, w.auth.ID)
	require.NoError(t, err)
	assert.Equal(t, 10, stored.MaxMessages, "the authorization is untouched")
	assert.Equal(t, w.auth.PolicyDigest, stored.PolicyDigest)

	// A token whose policy digest disagrees with the stored policy is not a
	// token of THIS authorization: introspection reads it inactive.
	tokenA := w.issueFor(t, w.clA1, w.keyA, w.aci(domain.AgentCommunicationRoleInitiator))
	live := introspectJSON(t, postIntrospect(t, w.introspectEngine(), tokenA))
	require.Equal(t, true, live["active"])
	claims, _ := w.minter.claimsFor(tokenA)
	ac := claims.Extra["agent_communication"].(map[string]any)
	ac["policy_digest"] = strings.Repeat("0", 64)
	w.minter.byJTI[claims.JTI] = claims
	widened := introspectJSON(t, postIntrospect(t, w.introspectEngine(), tokenA))
	assert.Equal(t, map[string]any{"active": false}, widened, "a widened policy digest never introspects active")

	// Wider capabilities are a NEW authorization, never an edit of this one.
	body := w.bodyA()
	body["participants"].([]map[string]any)[0]["capabilities"] = []string{"repository.read", "repository.write", "command.execute"}
	rec := acDo(t, admin, http.MethodPost, acBase, body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.NotEqual(t, id, acJSON(t, rec)["id"])
	assert.NotEqual(t, w.auth.PolicyDigest, acJSON(t, rec)["policy_digest"])
}

// RULE: AYGHU-TOKEN-BINDING-1
func TestRule_AYGHU_TOKEN_BINDING_1(t *testing.T) {
	w := newACTokenWorld(t)
	r := w.engine(w.authClient(w.clA1))
	aciA := w.aci(domain.AgentCommunicationRoleInitiator)

	rec := postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	c := w.minter.last
	ac := c.Extra["agent_communication"].(map[string]any)
	cnf := c.Extra["cnf"].(map[string]any)
	assert.Equal(t, w.auth.ID.String(), ac["authorization_id"], "bound to the exact authorization")
	assert.Equal(t, w.auth.SessionID.String(), ac["session_id"], "bound to the session")
	assert.Equal(t, aciA.String(), ac["aci"], "bound to the participant ACI")
	assert.Equal(t, w.clA1.ClientID, c.ClientID, "bound to the OAuth client")
	assert.Equal(t, w.saA1.ID.String(), c.Subject, "bound to the service account")
	assert.Equal(t, w.auth.RelayAudience, c.Audience, "bound to the relay audience")
	assert.Equal(t, w.keyA.jkt, cnf["jkt"], "bound to the proof key")
	for _, forbidden := range []string{"email", "owner_id", "owner_email"} {
		_, present := c.Extra[forbidden]
		assert.False(t, present, "no owner identity in the token (%s)", forbidden)
	}

	// Every binding, when broken, refuses.
	cases := []struct {
		name      string
		form      func() url.Values
		key       dpopKey
		client    *domain.Client
		wantError string
	}{
		{"other participant's ACI", func() url.Values {
			f := w.tokenForm()
			f.Set("authorization_details", acTokenDetails(w.auth.ID, w.aci(domain.AgentCommunicationRoleResponder)))
			return f
		}, w.keyA, w.clA1, "invalid_grant"},
		{"other authorization id", func() url.Values {
			f := w.tokenForm()
			id, _ := uuid.NewV7()
			f.Set("authorization_details", acTokenDetails(id, aciA))
			return f
		}, w.keyA, w.clA1, "invalid_grant"},
		{"other audience", func() url.Values {
			f := w.tokenForm()
			f.Set("audience", "https://relay.example.test/other")
			return f
		}, w.keyA, w.clA1, "invalid_target"},
		{"other proof key", w.tokenForm, newDPoPKey(t), w.clA1, "invalid_dpop_proof"},
		{"other client (the responder's installation)", w.tokenForm, w.keyA, w.clA2, "invalid_grant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := w.minter.calls
			rec := postToken(t, w.engine(w.authClient(tc.client)), tc.form(), mintDPoP(t, tc.key, uuid.NewString()))
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, tc.wantError, tokenJSON(t, rec)["error"])
			assert.Equal(t, before, w.minter.calls, "nothing minted")
		})
	}
}

// RULE: AYGHU-NO-REFRESH-1
func TestRule_AYGHU_NO_REFRESH_1(t *testing.T) {
	w := newACTokenWorld(t)
	r := w.engine(w.authClient(w.clA1))

	rec := postToken(t, r, w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := tokenJSON(t, rec)
	_, hasRefresh := body["refresh_token"]
	assert.False(t, hasRefresh, "a participant token never comes with a refresh token")
	raw := rec.Body.String()
	assert.NotContains(t, raw, "refresh_token")
	access := body["access_token"].(string)

	// The refresh grant cannot prolong a participant's access either: there
	// is nothing to present.
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {access}}
	rec = postToken(t, r, form, "")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.NotEqual(t, "DPoP", tokenJSON(t, rec)["token_type"])
	_, hasToken := tokenJSON(t, rec)["access_token"]
	assert.False(t, hasToken)
	assert.Equal(t, 1, w.minter.calls, "only the one participant token was ever minted")
}

// RULE: AYGHU-TOKEN-AUDIT-SAFE-1
func TestRule_AYGHU_TOKEN_AUDIT_SAFE_1(t *testing.T) {
	w := newACTokenWorld(t)
	r := w.engine(w.authClient(w.clA1))
	proof := mintDPoP(t, w.keyA, uuid.NewString())

	rec := postToken(t, r, w.tokenForm(), proof)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	access := tokenJSON(t, rec)["access_token"].(string)

	foreignProof := mintDPoP(t, newDPoPKey(t), uuid.NewString())
	rec = postToken(t, r, w.tokenForm(), foreignProof)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	events := w.audit.Events()
	require.GreaterOrEqual(t, len(events), 3, "issued + generic oauth_token.issued + refused")
	flat, err := json.Marshal(events)
	require.NoError(t, err)
	body := string(flat)
	for name, secret := range map[string]string{"access token": access, "DPoP proof": proof, "foreign proof": foreignProof, "proof key thumbprint": w.keyA.jkt} {
		assert.NotContains(t, body, secret, "%s must never enter audit metadata", name)
	}
	for _, forbidden := range []string{"\"jwk\"", "private_key", "client_secret", "\"proof\"", "\"token\":"} {
		assert.NotContains(t, body, forbidden)
	}
	// The refusal event names a stable reason code and the client, nothing else.
	var refusal map[string]any
	for _, ev := range events {
		if ev.Action == AuditActionAgentCommunicationTokenRefused {
			refusal = ev.Metadata
		}
	}
	require.NotNil(t, refusal)
	keys := make([]string, 0, len(refusal))
	for k := range refusal {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	assert.Equal(t, []string{"client_id", "reason"}, keys)
	assert.Equal(t, "thumbprint_mismatch", refusal["reason"])
}

// acDo/acJSON/postToken/tokenJSON/postIntrospect/introspectJSON come from the
// sibling fixtures; the helpers below only keep this file self-describing.
var _ = fmt.Sprintf
var _ = httptest.NewRecorder
