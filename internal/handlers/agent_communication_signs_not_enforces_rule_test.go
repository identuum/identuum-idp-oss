package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// AYGHU-6 SPEC RE-BASELINE. The Ayghu file's "Identuum IDP and Identuum AG"
// section draws the line inside Identuum itself:
//
//	"The IDP signs what was authorized. It does not enforce what an agent
//	 may do. Signing a capability is not enforcing it. Enforcement is AG's
//	 job."
//
// with "Identuum IDP must not own … execution policy, tool execution" and
// "Identuum AG owns … session and capability policy … execution
// authorization".
//
// So a capability set must never change an answer this server gives. The
// only thing it may change is the signed policy digest — what was
// authorized — and what the OWNER reads back from the admin surface.

// acAuthzWithCapabilities creates a second authorization for the same two
// participants, carrying caps on the initiator.
func acAuthzWithCapabilities(t *testing.T, w *acIntrospectWorld, caps []string) *domain.AgentCommunicationAuthorization {
	t.Helper()
	a, err := w.svc.CreateForActor(context.Background(), w.adminA, service.CreateAgentCommunicationAuthorizationInput{
		RelayAudience:       w.auth.RelayAudience,
		ExpiresAt:           time.Now().Add(time.Hour),
		MaxMessages:         10,
		MaxMessageSizeBytes: 4096,
		Participants: []service.AgentCommunicationParticipantInput{
			{ServiceAccountID: w.saA1.ID, ClientID: w.clA1.ClientID, Role: domain.AgentCommunicationRoleInitiator,
				ProofKeyThumbprint: w.keyA.jkt, Capabilities: caps},
			{ServiceAccountID: w.saA2.ID, ClientID: w.clA2.ClientID, Role: domain.AgentCommunicationRoleResponder,
				ProofKeyThumbprint: w.keyB.jkt},
		},
	})
	require.NoError(t, err)
	return a
}

// RULE: AYGHU-SIGNS-NOT-ENFORCES-1
func TestRule_AYGHU_SIGNS_NOT_ENFORCES_1(t *testing.T) {
	w := newACIntrospectWorld(t)

	// Communication only (the file: "An empty local-tool capability list
	// means communication only") and the full vocabulary.
	all := make([]string, 0, 7)
	for _, c := range domain.AgentCommunicationCapabilities() {
		all = append(all, string(c))
	}
	communicationOnly := acAuthzWithCapabilities(t, w, nil)
	fullyCapable := acAuthzWithCapabilities(t, w, all)
	require.Empty(t, communicationOnly.Participant(domain.AgentCommunicationRoleInitiator).Capabilities)
	require.Len(t, fullyCapable.Participant(domain.AgentCommunicationRoleInitiator).Capabilities, 7)

	issueAndIntrospect := func(t *testing.T, a *domain.AgentCommunicationAuthorization) map[string]any {
		t.Helper()
		form := w.tokenForm()
		form.Set("authorization_details", acTokenDetails(a.ID, a.Participant(domain.AgentCommunicationRoleInitiator).ACI))
		rec := postToken(t, w.engine(w.authClient(w.clA1)), form, mintDPoP(t, w.keyA, uuid.NewString()))
		// An empty capability set is NOT a refusal: this server does not
		// decide what the agent may do.
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		body := tokenJSON(t, rec)
		assert.Equal(t, "DPoP", body["token_type"])
		intro := introspectJSON(t, postIntrospect(t, w.introspectEngine(), body["access_token"].(string)))
		require.Equal(t, true, intro["active"], "capabilities never make a live token inactive")
		return intro
	}

	introEmpty := issueAndIntrospect(t, communicationOnly)
	introFull := issueAndIntrospect(t, fullyCapable)

	// The two answers differ only in the identifiers and the policy digest —
	// never in a verdict, a scope, a token type or a permission field.
	for _, key := range []string{"active", "token_type", "scope", "client_id", "sub", "aud"} {
		assert.Equal(t, introEmpty[key], introFull[key], "%s must not depend on capabilities", key)
	}
	acEmpty := introEmpty["agent_communication"].(map[string]any)
	acFull := introFull["agent_communication"].(map[string]any)
	assert.NotEqual(t, acEmpty["policy_digest"], acFull["policy_digest"], "the digest is what a capability changes")
	assert.Equal(t, acEmpty["role"], acFull["role"])
	assert.Equal(t, acEmpty["max_messages"], acFull["max_messages"])

	// No capability, and no permission vocabulary at all, rides on the token
	// or on the introspection answer: an enforcement point cannot mistake
	// this server for the authority that grants tool use.
	claims, err := json.Marshal(w.minter.last)
	require.NoError(t, err)
	for _, sample := range append(append([]string{}, all...), "capabilit", "permission", "allow", "deny", "grant") {
		assert.NotContains(t, strings.ToLower(string(claims)), strings.ToLower(sample),
			"a participant token carries no capability or permission vocabulary (%s)", sample)
		for _, intro := range []map[string]any{introEmpty, introFull} {
			raw, err := json.Marshal(intro)
			require.NoError(t, err)
			assert.NotContains(t, strings.ToLower(string(raw)), strings.ToLower(sample),
				"an introspection answer carries no capability or permission vocabulary (%s)", sample)
		}
	}

	// What the server DOES do with a capability: record it, sign it into the
	// digest, and show it to the OWNER — the authority that granted it.
	rec := acDo(t, w.acTestWorld.engine(w.adminA), http.MethodGet, acBase+"/"+fullyCapable.ID.String(), nil)
	require.Equal(t, http.StatusOK, rec.Code)
	parts := acJSON(t, rec)["participants"].([]any)
	require.Len(t, parts, 2)
	var initiator map[string]any
	for _, p := range parts {
		if m := p.(map[string]any); m["role"] == string(domain.AgentCommunicationRoleInitiator) {
			initiator = m
		}
	}
	require.NotNil(t, initiator)
	assert.Len(t, initiator["capabilities"].([]any), 7, "the owner reads back exactly what was authorized")
}
