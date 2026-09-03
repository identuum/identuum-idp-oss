package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// AYGHU-4 ledger teeth over POST /api/v1/oauth/introspection for
// participant tokens. Fixtures live in introspection_agent_communication_test.go.

// RULE: AYGHU-REVOKED-INACTIVE-1
func TestRule_AYGHU_REVOKED_INACTIVE_1(t *testing.T) {
	w := newACIntrospectWorld(t)
	r := w.introspectEngine()
	tokenA := w.issueFor(t, w.clA1, w.keyA, w.aci(domain.AgentCommunicationRoleInitiator))
	tokenB := w.issueFor(t, w.clA2, w.keyB, w.aci(domain.AgentCommunicationRoleResponder))
	claimsA, _ := w.minter.claimsFor(tokenA)
	claimsB, _ := w.minter.claimsFor(tokenB)

	// Issuance recorded both jtis bound to the authorization.
	require.Len(t, w.issued.rows, 2)
	for _, row := range w.issued.rows {
		assert.Equal(t, w.auth.ID, row.AuthorizationID)
	}

	for name, tok := range map[string]string{"initiator": tokenA, "responder": tokenB} {
		body := introspectJSON(t, postIntrospect(t, r, tok))
		require.Equal(t, true, body["active"], "%s active before revocation", name)
	}

	// Revoke through the admin surface: the authorization row is stamped
	// AND every live jti is written to the revocation store at once.
	_, revokedNow, err := w.svc.RevokeForActor(context.Background(), w.adminA, w.auth.ID, "compromised")
	require.NoError(t, err)
	require.True(t, revokedNow)
	assert.Contains(t, w.jtis.revoked, claimsA.JTI, "the initiator's jti is revoked immediately")
	assert.Contains(t, w.jtis.revoked, claimsB.JTI, "the responder's jti is revoked immediately")

	for name, tok := range map[string]string{"initiator": tokenA, "responder": tokenB} {
		body := introspectJSON(t, postIntrospect(t, r, tok))
		assert.Equal(t, map[string]any{"active": false}, body, "%s inactive right after revocation, long before expiry", name)
	}

	// Even a consumer that only knows the jti list sees the revocation.
	for _, jti := range []string{claimsA.JTI, claimsB.JTI} {
		revoked, err := w.jtis.IsRevoked(context.Background(), jti)
		require.NoError(t, err)
		assert.True(t, revoked)
	}
}

// RULE: AYGHU-INTROSPECT-503-1
func TestRule_AYGHU_INTROSPECT_503_1(t *testing.T) {
	w := newACIntrospectWorld(t)
	r := w.introspectEngine()
	tokenA := w.issueFor(t, w.clA1, w.keyA, w.aci(domain.AgentCommunicationRoleInitiator))

	assert503 := func(t *testing.T, name string) {
		t.Helper()
		rec := postIntrospect(t, r, tokenA)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "%s: got %d %s", name, rec.Code, rec.Body.String())
		body := introspectJSON(t, rec)
		assert.Equal(t, "temporarily_unavailable", body["error"], name)
		assert.Equal(t, "auth_store_error", body["reason"], name)
		cid, _ := body["correlation_id"].(string)
		assert.NotEmpty(t, cid, name)
		assert.Equal(t, cid, rec.Header().Get(mw.CorrelationIDHeader), name)
		_, hasActive := body["active"]
		assert.False(t, hasActive, "%s: an unjudged token is never presented as a judged verdict", name)
	}

	w.repo.fail = fmt.Errorf("dial tcp 10.0.0.9:5432: connect: connection refused")
	assert503(t, "authorization store")
	w.repo.fail = nil

	w.clients.fail = fmt.Errorf("read tcp: i/o timeout")
	assert503(t, "client store")
	w.clients.fail = nil

	w.jtis.fail = fmt.Errorf("pq: the database system is shutting down")
	assert503(t, "jti revocation store")
	w.jtis.fail = nil

	// Healthy again: the verdict is a verdict.
	body := introspectJSON(t, postIntrospect(t, r, tokenA))
	assert.Equal(t, true, body["active"])
}

// RULE: AYGHU-INTROSPECT-NO-KEYS-1
func TestRule_AYGHU_INTROSPECT_NO_KEYS_1(t *testing.T) {
	w := newACIntrospectWorld(t)
	r := w.introspectEngine()
	proof := mintDPoP(t, w.keyA, "jti-for-no-keys")
	form := w.tokenForm()
	rec := postToken(t, w.engine(w.authClient(w.clA1)), form, proof)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	tokenA := tokenJSON(t, rec)["access_token"].(string)

	res := postIntrospect(t, r, tokenA)
	require.Equal(t, http.StatusOK, res.Code)
	body := introspectJSON(t, res)
	require.Equal(t, true, body["active"])

	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	allowed := map[string]bool{"active": true, "scope": true, "client_id": true, "token_type": true, "exp": true, "iat": true, "nbf": true, "sub": true, "aud": true, "iss": true, "jti": true, "cnf": true, "authorization_details": true, "agent_communication": true, "username": true}
	for _, k := range keys {
		assert.True(t, allowed[k], "top-level key %q is not in the safe set", k)
	}
	cnf, ok := body["cnf"].(map[string]any)
	require.True(t, ok, "cnf present")
	assert.Equal(t, map[string]any{"jkt": w.keyA.jkt}, cnf, "cnf carries the RFC 7638 thumbprint and NOTHING else")
	ac := body["agent_communication"].(map[string]any)
	acKeys := make([]string, 0, len(ac))
	for k := range ac {
		acKeys = append(acKeys, k)
	}
	sort.Strings(acKeys)
	assert.Equal(t, []string{"aci", "authorization_expires_at", "authorization_id", "max_message_size_bytes", "max_messages", "policy_digest", "policy_version", "role", "session_id"}, acKeys)

	// authorization_details is exactly the accepted closed detail — never a
	// dump of the token's other claims.
	details, ok := body["authorization_details"].([]any)
	require.True(t, ok, "authorization_details is the accepted array: %v", body["authorization_details"])
	require.Len(t, details, 1)
	detail := details[0].(map[string]any)
	detailKeys := make([]string, 0, len(detail))
	for k := range detail {
		detailKeys = append(detailKeys, k)
	}
	sort.Strings(detailKeys)
	assert.Equal(t, []string{"aci", "authorization_id", "type"}, detailKeys)
	assert.Equal(t, "agent_communication", detail["type"])

	raw := res.Body.String()
	for _, forbidden := range []string{`"jwk"`, `"x":`, `"n":`, `"e":`, `"d":`, `"crv"`, `"kty"`, proof, tokenA, "proof_key_thumbprint"} {
		assert.NotContains(t, raw, forbidden, "introspection must never carry key material, the proof or the token")
	}
	assert.False(t, strings.Contains(raw, "capabilit"), "no capability descriptions")
}
