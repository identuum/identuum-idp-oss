package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/types"
)

// AYGHU-6 SPEC RE-BASELINE. The rewritten Ayghu file splits the product in
// two and states the identity provider's NEGATIVE obligations outright:
// "The identity provider must never receive prompt contents", "The identity
// provider must not possess message encryption private keys", "Conversation
// transcripts and final reports are local Ayghu concerns — the identity
// provider does not store them", and the v1 exclusion list "Identity-provider
// access to message plaintext / transcripts / repository data".
//
// Those are invariants of a SURFACE, so this rule audits the surface: every
// field of every agent-communication type the IdP stores or puts on the wire,
// every claim key of an issued participant token, every key of an
// introspection answer, and every endpoint of the canonical census. A field
// or a route that could carry prompt text, message content, a transcript, a
// report or an encryption private key makes this test fail.

// forbiddenSurfaceTokens are substrings no agent-communication field name,
// json name, claim key or endpoint path may contain. They name CONTENT and
// KEY MATERIAL — the two things the identity provider must never hold.
var forbiddenSurfaceTokens = []string{
	"prompt", "transcript", "plaintext", "ciphertext", "encrypt", "decrypt",
	"privatekey", "private_key", "content", "payload", "conversation",
	"attachment", "report", "queue", "envelope",
}

func assertNoForbiddenToken(t *testing.T, where, name string) {
	t.Helper()
	lower := strings.ToLower(name)
	for _, bad := range forbiddenSurfaceTokens {
		assert.NotContains(t, lower, bad,
			"%s: %q carries %q — the identity provider must never hold prompt content, transcripts or encryption keys", where, name, bad)
	}
}

// walkSurfaceType asserts every field name and json name of typ (recursively
// through structs, pointers, slices and maps) is free of forbidden tokens.
func walkSurfaceType(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	for typ.Kind() == reflect.Ptr || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return
	}
	seen[typ] = true
	where := typ.PkgPath() + "." + typ.Name()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		assertNoForbiddenToken(t, where, f.Name)
		if tag := strings.Split(f.Tag.Get("json"), ",")[0]; tag != "" && tag != "-" {
			assertNoForbiddenToken(t, where, tag)
		}
		walkSurfaceType(t, f.Type, seen)
	}
}

// RULE: AYGHU-NO-PROMPT-CONTENT-1
func TestRule_AYGHU_NO_PROMPT_CONTENT_1(t *testing.T) {
	// (1) Stored and wire types: the aggregate, the participant, the issued
	// token record, the policy, the admin request bodies, the admin response
	// projection and the introspection projection.
	seen := map[reflect.Type]bool{}
	for _, sample := range []any{
		domain.AgentCommunicationAuthorization{},
		domain.AgentCommunicationParticipant{},
		domain.AgentCommunicationPolicy{},
		domain.AgentCommunicationToken{},
		types.AgentCommunicationAuthorization{},
		types.AgentCommunicationAuthorizationList{},
		agentCommunicationCreateRequest{},
		agentCommunicationParticipantRequest{},
		agentCommunicationRevokeRequest{},
		service.AgentCommunicationTokenRequest{},
		service.AgentCommunicationIssuanceRecord{},
		service.IntrospectionAgentCommunication{},
	} {
		walkSurfaceType(t, reflect.TypeOf(sample), seen)
	}
	require.NotEmpty(t, seen, "the surface must actually have been walked")

	// (2) An issued participant token: every claim key, top level and inside
	// the agent_communication projection.
	w := newACTokenWorld(t)
	rec := postToken(t, w.engine(w.authClient(w.clA1)), w.tokenForm(), mintDPoP(t, w.keyA, uuid.NewString()))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	claims := w.minter.last
	for k := range claims.Extra {
		assertNoForbiddenToken(t, "token claim", k)
	}
	ac, ok := claims.Extra["agent_communication"].(map[string]any)
	require.True(t, ok, "the participant projection must be present")
	for k := range ac {
		assertNoForbiddenToken(t, "agent_communication claim", k)
	}

	// (3) An introspection answer: every key of the live body, at every depth.
	w2 := newACIntrospectWorld(t)
	token := w2.issueFor(t, w2.clA1, w2.keyA, w2.aci(domain.AgentCommunicationRoleInitiator))
	introRec := postIntrospect(t, w2.introspectEngine(), token)
	require.Equal(t, http.StatusOK, introRec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(introRec.Body.Bytes(), &body))
	require.Equal(t, true, body["active"], introRec.Body.String())
	var walkKeys func(prefix string, v any)
	walkKeys = func(prefix string, v any) {
		switch typed := v.(type) {
		case map[string]any:
			for k, sub := range typed {
				assertNoForbiddenToken(t, "introspection "+prefix, k)
				walkKeys(prefix+"."+k, sub)
			}
		case []any:
			for _, sub := range typed {
				walkKeys(prefix, sub)
			}
		}
	}
	walkKeys("body", body)

	// (4) The canonical endpoint census: no route anywhere in the product
	// carries messages, prompts, transcripts or reports.
	manifest, err := os.ReadFile("../../tools/api-docgen/testdata/endpoints.manifest.txt")
	require.NoError(t, err, "the canonical endpoint manifest must be readable")
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	require.Greater(t, len(lines), 100, "the manifest must be the whole census")
	agentRoutes := 0
	for _, line := range lines {
		path := strings.TrimSpace(line)
		if path == "" {
			continue
		}
		lower := strings.ToLower(path)
		for _, bad := range []string{"prompt", "transcript", "message", "conversation", "report", "attachment", "upload"} {
			assert.NotContains(t, lower, bad, "no endpoint may carry %q: %s", bad, path)
		}
		if strings.Contains(lower, "agent-communication") {
			agentRoutes++
		}
	}
	assert.Equal(t, 4, agentRoutes, "the agent-communication surface is exactly the four authorization routes")
}
