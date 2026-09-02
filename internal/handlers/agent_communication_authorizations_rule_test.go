package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// AYGHU-2 ADMIN API ledger teeth over /api/v1/agent-communication-authorizations.
// Fixtures live in agent_communication_authorizations_test.go.

// RULE: AYGHU-ORG-SCOPE-1
func TestRule_AYGHU_ORG_SCOPE_1(t *testing.T) {
	w := newACWorld(t)
	own := w.seed(t, w.adminA, w.saA1, w.clA1, w.saA2, w.clA2)
	foreign := w.seed(t, w.adminB, w.saB1, w.clB1, w.saB2, w.clB2)
	absent := uuid.New()
	rA := w.engine(w.adminA)

	t.Run("a foreign organization's id and an absent id are indistinguishable", func(t *testing.T) {
		for _, probe := range []struct {
			name string
			do   func(id uuid.UUID) (int, string)
		}{
			{"GET", func(id uuid.UUID) (int, string) {
				rec := acDo(t, rA, http.MethodGet, acBase+"/"+id.String(), nil)
				return rec.Code, rec.Body.String()
			}},
			{"revoke", func(id uuid.UUID) (int, string) {
				rec := acDo(t, rA, http.MethodPost, acBase+"/"+id.String()+"/revoke", map[string]any{"reason": "probe"})
				return rec.Code, rec.Body.String()
			}},
		} {
			fCode, fBody := probe.do(foreign.ID)
			aCode, aBody := probe.do(absent)
			assert.Equal(t, http.StatusNotFound, fCode, "%s: cross-org probe must be 404", probe.name)
			assert.Equal(t, fCode, aCode, "%s: foreign %d vs absent %d — the difference is an enumeration oracle", probe.name, fCode, aCode)
			assert.Equal(t, fBody, aBody, "%s: bodies must be byte-identical", probe.name)
		}
		still, err := w.svc.Get(context.Background(), w.orgB, foreign.ID)
		require.NoError(t, err)
		assert.Nil(t, still.RevokedAt, "the cross-org revoke probe changed nothing")
	})

	t.Run("list is scoped to the actor's organization", func(t *testing.T) {
		rec := acDo(t, rA, http.MethodGet, acBase, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		list := acJSON(t, rec)
		assert.EqualValues(t, 1, list["count"])
		ids := []string{}
		for _, a := range list["authorizations"].([]any) {
			ids = append(ids, a.(map[string]any)["id"].(string))
		}
		assert.Equal(t, []string{own.ID.String()}, ids)
		assert.NotContains(t, rec.Body.String(), foreign.ID.String())
	})

	t.Run("an explicit foreign organization on create is refused", func(t *testing.T) {
		body := w.bodyA()
		body["organization_id"] = w.orgB.String()
		rec := acDo(t, rA, http.MethodPost, acBase, body)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.NotContains(t, rec.Body.String(), foreign.ID.String())
	})

	t.Run("site_admin and org_user are refused uniformly — caller-dependent, never target-dependent", func(t *testing.T) {
		for _, p := range []struct {
			name      string
			principal *domain.Principal
		}{{"site_admin", w.siteAdmin}, {"org_user", w.userA}} {
			r := w.engine(p.principal)
			codes := map[string]int{}
			codes["create"] = acDo(t, r, http.MethodPost, acBase, w.bodyA()).Code
			codes["list"] = acDo(t, r, http.MethodGet, acBase, nil).Code
			codes["get own-org id"] = acDo(t, r, http.MethodGet, acBase+"/"+own.ID.String(), nil).Code
			codes["get foreign id"] = acDo(t, r, http.MethodGet, acBase+"/"+foreign.ID.String(), nil).Code
			codes["get absent id"] = acDo(t, r, http.MethodGet, acBase+"/"+absent.String(), nil).Code
			codes["revoke own-org id"] = acDo(t, r, http.MethodPost, acBase+"/"+own.ID.String()+"/revoke", nil).Code
			codes["revoke absent id"] = acDo(t, r, http.MethodPost, acBase+"/"+absent.String()+"/revoke", nil).Code
			for name, code := range codes {
				assert.Equal(t, http.StatusForbidden, code, "%s %s", p.name, name)
			}
		}
		still, err := w.svc.Get(context.Background(), w.orgA, own.ID)
		require.NoError(t, err)
		assert.Nil(t, still.RevokedAt, "a refused revoke changed nothing")
		assert.Len(t, w.repo.rows, 2, "a refused create persisted nothing")
	})

	t.Run("CONTROL: the actor's own organization is reachable", func(t *testing.T) {
		rec := acDo(t, rA, http.MethodGet, acBase+"/"+own.ID.String(), nil)
		require.Equal(t, http.StatusOK, rec.Code, "CONTROL FAILED: own-org read → %d; the assertions above would prove nothing", rec.Code)
		rec = acDo(t, rA, http.MethodPost, acBase+"/"+own.ID.String()+"/revoke", nil)
		require.Equal(t, http.StatusOK, rec.Code, "CONTROL FAILED: own-org revoke → %d", rec.Code)
		assert.Equal(t, "revoked", acJSON(t, rec)["status"])
	})
}

// RULE: AYGHU-STORE-503-1
func TestRule_AYGHU_STORE_503_1(t *testing.T) {
	w := newACWorld(t)
	own := w.seed(t, w.adminA, w.saA1, w.clA1, w.saA2, w.clA2)
	r := w.engine(w.adminA)

	sinkCalls := 0
	var sinkWhere []string
	orig := mw.AuthStoreErrorSink
	mw.AuthStoreErrorSink = func(_ context.Context, where, correlationID string, err error) {
		sinkCalls++
		sinkWhere = append(sinkWhere, where)
		assert.NotEmpty(t, correlationID)
		assert.Error(t, err)
	}
	t.Cleanup(func() { mw.AuthStoreErrorSink = orig })

	assert503 := func(t *testing.T, name string, do func() (int, map[string]any, http.Header), beforeCalls int) {
		t.Helper()
		code, body, hdr := do()
		require.Equal(t, http.StatusServiceUnavailable, code, "%s: a store error must be 503, got %d (%v)", name, code, body)
		assert.Equal(t, "temporarily_unavailable", body["error"], name)
		assert.Equal(t, "auth_store_error", body["reason"], name)
		cid, _ := body["correlation_id"].(string)
		assert.NotEmpty(t, cid, "%s: correlation id on the body", name)
		assert.Equal(t, cid, hdr.Get(mw.CorrelationIDHeader), "%s: the same id on the response header", name)
		assert.NotEmpty(t, hdr.Get("Retry-After"), name)
		assert.Equal(t, beforeCalls+1, sinkCalls, "%s: exactly one AUTH-503 sink call", name)
	}
	run := func(method, path string, body any) func() (int, map[string]any, http.Header) {
		return func() (int, map[string]any, http.Header) {
			rec := acDo(t, r, method, path, body)
			return rec.Code, acJSON(t, rec), rec.Header()
		}
	}

	// The authorization store fails on every path.
	w.repo.fail = fmt.Errorf("dial tcp 10.0.0.9:5432: connect: connection refused")
	assert503(t, "create", run(http.MethodPost, acBase, w.bodyA()), sinkCalls)
	assert503(t, "list", run(http.MethodGet, acBase, nil), sinkCalls)
	assert503(t, "get own", run(http.MethodGet, acBase+"/"+own.ID.String(), nil), sinkCalls)
	assert503(t, "get absent", run(http.MethodGet, acBase+"/"+uuid.New().String(), nil), sinkCalls)
	assert503(t, "revoke", run(http.MethodPost, acBase+"/"+own.ID.String()+"/revoke", nil), sinkCalls)
	w.repo.fail = nil

	// A participant lookup store failure on create is the same class.
	w.sas.fail = fmt.Errorf("read tcp: i/o timeout")
	assert503(t, "create (service-account store)", run(http.MethodPost, acBase, w.bodyA()), sinkCalls)
	w.sas.fail = nil
	w.clients.fail = fmt.Errorf("pq: the database system is shutting down")
	assert503(t, "create (client store)", run(http.MethodPost, acBase, w.bodyA()), sinkCalls)
	w.clients.fail = nil

	for _, where := range sinkWhere {
		assert.True(t, strings.HasPrefix(where, "agent_communication."), "sink where=%q names the path", where)
	}
	assert.Equal(t, 0, w.rec.Len(), "no audit event for a refused-by-outage request")
	assert.Len(t, w.repo.rows, 1, "nothing was persisted while the store was failing")

	// Healthy again: the verdicts are back and are NOT 503.
	rec := acDo(t, r, http.MethodGet, acBase+"/"+uuid.New().String(), nil)
	assert.Equal(t, http.StatusNotFound, rec.Code, "an absent id with a healthy store is a 404 verdict")
	rec = acDo(t, r, http.MethodGet, acBase+"/"+own.ID.String(), nil)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// RULE: AYGHU-AUDIT-1
func TestRule_AYGHU_AUDIT_1(t *testing.T) {
	w := newACWorld(t)
	r := w.engine(w.adminA)
	const freeText = "operator asked for it, ticket OPS-1234"

	allowedTop := map[string]bool{"authorization_id": true, "session_id": true, "organization_id": true, "owner_id": true, "participants": true, "revoked_by": true, "result": true}
	allowedParticipant := map[string]bool{"aci": true, "role": true, "service_account_id": true, "oauth_client_id": true}
	assertSafe := func(t *testing.T, ev audit.Event) {
		t.Helper()
		for k := range ev.Metadata {
			assert.True(t, allowedTop[k], "metadata key %q is not in the safe set", k)
		}
		if parts, ok := ev.Metadata["participants"].([]map[string]any); ok {
			for _, p := range parts {
				for k := range p {
					assert.True(t, allowedParticipant[k], "participant metadata key %q is not in the safe set", k)
				}
			}
		}
		flat := fmt.Sprintf("%v %s %s %s", ev.Metadata, ev.Action, ev.Outcome, ev.SubjectType)
		assert.NotContains(t, flat, acThumbA, "a proof-key thumbprint never enters the audit")
		assert.NotContains(t, flat, acThumbB)
		assert.NotContains(t, flat, "relay.example.test", "the relay audience never enters the audit")
		assert.NotContains(t, flat, freeText, "the free-text revocation reason never enters the audit")
		assert.Equal(t, w.adminA.UserID, ev.ActorID, "acting owner recorded")
		assert.Equal(t, w.orgA, ev.OrganizationID)
	}

	// Create → exactly one created event.
	rec := acDo(t, r, http.MethodPost, acBase, w.bodyA())
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	created := acJSON(t, rec)
	events := w.rec.Events()
	require.Len(t, events, 1, "create records exactly one audit event")
	ev := events[0]
	assert.Equal(t, AuditActionAgentCommunicationAuthorizationCreated, ev.Action)
	assert.Equal(t, "success", ev.Outcome)
	assert.Equal(t, created["id"], ev.SubjectID.String())
	assert.Equal(t, created["id"], ev.Metadata["authorization_id"])
	assert.Equal(t, created["session_id"], ev.Metadata["session_id"])
	assert.Equal(t, w.adminA.UserID.String(), ev.Metadata["owner_id"])
	parts, ok := ev.Metadata["participants"].([]map[string]any)
	require.True(t, ok, "participants metadata is the safe projection")
	require.Len(t, parts, 2)
	for _, p := range parts {
		_, err := uuid.Parse(p["aci"].(string))
		assert.NoError(t, err)
		assert.Contains(t, []any{"initiator", "responder"}, p["role"])
	}
	assertSafe(t, ev)

	// A refused create records nothing.
	body := w.bodyA()
	body["participants"] = body["participants"].([]map[string]any)[:1]
	rec = acDo(t, r, http.MethodPost, acBase, body)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, 1, w.rec.Len(), "a refused create records no event")

	// Revoke → one revoked event (result revoked), free text kept out.
	id := created["id"].(string)
	rec = acDo(t, r, http.MethodPost, acBase+"/"+id+"/revoke", map[string]any{"reason": freeText})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	events = w.rec.Events()
	require.Len(t, events, 2, "revoke records exactly one audit event")
	rev := events[1]
	assert.Equal(t, AuditActionAgentCommunicationAuthorizationRevoked, rev.Action)
	assert.Equal(t, "success", rev.Outcome)
	assert.Equal(t, id, rev.Metadata["authorization_id"])
	assert.Equal(t, "revoked", rev.Metadata["result"])
	assert.Equal(t, w.adminA.UserID.String(), rev.Metadata["revoked_by"])
	assertSafe(t, rev)

	// Idempotent repeat → one more event naming the repeat honestly.
	rec = acDo(t, r, http.MethodPost, acBase+"/"+id+"/revoke", map[string]any{"reason": freeText})
	require.Equal(t, http.StatusOK, rec.Code)
	events = w.rec.Events()
	require.Len(t, events, 3)
	assert.Equal(t, "already_revoked", events[2].Metadata["result"])
	assertSafe(t, events[2])

	// A refused revoke (absent id) records nothing.
	rec = acDo(t, r, http.MethodPost, acBase+"/"+uuid.New().String()+"/revoke", nil)
	require.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, 3, w.rec.Len())
}
