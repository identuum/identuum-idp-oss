package handlers

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// A session-revocation endpoint acts only on the authenticated principal's
// own sessions: it exposes no cross-user target, a session owned by another
// user is never revoked (the request gets the same opaque success as a real
// revoke, but the victim's session stays live), and the revoker is invoked
// only for a session the principal owns. Driven through the routed
// HandleRevokeOwnSession; the assertion is which session id (if any) actually
// reached the revoker.
// RULE: SESSION-SELF-REVOKE-1
func TestRevokeOwnSession_NeverRevokesAnotherUsersSession(t *testing.T) {
	repo := newFakeSessionRepoForHandlerTests()
	rev := &fakeSessionRevoker{}

	me := uuid.New()
	myCurrent := uuid.New()
	mySession := makeSession(t, me)
	repo.addSession(mySession)

	// A session owned by a DIFFERENT user.
	otherUser := uuid.New()
	victim := makeSession(t, otherUser)
	repo.addSession(victim)

	principal := sessionsTestPrincipal(me, myCurrent, domain.RoleOrgUser)
	r := newSessionsEngine(t, principal, SessionsHandlerDeps{
		SessionList: repo, SessionRepo: repo, UserSession: rev, Audit: &captureAudit{},
	})

	// Cross-user attempt: opaque success body, but the revoker is NEVER
	// called for the victim's session.
	rec := sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke",
		map[string]any{"session_id": victim.ID.String()})
	assert.Equal(t, http.StatusOK, rec.Code)
	rev.mu.Lock()
	for _, id := range rev.calls {
		if id == victim.ID {
			rev.mu.Unlock()
			t.Fatalf("cross-user revocation: another user's session %s was revoked", victim.ID)
		}
	}
	rev.mu.Unlock()

	// Own session: the revoker IS invoked for exactly that id.
	rec = sessionsDoJSON(t, r, http.MethodPost, "/api/v1/revoke",
		map[string]any{"session_id": mySession.ID.String()})
	assert.Equal(t, http.StatusOK, rec.Code)
	rev.mu.Lock()
	defer rev.mu.Unlock()
	found := false
	for _, id := range rev.calls {
		if id == mySession.ID {
			found = true
		}
		require.NotEqual(t, victim.ID, id, "victim session must never be revoked across the whole flow")
	}
	assert.True(t, found, "the principal's own session must be revoked when it is the target")
}
