package handlers

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// H6: a passkey is a lasting sign-in factor, so adding or removing one needs a
// RECENT sign-in — the session's creation, or its last step-up, inside the
// window (ten minutes by default). A stolen or long-idle session cannot plant
// one. The tests use ages far from the boundary (a minute, an hour) so they
// need no clock seam.

type fixedSessionLookup struct {
	session *domain.Session
	err     error
}

func (f fixedSessionLookup) GetByID(context.Context, uuid.UUID) (*domain.Session, error) {
	return f.session, f.err
}

func passkeyReauthEngine(t *testing.T, lookup SessionByIDLookup, sessionID uuid.UUID) *gin.Engine {
	t.Helper()
	user := newWebAuthnTestUser(uuid.New())
	svc, err := service.NewWebAuthnService(service.WebAuthnServiceConfig{
		BaseURL:     "https://idp.example.test",
		UserRepo:    stubWebAuthnUserRepo{},
		CredRepo:    emptyWebAuthnCredRepo{},
		SessionRepo: repository.NewInMemoryWebAuthnSessionRepository(),
	})
	require.NoError(t, err)
	deps := WebAuthnHandlerDeps{
		WebAuthn: svc, UserLookup: newFakeWebAuthnUserLookup(user), Audit: audit.NoopService{},
		SessionLookup: lookup,
	}
	p := principalForUser(user)
	p.SessionID = sessionID
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(p))
	r.POST("/api/v1/webauthn/register/begin", HandleWebAuthnRegisterBegin(deps))
	r.DELETE("/api/v1/webauthn/credentials/:id", HandleDeleteWebAuthnCredential(deps))
	return r
}

func TestPassKeyAddAndRemoveNeedARecentSignIn(t *testing.T) {
	sid := uuid.New()
	ago := func(d time.Duration) *domain.Session { return &domain.Session{CreatedAt: time.Now().Add(-d)} }

	cases := []struct {
		name         string
		lookup       SessionByIDLookup
		sessionID    uuid.UUID
		wantStatus   int
		wantErrField string
	}{
		{"signed in a minute ago", fixedSessionLookup{session: ago(time.Minute)}, sid, http.StatusOK, ""},
		{"signed in an hour ago", fixedSessionLookup{session: ago(time.Hour)}, sid, http.StatusForbidden, "reauth_required"},
		{"an old session stepped up a minute ago", fixedSessionLookup{session: func() *domain.Session {
			up := time.Now().Add(-time.Minute)
			return &domain.Session{CreatedAt: time.Now().Add(-8 * time.Hour), LastACRUpliftAt: &up}
		}()}, sid, http.StatusOK, ""},
		{"no session lookup wired fails closed", nil, sid, http.StatusForbidden, "reauth_required"},
		{"a principal with no session fails closed", fixedSessionLookup{session: ago(time.Second)}, uuid.Nil, http.StatusForbidden, "reauth_required"},
		{"a session store outage is a 503", fixedSessionLookup{err: errors.New("store down")}, sid, http.StatusServiceUnavailable, ""},
	}
	for _, tc := range cases {
		t.Run("register/begin: "+tc.name, func(t *testing.T) {
			r := passkeyReauthEngine(t, tc.lookup, tc.sessionID)
			rec := webauthnDoJSON(t, r, http.MethodPost, "/api/v1/webauthn/register/begin", nil)
			assert.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())
			if tc.wantErrField != "" {
				assert.Contains(t, rec.Body.String(), tc.wantErrField)
			}
		})
	}

	// Deleting is gated the same way. A fresh sign-in reaches the service
	// (there is no such credential, so 404); a stale one never does.
	t.Run("delete: stale is refused, fresh reaches the service", func(t *testing.T) {
		credID := uuid.New().String()
		r := passkeyReauthEngine(t, fixedSessionLookup{session: ago(time.Hour)}, sid)
		rec := webauthnDoJSON(t, r, http.MethodDelete, "/api/v1/webauthn/credentials/"+credID, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "reauth_required")

		r = passkeyReauthEngine(t, fixedSessionLookup{session: ago(time.Minute)}, sid)
		rec = webauthnDoJSON(t, r, http.MethodDelete, "/api/v1/webauthn/credentials/"+credID, nil)
		assert.NotEqual(t, http.StatusForbidden, rec.Code, "a recent sign-in must pass the gate")
	})
}
