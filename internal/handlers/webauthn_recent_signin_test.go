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
// window. A stolen or long-idle session cannot plant one.

type fixedSessionLookup struct {
	session *domain.Session
	err     error
}

func (f fixedSessionLookup) GetByID(context.Context, uuid.UUID) (*domain.Session, error) {
	return f.session, f.err
}

func passkeyReauthFixture(t *testing.T, lookup SessionByIDLookup, sessionID uuid.UUID) (*gin.Engine, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
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
		SessionLookup: lookup, Now: func() time.Time { return now },
	}
	p := principalForUser(user)
	p.SessionID = sessionID
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(p))
	r.POST("/api/v1/webauthn/register/begin", HandleWebAuthnRegisterBegin(deps))
	r.DELETE("/api/v1/webauthn/credentials/:id", HandleDeleteWebAuthnCredential(deps))
	return r, now
}

func TestPassKeyAddAndRemoveNeedARecentSignIn(t *testing.T) {
	sid := uuid.New()

	type kase struct {
		name         string
		session      func(now time.Time) *domain.Session
		lookupErr    error
		noLookup     bool
		noSession    bool
		wantStatus   int
		wantErrField string
	}
	cases := []kase{
		{name: "signed in a minute ago", session: func(now time.Time) *domain.Session { return &domain.Session{CreatedAt: now.Add(-time.Minute)} }, wantStatus: http.StatusOK},
		{name: "signed in an hour ago", session: func(now time.Time) *domain.Session { return &domain.Session{CreatedAt: now.Add(-time.Hour)} }, wantStatus: http.StatusForbidden, wantErrField: "reauth_required"},
		{name: "an old session stepped up a minute ago", session: func(now time.Time) *domain.Session {
			up := now.Add(-time.Minute)
			return &domain.Session{CreatedAt: now.Add(-8 * time.Hour), LastACRUpliftAt: &up}
		}, wantStatus: http.StatusOK},
		{name: "no session lookup wired fails closed", noLookup: true, wantStatus: http.StatusForbidden, wantErrField: "reauth_required"},
		{name: "a principal with no session fails closed", noSession: true, session: func(now time.Time) *domain.Session { return &domain.Session{CreatedAt: now} }, wantStatus: http.StatusForbidden, wantErrField: "reauth_required"},
		{name: "a session store outage is a 503", lookupErr: errors.New("store down"), wantStatus: http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run("register/begin: "+tc.name, func(t *testing.T) {
			var lookup SessionByIDLookup
			if !tc.noLookup {
				l := fixedSessionLookup{err: tc.lookupErr}
				lookup = &l
			}
			sessionID := sid
			if tc.noSession {
				sessionID = uuid.Nil
			}
			r, now := passkeyReauthFixture(t, lookup, sessionID)
			if fl, ok := lookup.(*fixedSessionLookup); ok && tc.session != nil {
				fl.session = tc.session(now)
			}
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
		r, now := passkeyReauthFixture(t, &fixedSessionLookup{session: &domain.Session{CreatedAt: time.Date(2026, 10, 4, 3, 0, 0, 0, time.UTC)}}, sid)
		_ = now
		rec := webauthnDoJSON(t, r, http.MethodDelete, "/api/v1/webauthn/credentials/"+credID, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "reauth_required")

		r, _ = passkeyReauthFixture(t, &fixedSessionLookup{session: &domain.Session{CreatedAt: time.Date(2026, 10, 4, 11, 58, 0, 0, time.UTC)}}, sid)
		rec = webauthnDoJSON(t, r, http.MethodDelete, "/api/v1/webauthn/credentials/"+credID, nil)
		assert.NotEqual(t, http.StatusForbidden, rec.Code, "a recent sign-in must pass the gate")
	})
}
