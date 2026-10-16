package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OSS-HARDENING-2 item 4: a password sign-in's audit event carries the same
// actor fields and OrganizationID an upstream sign-in carries, so an
// organization admin can audit every sign-in of its members (the Audit page
// filters by organization_id; a row without it is invisible to them).

func assertSignInActor(t *testing.T, ev audit.Event, user *domain.User) {
	t.Helper()
	if ev.ActorType != audit.ActorTypeUser || ev.ActorID != user.ID || ev.ActorEmail != user.Email ||
		ev.ActorRole != string(user.Role) || ev.OrganizationID != user.OrganizationID {
		t.Errorf("%s: actor = %s/%s %q %q org %s; want the signed-in user %s %q %q of organization %s",
			ev.Action, ev.ActorType, ev.ActorID, ev.ActorEmail, ev.ActorRole, ev.OrganizationID,
			user.ID, user.Email, user.Role, user.OrganizationID)
	}
	if ev.Metadata["method"] != "password" {
		t.Errorf("%s: metadata = %+v; want method=password", ev.Action, ev.Metadata)
	}
}

func TestLoginRoute_PasswordSignInIsAuditedAsTheTenantsUser(t *testing.T) {
	user := &domain.User{
		ID: uuid.New(), Email: "alice@example.com", Role: domain.RoleOrgUser,
		OrganizationID: uuid.New(),
		PasswordHash:   hashPasswordForHandlers(t, "correct"), EmailVerified: true,
	}
	r, _, rec := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail[user.Email] = []*domain.User{user}
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"alice@example.com","password":"correct"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	var signIn *audit.Event
	for _, e := range rec.Events() {
		if e.Action == "user_session.login.success" {
			ev := e
			signIn = &ev
		}
	}
	if signIn == nil {
		t.Fatalf("user_session.login.success not recorded; events = %+v", rec.Events())
	}
	assertSignInActor(t, *signIn, user)
}

func TestMFACompletion_SignInIsAuditedAsTheTenantsUser(t *testing.T) {
	// completeLogin is the one tail of the second-factor, enrolment and
	// password-change sign-ins; each names its own action and all are
	// sign-ins of the person.
	for _, action := range []string{"user_session.login.mfa_verified", "user_session.login.mfa_enrolled", "user_session.login.success"} {
		t.Run(action, func(t *testing.T) {
			gin.SetMode(gin.ReleaseMode)
			user := &domain.User{ID: uuid.New(), Email: "bob@example.com", Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}
			sessions := service.NewUserSessionService(nil, newSessionRepoForHandlers(), service.UserSessionServiceOptions{DefaultTTL: time.Hour})
			rec := &audit.Recorder{}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa", nil)
			acr, amr := service.LoginContext(true)
			completeLogin(c, AuthSessionsHandlerDeps{UserSession: sessions, Audit: rec}, &service.MFAEnrollmentCompleteResult{User: user}, action, acr, amr, "password")
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
			}
			var signIn *audit.Event
			for _, e := range rec.Events() {
				if e.Action == action {
					ev := e
					signIn = &ev
				}
			}
			if signIn == nil {
				t.Fatalf("%s not recorded; events = %+v", action, rec.Events())
			}
			assertSignInActor(t, *signIn, user)
		})
	}
}
