package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OSS-HARDENING-3 item 4: the recovery-code consumption event of a sign-in
// (user_session.login.mfa_recovery_code_consumed) names the person and their
// organization as its actor, as the sign-in events do since OSS-HARDENING-2,
// so an organization admin's audit view (filtered by organization_id) shows
// a member running their recovery list down. Its metadata is unchanged.
func TestMFACompletion_RecoveryCodeConsumedIsAuditedAsTheTenantsUser(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	user := &domain.User{ID: uuid.New(), Email: "bob@example.com", Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}
	sessions := service.NewUserSessionService(nil, newSessionRepoForHandlers(), service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	rec := &audit.Recorder{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa", nil)
	completeMFALogin(c, AuthSessionsHandlerDeps{UserSession: sessions, Audit: rec},
		&service.MFAEnrollmentCompleteResult{User: user, RecoveryCodeUsed: true, RemainingRecoveryCodes: 3},
		"user_session.login.mfa_verified", true)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	ev := auditedAction(rec, "user_session.login.mfa_recovery_code_consumed")
	if ev == nil {
		t.Fatalf("user_session.login.mfa_recovery_code_consumed not recorded; events = %+v", rec.Events())
	}
	if ev.ActorType != audit.ActorTypeUser || ev.ActorID != user.ID || ev.ActorEmail != user.Email ||
		ev.ActorRole != string(user.Role) || ev.OrganizationID != user.OrganizationID {
		t.Errorf("actor = %s/%s %q %q org %s; want the signed-in user %s %q %q of organization %s",
			ev.ActorType, ev.ActorID, ev.ActorEmail, ev.ActorRole, ev.OrganizationID,
			user.ID, user.Email, user.Role, user.OrganizationID)
	}
	if ev.Outcome != "success" || ev.Metadata["user_id"] != user.ID.String() || ev.Metadata["remaining_recovery_codes_count"] != 3 || ev.Metadata["session_id"] == nil {
		t.Errorf("event = outcome %q metadata %+v; want success with user_id, session_id and remaining_recovery_codes_count 3 unchanged", ev.Outcome, ev.Metadata)
	}
	if len(ev.Metadata) != 3 {
		t.Errorf("metadata keys = %d (%+v); want the three it carried before", len(ev.Metadata), ev.Metadata)
	}
}
