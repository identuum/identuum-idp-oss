package handlers

// logout_unconfirmed.go — THE-LOGOUT-THAT-CANNOT-REVOKE (2026-09-02).
//
// The last AUTH-503 collapse sites: HandleEndSession and
// HandleFrontchannelLogout read a cookie-session STORE error as "no
// session", cleared the cookie and silently skipped the server-side
// revocation — the session survived on the server while the browser
// believed it was gone, and nothing recorded it.
//
// The ruling (the ui's own logout pattern): on a store error still clear
// the cookie — the user asked to leave this device — but NEVER silently.
// Every unconfirmed revocation now:
//   - emits the AUTH-503 ERROR line with the request's correlation id
//     (mw.NoteAuthStoreError — log only, no Retry-After on a logout answer);
//   - records the audit event `user_session.logout.revocation_unconfirmed`
//     with safe metadata (flow, the lookup that failed, the correlation id;
//     never a token or cookie value);
//   - marks the response with `X-Identuum-Logout: revocation_unconfirmed`
//     next to the X-Request-ID the correlation middleware already set, so an
//     RP or operator inspecting the answer can see it.
// A successful revocation path is untouched.

import (
	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// AuditActionLogoutRevocationUnconfirmed is the audit action recorded when a
// logout could not confirm the server-side revocation because a store did
// not answer.
const AuditActionLogoutRevocationUnconfirmed = "user_session.logout.revocation_unconfirmed"

// LogoutUnconfirmedHeader marks a logout answer whose server-side
// revocation is unconfirmed.
const LogoutUnconfirmedHeader = "X-Identuum-Logout"

// noteLogoutRevocationUnconfirmed logs, audits and marks an unconfirmed
// revocation; returns the correlation id. flow names the ceremony
// ("end_session" / "frontchannel"), where the lookup that failed.
func noteLogoutRevocationUnconfirmed(c *gin.Context, auditSvc audit.Service, flow, where string, err error) string {
	cid := mw.NoteAuthStoreError(c, "logout."+where, err)
	c.Header(LogoutUnconfirmedHeader, "revocation_unconfirmed")
	if auditSvc == nil {
		auditSvc = audit.NoopService{}
	}
	_ = auditSvc.Record(c.Request.Context(), audit.Event{
		Action:        AuditActionLogoutRevocationUnconfirmed,
		Outcome:       "failure",
		CorrelationID: cid,
		RequestID:     cid,
		IPAddress:     c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
		Metadata: map[string]any{
			"flow":           flow,
			"where":          where,
			"reason":         "auth_store_error",
			"correlation_id": cid,
		},
	})
	return cid
}
