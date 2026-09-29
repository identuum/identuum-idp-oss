package handlers

// browser_login_mfa_enrol.go — TOTP enrolment at the OpenID Connect browser
// sign-in, after the D-017 change step, for a user whose organization
// requires MFA and who has none (OSS-FIN-2). It drives the same pending
// enrolment the console uses (MFAEnrollmentService CreatePending, Initiate,
// Complete), so the secret is encrypted at rest and the enrolment code is a
// claimed TOTP step exactly as there. The page carries no script: the secret
// and the otpauth link are shown as text.

import (
	"errors"
	"html"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

const mfaEnrolFormTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Cache-Control" content="no-store">
  <title>Set up two-factor authentication — Identuum</title>
</head>
<body>
  <main>
    <h1>Set up two-factor authentication</h1>
    {{SETUP}}
    {{ERROR}}
    <form method="POST" action="/api/v1/auth/browser-login" autocomplete="off">
      <label>Code from your authenticator app <input type="text" name="totp_code" required autofocus inputmode="numeric" autocomplete="one-time-code"></label><br>
      <input type="hidden" name="mfa_enroll_session" value="{{HANDLE}}">
      <input type="hidden" name="return_to" value="{{RETURN_TO}}">
      {{CSRF}}
      <button type="submit">Verify and continue</button>
    </form>
  </main>
</body>
</html>`

// startBrowserMFAEnrol opens a pending enrolment for user and renders the
// setup page. It reports false when the enrolment cannot start (the caller
// then points the user to the console, as before).
func startBrowserMFAEnrol(c *gin.Context, deps BrowserLoginHandlerDeps, user *domain.User, remember bool, returnTo string) bool {
	row, err := deps.MFAEnrollment.CreatePending(c.Request.Context(), user, domain.MFAPendingKindEnroll, remember)
	if err != nil || row == nil {
		return false
	}
	out, err := deps.MFAEnrollment.Initiate(c.Request.Context(), row.ID)
	if err != nil || out == nil {
		return false
	}
	var codes strings.Builder
	for _, rc := range out.RecoveryCodes {
		codes.WriteString("<li><code>" + html.EscapeString(rc) + "</code></li>")
	}
	setup := `<p>Your organization requires two-factor authentication. Add this key to your authenticator app, then enter the code it shows.</p>` +
		`<p>Key: <code data-secret="` + html.EscapeString(out.Secret) + `">` + html.EscapeString(out.Secret) + `</code></p>` +
		`<p><a href="` + html.EscapeString(out.OtpauthURL) + `">Open in an authenticator app on this device</a></p>` +
		`<p>Recovery codes — keep them somewhere safe; each signs you in once if you lose the app:</p><ul>` + codes.String() + `</ul>`
	renderMFAEnrolForm(c, deps, row.ID.String(), returnTo, setup, false)
	return true
}

func renderMFAEnrolForm(c *gin.Context, deps BrowserLoginHandlerDeps, handle, returnTo, setup string, invalidCode bool) {
	csrfInput := ""
	if deps.CSRF != nil {
		if tok, cookie, err := deps.CSRF.Issue(); err == nil {
			writeBrowserCSRFCookie(c, cookie)
			csrfInput = `<input type="hidden" name="csrf_token" value="` + html.EscapeString(tok) + `">`
		}
	}
	banner := ""
	if invalidCode {
		banner = `<p role="alert" data-error="invalid_code">That code did not match. Enter the current code from your authenticator app.</p>`
	}
	body := strings.NewReplacer(
		"{{SETUP}}", setup,
		"{{ERROR}}", banner,
		"{{HANDLE}}", html.EscapeString(handle),
		"{{RETURN_TO}}", html.EscapeString(returnTo),
		"{{CSRF}}", csrfInput,
	).Replace(mfaEnrolFormTemplate)
	writeNoStoreHTML(c, body)
}

// handleBrowserMFAEnrol completes the enrolment with the submitted code and
// signs the user in. A wrong code keeps the pending enrolment and asks again
// (the key is not shown twice); an expired or spent one restarts the sign-in.
func handleBrowserMFAEnrol(c *gin.Context, deps BrowserLoginHandlerDeps, handle, returnTo string) {
	id, err := uuid.Parse(handle)
	code := strings.TrimSpace(c.PostForm("totp_code"))
	if err != nil || id == uuid.Nil {
		browserLoginRedirect(c, "error=invalid_credentials", returnTo)
		return
	}
	out, err := deps.MFAEnrollment.Complete(c.Request.Context(), id, code)
	if err != nil || out == nil || out.User == nil {
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.login.mfa_enroll_complete_failure",
			Outcome:   "denied",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		})
		if errors.Is(err, service.ErrMFAEnrollmentInvalid) {
			renderMFAEnrolForm(c, deps, handle, returnTo, `<p>Enter the code your authenticator app shows for this account.</p>`, true)
			return
		}
		browserLoginRedirect(c, "error=invalid_credentials", returnTo)
		return
	}
	startBrowserSession(c, deps, out.User, out.RememberMe, true, "user_session.login.mfa_enrolled", returnTo)
}

// startBrowserSession creates the session for a sign-in that ends at the
// browser form (the change step with no MFA due, or a completed enrolment)
// and plants its cookie.
func startBrowserSession(c *gin.Context, deps BrowserLoginHandlerDeps, user *domain.User, remember, mfaDone bool, auditAction, returnTo string) {
	maxSessions := 0
	if user.OrgMaxSessionsPerUser != nil {
		maxSessions = *user.OrgMaxSessionsPerUser
	}
	ip, ua := c.ClientIP(), c.Request.UserAgent()
	acr, amr := service.LoginContext(mfaDone)
	issued, err := deps.UserSession.CreateUserSession(c.Request.Context(), service.CreateUserSessionInput{
		UserID:             user.ID,
		IPAddress:          &ip,
		UserAgent:          &ua,
		RememberMe:         remember,
		Acr:                acr,
		Amr:                amr,
		MaxSessionsPerUser: maxSessions,
		OrganizationID:     user.OrganizationID,
		Role:               string(user.Role),
	})
	if err != nil || issued == nil || issued.Session == nil {
		c.String(http.StatusServiceUnavailable, "temporarily unavailable, try again")
		return
	}
	if auditAction != "" {
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    auditAction,
			Outcome:   "success",
			IPAddress: ip,
			UserAgent: ua,
			Metadata:  map[string]any{"user_id": user.ID.String(), "session_id": issued.Session.ID.String()},
		})
	}
	finishBrowserSignIn(c, deps, &service.LoginResult{UserID: user.ID.String(), User: user, Session: issued.Session, RefreshToken: issued.RefreshToken}, returnTo)
}
