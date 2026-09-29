package handlers

// browser_login_password_change.go — the required password change of the
// OpenID Connect browser sign-in (OSS-FIN-1, owner ruling D-017). The
// console's counterpart is auth_login_password_change.go; both redeem the
// same one-time password_change handle through changeRequiredPassword.

import (
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// changeStepWired reports whether the D-017 change step can run here.
func (d BrowserLoginHandlerDeps) changeStepWired() bool {
	return d.MFAEnrollment != nil && d.ChangePassword != nil && d.UserSession != nil
}

// passwordChangeFormTemplate is the change step of the browser sign-in: the
// one-time handle rides as a hidden field; no cookie exists yet.
const passwordChangeFormTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Cache-Control" content="no-store">
  <title>Choose a new password — Identuum</title>
</head>
<body>
  <main>
    <h1>Choose a new password</h1>
    <p>Your administrator set your password. Choose your own to continue.</p>
    {{ERROR}}
    <form method="POST" action="/api/v1/auth/browser-login" autocomplete="off">
      <label>New password <input type="password" name="new_password" required autofocus autocomplete="new-password"></label><br>
      <label>Confirm new password <input type="password" name="confirm_password" required autocomplete="new-password"></label><br>
      <input type="hidden" name="password_change_session" value="{{HANDLE}}">
      <input type="hidden" name="return_to" value="{{RETURN_TO}}">
      <input type="hidden" name="remember_me" value="{{REMEMBER}}">
      {{CSRF}}
      <button type="submit">Change password and continue</button>
    </form>
  </main>
</body>
</html>`

// mfaEnrolFirstPage answers a change that succeeded for a user whose
// organization requires an authenticator not yet enrolled: this form cannot
// enrol one, the console can.
const mfaEnrolFirstPage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta http-equiv="Cache-Control" content="no-store"><title>Set up two-factor authentication — Identuum</title></head>
<body><main>
<h1>Password changed</h1>
<p>Your organization requires two-factor authentication. Sign in to the console to set up an authenticator app, then return here.</p>
<p><a href="/login">Go to the console sign-in</a></p>
</main></body>
</html>`

// renderPasswordChangeForm writes the change step. message, when set, is a
// safe displayable policy text (never a password); values are escaped.
func renderPasswordChangeForm(c *gin.Context, deps BrowserLoginHandlerDeps, handle, returnTo string, remember bool, message string) {
	csrfInput := ""
	if deps.CSRF != nil {
		if tok, cookie, err := deps.CSRF.Issue(); err == nil {
			writeBrowserCSRFCookie(c, cookie)
			csrfInput = `<input type="hidden" name="csrf_token" value="` + html.EscapeString(tok) + `">`
		}
	}
	rememberVal := ""
	if remember {
		rememberVal = "1"
	}
	banner := ""
	if message != "" {
		banner = `<p role="alert" data-error="weak_password">` + html.EscapeString(message) + `</p>`
	}
	body := strings.NewReplacer(
		"{{HANDLE}}", html.EscapeString(handle),
		"{{RETURN_TO}}", html.EscapeString(returnTo),
		"{{REMEMBER}}", rememberVal,
		"{{ERROR}}", banner,
		"{{CSRF}}", csrfInput,
	).Replace(passwordChangeFormTemplate)
	writeNoStoreHTML(c, body)
}

func writeNoStoreHTML(c *gin.Context, body string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Status(http.StatusOK)
	_, _ = c.Writer.Write([]byte(body))
}

func browserLoginRedirect(c *gin.Context, query, returnTo string) {
	loc := "/api/v1/auth/browser-login?" + query
	if returnTo != "" {
		loc += "&return_to=" + url.QueryEscape(returnTo)
	}
	c.Redirect(http.StatusSeeOther, loc)
}

// handleBrowserPasswordChange redeems the change step, then continues the
// sign-in: the session cookie when no MFA applies; the sign-in form again
// when a TOTP is due (it is entered there); a pointer to the console when an
// authenticator must still be enrolled.
func handleBrowserPasswordChange(c *gin.Context, deps BrowserLoginHandlerDeps, handle, returnTo string) {
	remember := c.PostForm("remember_me") == "1"
	newPassword := c.PostForm("new_password")
	if newPassword == "" || newPassword != c.PostForm("confirm_password") {
		renderPasswordChangeForm(c, deps, handle, returnTo, remember, "The two passwords do not match.")
		return
	}
	user, remember, err := changeRequiredPassword(c, deps.MFAEnrollment, deps.ChangePassword, deps.Audit, handle, newPassword)
	var policy *service.ChangePasswordPolicyError
	switch {
	case errors.As(err, &policy):
		renderPasswordChangeForm(c, deps, handle, returnTo, remember, policy.Detail)
		return
	case err != nil:
		browserLoginRedirect(c, "error=invalid_credentials", returnTo)
		return
	}
	switch {
	case service.IsMFARequiredForUser(user) && !user.MFAEnabled:
		writeNoStoreHTML(c, mfaEnrolFirstPage)
		return
	case user.MFAEnabled:
		browserLoginRedirect(c, "notice=password_changed", returnTo)
		return
	}
	maxSessions := 0
	if user.OrgMaxSessionsPerUser != nil {
		maxSessions = *user.OrgMaxSessionsPerUser
	}
	ip, ua := c.ClientIP(), c.Request.UserAgent()
	acr, amr := service.LoginContext(false)
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
	finishBrowserSignIn(c, deps, &service.LoginResult{UserID: user.ID.String(), User: user, Session: issued.Session, RefreshToken: issued.RefreshToken}, returnTo)
}
