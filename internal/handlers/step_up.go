package handlers

// step_up.go — THE-HONEST-ACR: the OP-native TOTP step-up ceremony.
//
// /authorize refers an interactive browser here when acr_values asks for
// the password+TOTP rung, the live session sits at the password rung, and
// the user has TOTP enrolled. The form takes the code, the SAME session is
// uplifted (Session.RecordACRUplift → sessions.last_acr_uplift_at/_value —
// the first production writer of those columns), and the browser resumes
// the original authorize URL, whose id_token then carries the rung that was
// actually performed. Nothing here ever stamps a requested-but-unverified
// acr.

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// StepUpVerifier verifies a TOTP code for an enrolled user.
// *service.MFAVerifierService satisfies it.
type StepUpVerifier interface {
	Verify(ctx context.Context, user *domain.User, code string) error
}

// ACRUpliftRecorder persists a step-up on a session.
// repository.SessionRepository satisfies it.
type ACRUpliftRecorder interface {
	RecordACRUplift(ctx context.Context, sessionID uuid.UUID, upliftAt time.Time, upliftValue string) error
}

// StepUpSessionResolver reads and resolves the browser session cookie.
// *service.CookieSessionService satisfies it; tests inject a fake.
type StepUpSessionResolver interface {
	Read(r *http.Request) (string, bool)
	Resolve(ctx context.Context, cookieValue string) (*service.CookieSessionLookupResult, error)
}

// StepUpHandlerDeps wires the ceremony. CookieSession, Verifier and
// Sessions are REQUIRED (the routes do not register without them); CSRF is
// optional but enforced when wired; Audit defaults to NoopService.
type StepUpHandlerDeps struct {
	CookieSession StepUpSessionResolver
	CSRF          *service.BrowserCSRFService
	Verifier      StepUpVerifier
	Sessions      ACRUpliftRecorder
	Audit         audit.Service
	// Now is injectable for tests; nil → time.Now.
	Now func() time.Time
}

// RegisterStepUpRoutes mounts
//
//	GET  /api/v1/auth/step-up
//	POST /api/v1/auth/step-up
func RegisterStepUpRoutes(router gin.IRouter, deps StepUpHandlerDeps) {
	if deps.CookieSession == nil || deps.Verifier == nil || deps.Sessions == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	// docgen:endpoint
	// docgen:surface=auth
	// docgen:method=GET
	// docgen:path=/api/v1/auth/step-up
	// docgen:summary=Render the TOTP step-up form for the browser session (THE-HONEST-ACR: /authorize refers here when acr_values asks for the password+TOTP rung and the session sits at the password rung).
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:notes=Browser session cookie required (401 login_required without it). Preserves return_to (same-origin path only) so the verified step-up resumes the original authorize request.
	router.GET("/api/v1/auth/step-up", HandleStepUpForm(deps))

	// docgen:endpoint
	// docgen:surface=auth
	// docgen:method=POST
	// docgen:path=/api/v1/auth/step-up
	// docgen:summary=Submit the TOTP step-up code; on success the SAME session records an ACR uplift to the password+TOTP rung and the browser is redirected to return_to.
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:notes=CSRF double-submit enforced when wired. A wrong code re-renders the form (303, error=invalid_code); a user without TOTP enrolled is refused (403 mfa_not_enrolled) — the acr is never stamped without a verified code.
	router.POST("/api/v1/auth/step-up", HandleStepUpSubmit(deps))
}

// HandleStepUpForm renders the TOTP form for the cookie session.
func HandleStepUpForm(deps StepUpHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if resolveStepUpSession(c, deps) == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "login_required"})
			return
		}
		returnTo := validateReturnTo(c.Query("return_to"))
		errCode := c.Query("error")
		var csrfToken string
		if deps.CSRF != nil {
			if tok, cookie, err := deps.CSRF.Issue(); err == nil {
				csrfToken = tok
				writeBrowserCSRFCookie(c, cookie)
			}
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Status(http.StatusOK)
		renderStepUpForm(c.Writer, returnTo, errCode, csrfToken)
	}
}

// HandleStepUpSubmit verifies the code and records the uplift.
func HandleStepUpSubmit(deps StepUpHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if deps.CSRF != nil {
			cookieVal := readCSRFCookie(c.Request, deps.CSRF.CookieName())
			formVal := c.PostForm(deps.CSRF.FormFieldName())
			if err := deps.CSRF.Verify(cookieVal, formVal); err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "csrf_failed"})
				return
			}
		}
		resolved := resolveStepUpSession(c, deps)
		if resolved == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "login_required"})
			return
		}
		returnTo := validateReturnTo(c.PostForm("return_to"))
		ip, ua := c.ClientIP(), c.Request.UserAgent()
		if !resolved.User.MFAEnabled {
			// /authorize already refuses this as unmet_authentication_requirements;
			// a direct POST gets the same honest answer.
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{Action: "user_session.step_up.failure", Outcome: "denied", IPAddress: ip, UserAgent: ua, Metadata: map[string]any{"reason": "mfa_not_enrolled"}})
			c.JSON(http.StatusForbidden, gin.H{"error": "mfa_not_enrolled"})
			return
		}
		if err := deps.Verifier.Verify(c.Request.Context(), resolved.User, c.PostForm("totp_code")); err != nil {
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{Action: "user_session.step_up.failure", Outcome: "denied", IPAddress: ip, UserAgent: ua, Metadata: map[string]any{"session_id": resolved.Session.ID.String()}})
			loc := "/api/v1/auth/step-up?error=invalid_code"
			if returnTo != "" {
				loc += "&return_to=" + url.QueryEscape(returnTo)
			}
			c.Redirect(http.StatusSeeOther, loc)
			return
		}
		now := deps.Now().UTC()
		if err := deps.Sessions.RecordACRUplift(c.Request.Context(), resolved.Session.ID, now, auth.ACRMFA); err != nil {
			// The code verified but the uplift did not persist: refusing is
			// the only honest answer — a resumed authorize would otherwise
			// mint an id_token at the password rung after a real TOTP.
			c.String(http.StatusServiceUnavailable, "temporarily unavailable, try again")
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action: "user_session.step_up.success", Outcome: "success", IPAddress: ip, UserAgent: ua,
			Metadata: map[string]any{"user_id": resolved.User.ID.String(), "session_id": resolved.Session.ID.String(), "acr": auth.ACRMFA},
		})
		if returnTo == "" {
			returnTo = "/"
		}
		c.Redirect(http.StatusSeeOther, returnTo)
	}
}

// resolveStepUpSession resolves the browser session cookie to a live
// session + user, or nil.
func resolveStepUpSession(c *gin.Context, deps StepUpHandlerDeps) *service.CookieSessionLookupResult {
	cookieVal, ok := deps.CookieSession.Read(c.Request)
	if !ok {
		return nil
	}
	resolved, err := deps.CookieSession.Resolve(c.Request.Context(), cookieVal)
	if err != nil || resolved == nil || resolved.Session == nil || resolved.User == nil {
		return nil
	}
	return resolved
}

const stepUpFormTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Cache-Control" content="no-store">
  <title>Confirm it's you — Identuum</title>
</head>
<body>
  <main>
    <h1>Confirm it's you</h1>
    <p>The application asked for a stronger sign-in. Enter the code from your authenticator app.</p>
    {{ERROR}}
    <form method="POST" action="/api/v1/auth/step-up" autocomplete="off">
      <label>Authenticator code <input type="text" name="totp_code" inputmode="numeric" autocomplete="one-time-code" required autofocus></label><br>
      <input type="hidden" name="return_to" value="{{RETURN_TO}}">
      {{CSRF}}
      <button type="submit">Continue</button>
    </form>
  </main>
</body>
</html>`

func renderStepUpForm(w http.ResponseWriter, returnTo, errCode, csrfToken string) {
	body := strings.ReplaceAll(stepUpFormTemplate, "{{RETURN_TO}}", html.EscapeString(returnTo))
	if errCode != "" {
		body = strings.ReplaceAll(body, "{{ERROR}}", `<p role="alert" data-error="`+html.EscapeString(errCode)+`">That code was not accepted. Please try again.</p>`)
	} else {
		body = strings.ReplaceAll(body, "{{ERROR}}", "")
	}
	csrfInput := ""
	if csrfToken != "" {
		csrfInput = `<input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `">`
	}
	body = strings.ReplaceAll(body, "{{CSRF}}", csrfInput)
	_, _ = w.Write([]byte(body))
}
