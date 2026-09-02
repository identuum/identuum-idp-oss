package handlers

// step_up_passkey.go — THE-PHISHING-RESISTANT-ACR: the OP-native passkey
// step-up ceremony, the same shape as the TOTP one (step_up.go) with a
// WebAuthn assertion instead of a code.
//
// /authorize refers an interactive browser here when acr_values asks for a
// rung only a passkey reaches (the phishing-resistant rung; or the mfa rung
// for a user without TOTP who holds a passkey), the live session sits below
// it, and the user has at least one WebAuthn credential. GET renders a page
// whose inline script runs navigator.credentials.get with the request
// options minted for THIS session's user; POST verifies the assertion
// through the existing WebAuthnService.FinishLogin (same validator, same
// single-use ceremony session, same RP-ID/origin checks), refuses an
// assertion by ANY OTHER USER, and only then records the uplift on the SAME
// browser session (Session.RecordACRUplift → sessions.last_acr_uplift_at/
// _value). A failed or foreign assertion writes nothing. Nothing here ever
// stamps a requested-but-unverified acr.
//
// CSRF: the finish is bound to a single-use, unguessable ceremony session
// that only the page (rendered for the cookie session) receives, and the
// assertion itself signs the server challenge — a cross-site POST cannot
// produce either.

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// PasskeyStepUpAsserter runs the WebAuthn assertion ceremony for a known
// user. *service.WebAuthnService satisfies it (BeginAssertion + FinishLogin).
type PasskeyStepUpAsserter interface {
	BeginAssertion(ctx context.Context, user *domain.User) (options any, sessionID string, err error)
	FinishLogin(ctx context.Context, sessionID string, request *http.Request) (*domain.WebAuthnCredential, *domain.User, bool, error)
}

// PasskeyStepUpHandlerDeps wires the ceremony. CookieSession, WebAuthn and
// Sessions are REQUIRED (the routes do not register without them).
type PasskeyStepUpHandlerDeps struct {
	CookieSession StepUpSessionResolver
	WebAuthn      PasskeyStepUpAsserter
	Sessions      ACRUpliftRecorder
	Audit         audit.Service
	// Now is injectable for tests; nil → time.Now.
	Now func() time.Time
}

// RegisterPasskeyStepUpRoutes mounts
//
//	GET  /api/v1/auth/step-up/passkey
//	POST /api/v1/auth/step-up/passkey
func RegisterPasskeyStepUpRoutes(router gin.IRouter, deps PasskeyStepUpHandlerDeps) {
	if deps.CookieSession == nil || deps.WebAuthn == nil || deps.Sessions == nil {
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
	// docgen:path=/api/v1/auth/step-up/passkey
	// docgen:summary=Render the passkey step-up page for the browser session (THE-PHISHING-RESISTANT-ACR: /authorize refers here when acr_values asks for a rung only a passkey reaches); mints the WebAuthn assertion options for this session's user.
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:notes=Browser session cookie required (401 login_required without it); 403 passkey_not_enrolled when the user holds no WebAuthn credential. Preserves return_to (same-origin path only) so the verified step-up resumes the original authorize request.
	router.GET("/api/v1/auth/step-up/passkey", HandlePasskeyStepUpPage(deps))

	// docgen:endpoint
	// docgen:surface=auth
	// docgen:method=POST
	// docgen:path=/api/v1/auth/step-up/passkey
	// docgen:summary=Finish the passkey step-up: verifies the WebAuthn assertion for the single-use ceremony session_id; when it verifies for the SAME user as the browser session, records an ACR uplift to the phishing-resistant rung and returns the return_to to resume.
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:notes=JSON body is the PublicKeyCredential assertion (base64url fields). 401 invalid_assertion on any verification failure or on an assertion by another user — nothing is recorded; 503 when the uplift cannot be persisted (the ceremony is never resumed on an unrecorded uplift).
	router.POST("/api/v1/auth/step-up/passkey", HandlePasskeyStepUpFinish(deps))
}

// HandlePasskeyStepUpPage begins the assertion ceremony for the cookie
// session's user and renders the page that runs it.
func HandlePasskeyStepUpPage(deps PasskeyStepUpHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		resolved, storeErr := resolveStepUpSession(c, StepUpHandlerDeps{CookieSession: deps.CookieSession})
		if storeErr != nil {
			respondAuthStoreUnavailable(c, "step-up.passkey.cookie-session", storeErr)
			return
		}
		if resolved == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "login_required", "reason": "login_required"})
			return
		}
		returnTo := validateReturnTo(c.Query("return_to"))
		options, ceremonyID, err := deps.WebAuthn.BeginAssertion(c.Request.Context(), resolved.User)
		if err != nil {
			if errors.Is(err, service.ErrWebAuthnNoCredentials) {
				c.JSON(http.StatusForbidden, gin.H{"error": "passkey_not_enrolled"})
				return
			}
			c.String(http.StatusServiceUnavailable, "temporarily unavailable, try again")
			return
		}
		optionsJSON, err := json.Marshal(options) // encoding/json escapes <, >, & → safe inside <script>
		if err != nil {
			c.String(http.StatusServiceUnavailable, "temporarily unavailable, try again")
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Status(http.StatusOK)
		renderPasskeyStepUpPage(c.Writer, string(optionsJSON), ceremonyID, returnTo, c.Query("error"))
	}
}

// HandlePasskeyStepUpFinish verifies the assertion and records the uplift.
func HandlePasskeyStepUpFinish(deps PasskeyStepUpHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		resolved, storeErr := resolveStepUpSession(c, StepUpHandlerDeps{CookieSession: deps.CookieSession})
		if storeErr != nil {
			respondAuthStoreUnavailable(c, "step-up.passkey.cookie-session", storeErr)
			return
		}
		if resolved == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "login_required", "reason": "login_required"})
			return
		}
		ip, ua := c.ClientIP(), c.Request.UserAgent()
		ceremonyID := strings.TrimSpace(c.Query("session_id"))
		if ceremonyID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		returnTo := validateReturnTo(c.Query("return_to"))
		_, assertedUser, _, err := deps.WebAuthn.FinishLogin(c.Request.Context(), ceremonyID, c.Request)
		if err != nil || assertedUser == nil || assertedUser.ID != resolved.User.ID {
			// A failed assertion, or a valid assertion by ANOTHER user, uplifts
			// nothing: the browser session's user did not perform it.
			reason := "assertion_invalid"
			if err == nil && assertedUser != nil {
				reason = "user_mismatch"
			}
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{
				Action: "user_session.step_up.passkey_failure", Outcome: "denied", IPAddress: ip, UserAgent: ua,
				Metadata: map[string]any{"session_id": resolved.Session.ID.String(), "reason": reason},
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_assertion"})
			return
		}
		now := deps.Now().UTC()
		if err := deps.Sessions.RecordACRUplift(c.Request.Context(), resolved.Session.ID, now, service.ACRPhishingResistant); err != nil {
			// Verified but not persisted: refusing is the only honest answer.
			c.String(http.StatusServiceUnavailable, "temporarily unavailable, try again")
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action: "user_session.step_up.passkey_success", Outcome: "success", IPAddress: ip, UserAgent: ua,
			Metadata: map[string]any{"user_id": resolved.User.ID.String(), "session_id": resolved.Session.ID.String(), "acr": service.ACRPhishingResistant},
		})
		if returnTo == "" {
			returnTo = "/"
		}
		c.JSON(http.StatusOK, gin.H{"return_to": returnTo})
	}
}

const passkeyStepUpPageTemplate = `<!DOCTYPE html>
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
    <p>The application asked for a passkey sign-in. Use your passkey to continue.</p>
    <p id="status" role="status">Waiting for your passkey…</p>
    {{ERROR}}
    <p><button id="retry" type="button" hidden>Try again</button></p>
    <noscript><p role="alert">This step needs JavaScript to talk to your passkey.</p></noscript>
    <script>
    (function () {
      var OPTIONS = {{OPTIONS}};
      var CEREMONY = "{{CEREMONY}}";
      var RETURN_TO = "{{RETURN_TO}}";
      function b64uToBuf(s) {
        var b = s.replace(/-/g, "+").replace(/_/g, "/");
        b += "=".repeat((4 - (b.length % 4)) % 4);
        var bin = atob(b), out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out.buffer;
      }
      function bufToB64u(buf) {
        var bytes = new Uint8Array(buf), bin = "";
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      }
      var status = document.getElementById("status");
      var retry = document.getElementById("retry");
      retry.addEventListener("click", function () { window.location.reload(); });
      function fail(msg) {
        status.textContent = msg;
        status.setAttribute("data-error", "passkey_failed");
        retry.hidden = false;
      }
      async function run() {
        try {
          var pk = Object.assign({}, OPTIONS);
          pk.challenge = b64uToBuf(OPTIONS.challenge);
          pk.allowCredentials = (OPTIONS.allowCredentials || []).map(function (c) {
            return Object.assign({}, c, { id: b64uToBuf(c.id) });
          });
          var cred = await navigator.credentials.get({ publicKey: pk });
          var r = cred.response;
          var body = {
            id: cred.id,
            rawId: bufToB64u(cred.rawId),
            type: cred.type,
            response: {
              authenticatorData: bufToB64u(r.authenticatorData),
              clientDataJSON: bufToB64u(r.clientDataJSON),
              signature: bufToB64u(r.signature),
              userHandle: r.userHandle ? bufToB64u(r.userHandle) : null
            }
          };
          var url = "/api/v1/auth/step-up/passkey?session_id=" + encodeURIComponent(CEREMONY) +
                    "&return_to=" + encodeURIComponent(RETURN_TO);
          var res = await fetch(url, {
            method: "POST", credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
          });
          if (!res.ok) { fail("That passkey was not accepted. Please try again."); return; }
          var data = await res.json();
          status.textContent = "Verified. Returning to the application…";
          window.location.assign(data.return_to || "/");
        } catch (e) {
          fail("The passkey step did not complete. Please try again.");
        }
      }
      run();
    })();
    </script>
  </main>
</body>
</html>`

func renderPasskeyStepUpPage(w http.ResponseWriter, optionsJSON, ceremonyID, returnTo, errCode string) {
	body := strings.ReplaceAll(passkeyStepUpPageTemplate, "{{OPTIONS}}", optionsJSON)
	body = strings.ReplaceAll(body, "{{CEREMONY}}", jsStringEscape(ceremonyID))
	body = strings.ReplaceAll(body, "{{RETURN_TO}}", jsStringEscape(returnTo))
	if errCode != "" {
		body = strings.ReplaceAll(body, "{{ERROR}}", `<p role="alert" data-error="`+html.EscapeString(errCode)+`">The previous attempt was not accepted.</p>`)
	} else {
		body = strings.ReplaceAll(body, "{{ERROR}}", "")
	}
	_, _ = w.Write([]byte(body))
}

// jsStringEscape makes s safe inside a double-quoted JS string literal that
// sits in an HTML <script> block (json.Marshal escapes <, >, & as <…).
func jsStringEscape(s string) string {
	b, _ := json.Marshal(s)
	return strings.TrimSuffix(strings.TrimPrefix(string(b), `"`), `"`)
}
