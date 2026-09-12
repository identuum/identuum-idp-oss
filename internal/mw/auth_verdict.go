package mw

// auth_verdict.go — THE-SESSION-REJECTION-ROOT-CAUSE (2026-09-02), AUTH-503.
//
// Two response classes on the authentication path, never confused:
//
//   - 401 is a VERDICT about the credential: absent, invalid, expired,
//     revoked, mismatched, session not live. Every 401 carries a `reason`
//     naming the verdict (vocabulary below) so a client — and the harness —
//     can tell them apart.
//   - 503 is a STORE / INFRASTRUCTURE failure: the check could not be
//     completed. The refusal is unchanged (fail closed, nothing is
//     admitted), only the STATUS and the LOG change: an ERROR line with a
//     correlation id and the lookup that failed, and the same correlation
//     id on the wire (`correlation_id` body member and the X-Request-ID
//     header) so an operator can join the two.
//
// The correlation id comes from CorrelationIDMiddleware (mounted globally
// by the OSS router) — the incoming X-Request-ID when it is well-formed,
// a fresh uuid otherwise — and is stored in the request context under
// logger.RequestIDKey so every logger.*Context line on the request carries
// it as `request_id` for free.

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/logger"
)

// CorrelationIDHeader is read on the way in (when well-formed) and always
// written on the way out.
const CorrelationIDHeader = "X-Request-ID"

const correlationIDContextKey = "identuum.correlation_id"

// Verdict reasons carried by 401 bodies. Stable vocabulary — the ui e2e
// asserts every auth 401 names one.
const (
	// ReasonNoCredential — no bearer / cookie credential was presented to a
	// guarded route (RequireAuthenticated & co.).
	ReasonNoCredential = "no_credential"
	// ReasonMissingCredential — a Bearer scheme with an empty token.
	ReasonMissingCredential = "missing_credential"
	// ReasonTokenInvalid — signature / claims / expiry verdict from the verifier.
	ReasonTokenInvalid = "token_invalid"
	// ReasonTokenRevoked — the jti is in the revocation store.
	ReasonTokenRevoked = "token_revoked"
	// ReasonSessionNotLive — the session / user / org liveness verdict is false.
	ReasonSessionNotLive = "session_not_live"
)

// CorrelationIDMiddleware assigns one correlation id per request: the
// incoming X-Request-ID when it is 1–64 chars of [A-Za-z0-9._-], else a
// fresh uuid. It is stored on the gin context and in the request context
// (logger.RequestIDKey) and echoed as the X-Request-ID response header.
func CorrelationIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := sanitizeCorrelationID(c.GetHeader(CorrelationIDHeader))
		if id == "" {
			id = uuid.NewString()
		}
		bindCorrelationID(c, id)
		c.Next()
	}
}

// CorrelationID returns the request's correlation id, minting and binding
// one when the middleware did not run (tests, alternative engines).
func CorrelationID(c *gin.Context) string {
	if v, ok := c.Get(correlationIDContextKey); ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	id := sanitizeCorrelationID(c.GetHeader(CorrelationIDHeader))
	if id == "" {
		id = uuid.NewString()
	}
	bindCorrelationID(c, id)
	return id
}

func bindCorrelationID(c *gin.Context, id string) {
	c.Set(correlationIDContextKey, id)
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), logger.RequestIDKey, id))
	c.Header(CorrelationIDHeader, id)
}

func sanitizeCorrelationID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 64 {
		return ""
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return ""
		}
	}
	return raw
}

// AuthStoreErrorSink receives every auth-path store error that is answered
// with 503, AFTER the correlation id is bound and BEFORE the response is
// written. The default writes the ERROR log line. It is a package variable
// so the rule test can prove "every 503 has its log line" by observing the
// sink; production code never reassigns it.
var AuthStoreErrorSink = func(ctx context.Context, where, correlationID string, err error) {
	logger.ErrorContext(ctx,
		"AUTH-503: auth-path store error — refused with 503, NOT an authentication verdict",
		zap.String("where", where),
		zap.String("correlation_id", correlationID),
		zap.Error(err),
	)
}

// RecordAuthStoreError logs the store error through AuthStoreErrorSink
// with the request's correlation id, sets Retry-After and X-Request-ID,
// and returns the correlation id for the caller's response body. Callers
// that render their own body (HTML for a browser page) use this directly;
// JSON callers use RespondAuthStoreUnavailable.
func RecordAuthStoreError(c *gin.Context, where string, err error) string {
	cid := NoteAuthStoreError(c, where, err)
	c.Header("Retry-After", "1")
	c.Header("Cache-Control", "no-store")
	return cid
}

// NoteAuthStoreError is the log-only half of RecordAuthStoreError: the
// ERROR line through AuthStoreErrorSink with the request's correlation id,
// no response headers. For paths that still complete for the user (a
// logout that clears the cookie even though the store could not confirm
// the revocation — THE-LOGOUT-THAT-CANNOT-REVOKE) where Retry-After would
// mislead the RP.
func NoteAuthStoreError(c *gin.Context, where string, err error) string {
	cid := CorrelationID(c)
	AuthStoreErrorSink(c.Request.Context(), where, cid, err)
	return cid
}

// AuthStoreUnavailableBody is the JSON body every 503 of this class
// carries: `error` is the OAuth code, `reason` the class marker, and
// `correlation_id` joins the wire response to the ERROR log line.
func AuthStoreUnavailableBody(correlationID string) gin.H {
	return gin.H{
		"error":             "temporarily_unavailable",
		"error_description": "authentication store unavailable; retry",
		"reason":            "auth_store_error",
		"correlation_id":    correlationID,
	}
}

// RespondAuthStoreUnavailable answers an auth-path store error: ERROR log
// with the correlation id, then 503 JSON. The request is aborted — nothing
// downstream runs, exactly as for a 401.
func RespondAuthStoreUnavailable(c *gin.Context, where string, err error) {
	cid := RecordAuthStoreError(c, where, err)
	c.AbortWithStatusJSON(http.StatusServiceUnavailable, AuthStoreUnavailableBody(cid))
}

// RespondUnauthenticatedReason is the 401 verdict with its reason.
//
// THE-SILENT-REFUSAL (2026-09-12): the verdict is ALSO logged, once, on the
// security logger — the reason code with the request's method, path and
// client IP, never the credential. Until this line a refusal reached only the
// caller's response body and left no server-side trace: three September e2e
// mints failed on a bearer 401 that nothing could name (wiki log/0025,
// 0026, 0029 and the mint of 2026-09-12). The reason already travels to the
// caller, so logging it discloses nothing new; the token, the Authorization
// header and every other credential stay out of the line by construction —
// nothing here reads them, and AUTH-REFUSAL-LOGGED-1 pins that. request_id
// rides along from the context when CorrelationIDMiddleware set it. The
// status, body and verdict are unchanged.
func RespondUnauthenticatedReason(c *gin.Context, reason string) {
	ctx := context.Background()
	method, path := "", ""
	if c.Request != nil {
		ctx = c.Request.Context()
		method = c.Request.Method
		if c.Request.URL != nil {
			path = c.Request.URL.Path
		}
	}
	logger.Security.WarnContext(ctx, "authentication refused",
		zap.String("event_type", "auth_refused"),
		zap.String("reason", reason),
		zap.String("method", method),
		zap.String("path", path),
		zap.String("ip_address", c.ClientIP()),
	)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":  "unauthorized",
		"reason": reason,
	})
}
