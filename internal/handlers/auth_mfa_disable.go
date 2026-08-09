package handlers

// auth_mfa_disable.go — OSS handler for the self-service MFA
// disable endpoint. The route POST /api/v1/me/mfa/disable is
// registered in RegisterAuthSessionRoutes alongside the rest of
// the /me/mfa surface (status read + recovery-code regenerate)
// and follows the same authority shape: mw.RequireAuthenticated
// gates entry and mw.PrincipalFromContext supplies the user_id.
// There is NO user_id parameter on the wire, so cross-user calls
// are structurally impossible.
//
// Re-auth contract:
//
//   - The handler accepts `code` and `password`. When `code` is
//     non-empty, the service tries the TOTP leg first; on TOTP miss
//     it falls back to a recovery-code match and does NOT try the
//     password. A matched recovery code is burned BEFORE the final
//     disable Update so a downstream failure cannot leave a reusable
//     code on the row.
//   - When `code` is empty and `password` is non-empty, the service
//     verifies the authenticated local user's current password.
//   - A code/password proof that does not match returns 401
//     invalid_code. The wire NEVER distinguishes "wrong TOTP" from
//     "wrong recovery code" from "wrong password".
//
// Policy gate:
//
//   - site_admin / org_admin / org with mfa_policy="required" are
//     refused with 403 mfa_required_by_policy and the user row is
//     left byte-identical. The policy check fires BEFORE the
//     verify leg so a denied call cannot leak the supplied code
//     through any state mutation.
//
// Post-disable side-effects (best-effort; failures swallowed):
//
//   - SessionRevoker.RevokeUserSessions fan-out so cookie sessions
//     stop authenticating.
//   - RefreshTokenRevoker.RevokeAllForUser fan-out so OAuth refresh
//     tokens stop minting access tokens.
//   - Audit row via the existing domain.AuditMFADisabled typed
//     constant. Metadata is identifier-shaped only — user_id,
//     organization_id, reauth_method, plus the safe count keys
//     emitted by the existing admin-reset family. The supplied
//     code, MFASecret, recovery codes, session IDs, refresh
//     tokens, token hashes, password, and password hash NEVER appear
//     in any of these.

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// mfaDisableRequest is the on-the-wire shape. Only the `code` and
// `password` fields are read; any other key is ignored.
type mfaDisableRequest struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

// HandleMFADisableSelf is the gin handler for POST
// /api/v1/me/mfa/disable. See the file-header doc for the full
// contract.
func HandleMFADisableSelf(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Defensive Cache-Control + Pragma on every response from
		// this handler so failure envelopes never end up cached.
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		principal, ok := mw.PrincipalFromContext(c)
		if !ok || principal == nil || principal.UserID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		var req mfaDisableRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		reauth, err := deps.MFAEnrollment.DisableSelfWithProof(c.Request.Context(), principal.UserID, service.MFADisableSelfInput{
			Code:     req.Code,
			Password: req.Password,
		})
		if err != nil {
			switch {
			case errors.Is(err, service.ErrMFANotEnrolled):
				c.JSON(http.StatusBadRequest, gin.H{"error": "mfa_not_enrolled"})
			case errors.Is(err, service.ErrMFADisableForbiddenByPolicy):
				c.JSON(http.StatusForbidden, gin.H{"error": "mfa_required_by_policy"})
			case errors.Is(err, service.ErrMFADisableInvalidCode):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_code"})
			case errors.Is(err, service.ErrMFAEnrollmentInvalid):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			}
			return
		}
		// Post-disable revocation fan-out. Both seams are
		// warn-and-continue per the existing admin-reset contract:
		// errors do not fail the disable (MFA is already off at
		// this point) and only count + success-flag identifiers
		// reach the audit row.
		sessionErr := deps.SessionRevoker.RevokeUserSessions(
			c.Request.Context(),
			principal.UserID,
			"mfa_self_disabled",
			map[string]any{
				"organization_id": principal.OrganizationID.String(),
			},
		)
		refreshCount, refreshErr := deps.RefreshTokenRevoker.RevokeAllForUser(c.Request.Context(), principal.UserID)
		c.Status(http.StatusNoContent)
		auditMeta := map[string]any{
			"user_id":          principal.UserID.String(),
			"organization_id":  principal.OrganizationID.String(),
			"reauth_method":    string(reauth),
			"sessions_revoked": sessionErr == nil,
		}
		if refreshErr == nil {
			auditMeta["refresh_tokens_revoked_count"] = refreshCount
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    string(domain.AuditMFADisabled),
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  auditMeta,
		})
	}
}
