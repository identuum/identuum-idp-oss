package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/setup"
)

// recordSetupCompleted writes the two rows a completed first-run setup owes
// the audit log (OSS-POLISH, audit F4): setup.completed for the first
// organization and user_created for the pinned site_admin, the first admin.
// The caller holds only the setup token, so the actor type says so. Neither
// row carries the token, the password or the operator's typed address.
func recordSetupCompleted(c *gin.Context, auditSvc audit.Service, out *setup.CompleteOutput) {
	if auditSvc == nil || out == nil {
		return
	}
	siteAdminID, _ := uuid.Parse(domain.SiteAdminID)
	base := audit.Event{
		Outcome:        "success",
		ActorType:      "setup_token",
		OrganizationID: out.OrganizationID,
		IPAddress:      c.ClientIP(),
		UserAgent:      c.Request.UserAgent(),
	}
	done := base
	done.Action = "setup.completed"
	done.Metadata = map[string]any{"organization_id": out.OrganizationID.String(), "organization_name": out.OrganizationName}
	_ = auditSvc.Record(c.Request.Context(), done)
	admin := base
	admin.Action = string(domain.AuditUserCreated)
	admin.SubjectID = siteAdminID
	admin.SubjectType = "user"
	admin.SubjectEmail = out.LoginEmail
	admin.Metadata = map[string]any{"role": string(domain.RoleSiteAdmin), "first_admin": true}
	_ = auditSvc.Record(c.Request.Context(), admin)
}

// SetupService is the narrow interface the appliance setup routes
// depend on. *setup.Service satisfies it; tests substitute fakes.
type SetupService interface {
	Status(ctx context.Context) (*setup.StatusView, error)
	VerifyToken(ctx context.Context, plaintext string) error
	Complete(ctx context.Context, dataDir string, in setup.CompleteInput) (*setup.CompleteOutput, error)
}

// SetupRoutesDeps is the narrow dependency bundle for the appliance
// setup routes. The Service holds every collaborator the handlers need;
// DataDir is required so Complete can sweep the on-disk token file.
type SetupRoutesDeps struct {
	Service SetupService
	DataDir string
	// Audit records setup.completed and the first admin's user_created
	// (OSS-POLISH, audit F4). Nil records nothing.
	Audit audit.Service
}

// setupCompleteRequest is the wizard form submission. The
// admin_password field is plaintext on the wire: it is consumed
// directly by the user repository which argon2id-hashes it on insert.
// We deliberately do not bind it into any log line or error wrap.
type setupCompleteRequest struct {
	SetupToken         string `json:"setup_token"         binding:"required"`
	OrganizationName   string `json:"organization_name"   binding:"required,min=1,max=255"`
	OrganizationDomain string `json:"organization_domain"`
	AdminEmail         string `json:"admin_email"         binding:"required,email"`
	AdminPassword      string `json:"admin_password"      binding:"required,min=12"`
}

// setupVerifyTokenRequest is the wizard's "is this code correct" probe.
type setupVerifyTokenRequest struct {
	SetupToken string `json:"setup_token" binding:"required"`
}

// RegisterSetupRoutes attaches the appliance setup endpoints to router.
// All three routes are public and unauthenticated — the setup token is
// the wizard-authorisation credential and is checked at the handler
// layer. Mount this BEFORE any bearer-token populator so the routes
// stay reachable even when no admin user exists yet.
//
//   - GET  /api/setup/status        — always returns the no-secrets state
//   - POST /api/setup/verify-token  — 204 on match, 401 on miss, 410 once complete
//   - POST /api/setup/complete      — runs the wizard, 410 once complete
//
// The /api/setup/ path prefix is deliberately outside /api/v1/: these
// are pre-completion appliance APIs, not the versioned product API.
func RegisterSetupRoutes(router gin.IRouter, deps SetupRoutesDeps) {
	if deps.Service == nil {
		return
	}

	// docgen:endpoint
	// docgen:surface=setup
	// docgen:method=GET
	// docgen:path=/api/setup/status
	// docgen:summary=First-run setup status — no-secrets snapshot of setup_required/setup_complete.
	// docgen:tier=oss
	// docgen:auth=public
	router.GET("/api/setup/status", handleSetupStatus(deps))

	// docgen:endpoint
	// docgen:surface=setup
	// docgen:method=POST
	// docgen:path=/api/setup/verify-token
	// docgen:summary=Verify a candidate setup token plaintext against the stored hash.
	// docgen:tier=oss
	// docgen:auth=public
	// docgen:status=204
	router.POST("/api/setup/verify-token", handleSetupVerifyToken(deps))

	// docgen:endpoint
	// docgen:surface=setup
	// docgen:method=POST
	// docgen:path=/api/setup/complete
	// docgen:summary=Complete first-run setup — creates the first organization, site_admin, and signing key.
	// docgen:tier=oss
	// docgen:auth=public
	router.POST("/api/setup/complete", handleSetupComplete(deps))
}

func handleSetupStatus(deps SetupRoutesDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		view, err := deps.Service.Status(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "setup_status_unavailable"})
			return
		}
		c.JSON(http.StatusOK, view)
	}
}

func handleSetupVerifyToken(deps SetupRoutesDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req setupVerifyTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		err := deps.Service.VerifyToken(c.Request.Context(), req.SetupToken)
		switch {
		case err == nil:
			c.Status(http.StatusNoContent)
		case errors.Is(err, setup.ErrAlreadyComplete):
			c.JSON(http.StatusGone, gin.H{"error": "setup_already_complete"})
		case errors.Is(err, setup.ErrTokenInvalid):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "setup_token_invalid"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "setup_verify_failed"})
		}
	}
}

func handleSetupComplete(deps SetupRoutesDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req setupCompleteRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		in := setup.CompleteInput{
			SetupToken:         req.SetupToken,
			OrganizationName:   req.OrganizationName,
			OrganizationDomain: req.OrganizationDomain,
			AdminEmail:         req.AdminEmail,
			AdminPassword:      req.AdminPassword,
		}
		out, err := deps.Service.Complete(c.Request.Context(), deps.DataDir, in)
		// Defensive scrub: don't keep the password in the request struct
		// any longer than necessary, even though Go strings are immutable.
		req.AdminPassword = ""
		switch {
		case err == nil:
			c.JSON(http.StatusOK, out)
			recordSetupCompleted(c, deps.Audit, out)
		case errors.Is(err, setup.ErrAlreadyComplete):
			c.JSON(http.StatusGone, gin.H{"error": "setup_already_complete"})
		case errors.Is(err, setup.ErrTokenInvalid):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "setup_token_invalid"})
		case errors.Is(err, setup.ErrOrganizationDomainRequired):
			// The name yields no default domain and none was given: the
			// operator must enter one (v0.5.1).
			c.JSON(http.StatusBadRequest, gin.H{"error": "organization_domain_required"})
		default:
			// validation errors and downstream service failures both
			// land here. We do not echo the underlying error message —
			// it may carry user input we don't want reflected — but we
			// do log it at the gin layer (handled by upstream middleware
			// in production; in tests, the failure body is structural).
			c.JSON(http.StatusBadRequest, gin.H{"error": "setup_complete_failed"})
		}
	}
}
