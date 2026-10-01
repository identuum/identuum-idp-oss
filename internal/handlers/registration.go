package handlers

// registration.go — self-registration (owner ruling D-021, rulings a-c).
//
// Public (no credential):
//   GET  /api/v1/auth/register/:org_slug  200 {open:false} | {open:true, verify_email, approval_required, password_policy}
//   POST /api/v1/auth/register/:org_slug  {email, name, password}
//        202 {"accepted":true} for every outcome (new, existing, closed,
//        unknown, idp_only, wrong domain); 400 weak_password (an open
//        organization's policy) is the only other answer. Per IP (/64) and
//        per organization rate-limited.
// site_admin:
//   GET|PUT /api/v1/settings/self-registration           {enabled}
// org_admin (its own organization):
//   GET|PUT /api/v1/organizations/:id/registration       the policy
//   GET     /api/v1/organizations/:id/registrations      pending approval
//   POST    /api/v1/users/:id/approve | /reject          (approve: users.go)

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Registrar is the self-registration service (*service.RegistrationService).
type Registrar interface {
	InstanceEnabled(ctx context.Context) (bool, error)
	SetInstanceEnabled(ctx context.Context, actor *domain.Principal, enabled bool) error
	OrgSettings(ctx context.Context, actor *domain.Principal, orgID uuid.UUID) (*domain.OrgRegistrationSettings, error)
	UpdateOrgSettings(ctx context.Context, actor *domain.Principal, orgID uuid.UUID, in domain.OrgRegistrationSettings) (*domain.OrgRegistrationSettings, error)
	Info(ctx context.Context, slug string) service.RegistrationInfo
	Register(ctx context.Context, slug string, in service.RegisterInput) error
	ListPending(ctx context.Context, actor *domain.Principal, orgID uuid.UUID) ([]domain.PendingRegistration, error)
	Approve(ctx context.Context, actor *domain.Principal, userID uuid.UUID) (*domain.User, error)
	Reject(ctx context.Context, actor *domain.Principal, userID uuid.UUID) error
}

// RegistrationHandlerDeps wires the routes. Limiters are the per-IP and
// per-organization limits of the public POST.
type RegistrationHandlerDeps struct {
	Registrar Registrar
	Limiters  []gin.HandlerFunc
}

// RegistrationOrgKey keys the per-organization limiter by the path's slug.
func RegistrationOrgKey(c *gin.Context) string { return "register-org:" + c.Param("org_slug") }

func registrationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrForbidden):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	case errors.Is(err, domain.ErrOrganizationNotFound), errors.Is(err, domain.ErrUserNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case errors.Is(err, service.ErrRegistrationInstanceDisabled):
		c.JSON(http.StatusConflict, gin.H{"error": "instance_registration_disabled"})
	case errors.Is(err, service.ErrRegistrationSMTPNotConfigured):
		c.JSON(http.StatusBadRequest, gin.H{"error": "smtp_not_configured"})
	case errors.Is(err, service.ErrRegistrationInvalidDomain):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_email_domain"})
	case errors.Is(err, service.ErrRegistrationNotPending):
		c.JSON(http.StatusConflict, gin.H{"error": "user is not pending registration approval"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}

func principal(c *gin.Context) *domain.Principal { p, _ := mw.PrincipalFromContext(c); return p }

func pathUUID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
	}
	return id, err == nil
}

// HandleRegistrationInfo serves GET /api/v1/auth/register/:org_slug.
func HandleRegistrationInfo(r Registrar) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, r.Info(c.Request.Context(), c.Param("org_slug")))
	}
}

// HandleSelfRegister serves POST /api/v1/auth/register/:org_slug.
func HandleSelfRegister(r Registrar) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email    string `json:"email"`
			Name     string `json:"name"`
			Password string `json:"password"`
		}
		_ = c.ShouldBindJSON(&req)
		err := r.Register(c.Request.Context(), c.Param("org_slug"), service.RegisterInput{
			Email: req.Email, Name: req.Name, Password: req.Password, IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent()})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "weak_password", "message": err.Error()})
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"accepted": true})
	}
}

// HandleGetInstanceRegistration serves GET /api/v1/settings/self-registration.
func HandleGetInstanceRegistration(r Registrar) gin.HandlerFunc {
	return func(c *gin.Context) {
		on, err := r.InstanceEnabled(c.Request.Context())
		if err != nil {
			registrationError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"enabled": on})
	}
}

// HandleSetInstanceRegistration serves PUT /api/v1/settings/self-registration.
func HandleSetInstanceRegistration(r Registrar) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if err := r.SetInstanceEnabled(c.Request.Context(), principal(c), *req.Enabled); err != nil {
			registrationError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"enabled": *req.Enabled})
	}
}

// HandleGetOrgRegistration serves GET /api/v1/organizations/:id/registration.
func HandleGetOrgRegistration(r Registrar) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := pathUUID(c)
		if !ok {
			return
		}
		set, err := r.OrgSettings(c.Request.Context(), principal(c), id)
		if err != nil {
			registrationError(c, err)
			return
		}
		c.JSON(http.StatusOK, set)
	}
}

// HandleSetOrgRegistration serves PUT /api/v1/organizations/:id/registration.
func HandleSetOrgRegistration(r Registrar) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := pathUUID(c)
		if !ok {
			return
		}
		var in domain.OrgRegistrationSettings
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		set, err := r.UpdateOrgSettings(c.Request.Context(), principal(c), id, in)
		if err != nil {
			registrationError(c, err)
			return
		}
		c.JSON(http.StatusOK, set)
	}
}

// HandleListPendingRegistrations serves GET /api/v1/organizations/:id/registrations.
func HandleListPendingRegistrations(r Registrar) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := pathUUID(c)
		if !ok {
			return
		}
		list, err := r.ListPending(c.Request.Context(), principal(c), id)
		if err != nil {
			registrationError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"registrations": list})
	}
}

// HandleRejectRegistration serves POST /api/v1/users/:id/reject.
func HandleRejectRegistration(r Registrar) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := pathUUID(c)
		if !ok {
			return
		}
		if err := r.Reject(c.Request.Context(), principal(c), id); err != nil {
			registrationError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// RegisterRegistrationRoutes mounts the routes when a Registrar is wired.
func RegisterRegistrationRoutes(router gin.IRouter, deps RegistrationHandlerDeps) {
	if deps.Registrar == nil {
		return
	}
	r := deps.Registrar

	// docgen:endpoint
	// docgen:surface=auth
	// docgen:method=GET
	// docgen:path=/api/v1/auth/register/:org_slug
	// docgen:summary=Whether an organization accepts self-registration (D-021): {open:false} for a closed, unknown or idp_only organization alike; else {open:true, verify_email, approval_required, password_policy}.
	// docgen:tier=oss
	// docgen:auth=public
	router.GET("/api/v1/auth/register/:org_slug", HandleRegistrationInfo(r))

	// docgen:endpoint
	// docgen:surface=auth
	// docgen:method=POST
	// docgen:path=/api/v1/auth/register/:org_slug
	// docgen:summary=Self-register as an org_user (D-021). One 202 {"accepted":true} for a new address, an existing one, a closed, unknown or idp_only organization and a refused email domain; 400 weak_password for a password an open organization's policy refuses. Rate-limited per IP (an IPv6 client by its /64) and per organization.
	// docgen:tier=oss
	// docgen:auth=public
	// docgen:status=202
	router.POST("/api/v1/auth/register/:org_slug", append(append([]gin.HandlerFunc{}, deps.Limiters...), HandleSelfRegister(r))...)

	site := router.Group("/api/v1/settings/self-registration", mw.RequireSiteAdmin())
	// docgen:endpoint
	// docgen:surface=organizations
	// docgen:method=GET
	// docgen:path=/api/v1/settings/self-registration
	// docgen:summary=The instance self-registration switch (D-021), the ceiling every organization's switch sits under. Off by default.
	// docgen:tier=oss
	// docgen:auth=site_admin
	site.GET("", HandleGetInstanceRegistration(r))
	// docgen:endpoint
	// docgen:surface=organizations
	// docgen:method=PUT
	// docgen:path=/api/v1/settings/self-registration
	// docgen:summary=Set the instance self-registration switch {enabled} (D-021); audited. Off closes every organization's sign-up.
	// docgen:tier=oss
	// docgen:auth=site_admin
	site.PUT("", HandleSetInstanceRegistration(r))

	org := router.Group("/api/v1/organizations/:id", mw.RequireSiteAdminOrSameOrgAdmin("id"))
	// docgen:endpoint
	// docgen:surface=organizations
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/:id/registration
	// docgen:summary=The organization's self-registration policy (D-021): allow_public_registration, require_registration_approval, verify_email, email_domains. org_admin of the organization only.
	// docgen:tier=oss
	// docgen:auth=org_admin
	org.GET("/registration", HandleGetOrgRegistration(r))
	// docgen:endpoint
	// docgen:surface=organizations
	// docgen:method=PUT
	// docgen:path=/api/v1/organizations/:id/registration
	// docgen:summary=Set the organization's self-registration policy (D-021); audited. 409 instance_registration_disabled when opening it while the instance switch is off; 400 smtp_not_configured when requiring a verified email without SMTP; 400 invalid_email_domain.
	// docgen:tier=oss
	// docgen:auth=org_admin
	org.PUT("/registration", HandleSetOrgRegistration(r))
	// docgen:endpoint
	// docgen:surface=organizations
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/:id/registrations
	// docgen:summary=Self-registrants held for approval (D-021): {registrations:[{id, email, name, created_at}]}. org_admin of the organization only.
	// docgen:tier=oss
	// docgen:auth=org_admin
	org.GET("/registrations", HandleListPendingRegistrations(r))

	// docgen:endpoint
	// docgen:surface=users
	// docgen:method=POST
	// docgen:path=/api/v1/users/:id/reject
	// docgen:summary=Reject a self-registrant held for approval (D-021): the account is deleted; audited. 409 when the user is not pending approval.
	// docgen:tier=oss
	// docgen:auth=org_admin
	router.POST("/api/v1/users/:id/reject", mw.RequireAuthenticated(), HandleRejectRegistration(r))
}
