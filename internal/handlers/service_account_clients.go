package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// ServiceAccountClientBundleHandlerDeps wires the combined-create
// route. ServiceAccountClientBundleService is required; routes
// register ONLY when it is non-nil.
type ServiceAccountClientBundleHandlerDeps struct {
	BundleService *service.ServiceAccountClientBundleService
	Audit         audit.Service
}

// RegisterServiceAccountClientBundleRoutes mounts
//
//	POST /api/v1/organizations/:id/service-accounts/with-client
//
// onto router. The route requires authentication; the service
// layer enforces site_admin or same-org org_admin (defense in
// depth — the same gates as the standalone SA admin route).
//
// Route choice: the path keeps `service-accounts` as the parent
// segment so an operator inspecting the route tree groups the
// bundled flow with the standalone /service-accounts admin
// surface rather than with the OAuth client admin surface.
func RegisterServiceAccountClientBundleRoutes(router gin.IRouter, deps ServiceAccountClientBundleHandlerDeps) {
	if deps.BundleService == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	g := router.Group("/api/v1/organizations/:id/service-accounts")
	g.Use(mw.RequireAuthenticated())

	// docgen:endpoint
	// docgen:surface=service-accounts
	// docgen:method=POST
	// docgen:path=/api/v1/organizations/:id/service-accounts/with-client
	// docgen:summary=Create a service account bundled with an OAuth client (one-shot issuance; the OAuth client_secret is returned ONCE).
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:notes=Authorisation is enforced at the handler layer (site_admin OR same-org membership). The cleartext client_secret appears in the response body exactly once.
	// docgen:status=201
	g.POST("/with-client", HandleCreateServiceAccountWithClient(deps))
}

// serviceAccountWithClientRequest is the request DTO.
type serviceAccountWithClientRequest struct {
	ServiceAccount serviceAccountWithClientSAInput     `json:"service_account"`
	Client         serviceAccountWithClientClientInput `json:"client"`
}

type serviceAccountWithClientSAInput struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Role        string     `json:"role"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

type serviceAccountWithClientClientInput struct {
	Name             string   `json:"name"`
	RedirectURIs     []string `json:"redirect_uris"`
	AllowedAudiences []string `json:"allowed_audiences"`
	Scope            string   `json:"scope"`
}

// serviceAccountWithClientResponse is the response DTO. Only the
// safe projections of the SA and the OAuth client land on the
// wire. The client_secret is included EXACTLY ONCE — on this
// response. List/get on either standalone admin surface will
// never echo it again.
type serviceAccountWithClientResponse struct {
	ServiceAccount any        `json:"service_account"`
	Client         safeClient `json:"client"`
	ClientSecret   string     `json:"client_secret,omitempty"`
}

// HandleCreateServiceAccountWithClient invokes the bundle service.
func HandleCreateServiceAccountWithClient(deps ServiceAccountClientBundleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, _ := mw.PrincipalFromContext(c)
		orgID, ok := parseSAOrgID(c)
		if !ok {
			return
		}
		var req serviceAccountWithClientRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		result, err := deps.BundleService.CreateServiceAccountWithClientForActor(
			c.Request.Context(), actor, orgID, service.BundleInput{
				SAName:           req.ServiceAccount.Name,
				SADescription:    req.ServiceAccount.Description,
				SARole:           domain.UserRole(req.ServiceAccount.Role),
				SAExpiresAt:      req.ServiceAccount.ExpiresAt,
				ClientName:       req.Client.Name,
				RedirectURIs:     req.Client.RedirectURIs,
				AllowedAudiences: req.Client.AllowedAudiences,
				Scope:            req.Client.Scope,
			},
		)
		if err != nil {
			respondBundleError(c, err)
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "service_account_client.created",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"service_account_id": result.ServiceAccount.ID.String(),
				"organization_id":    result.ServiceAccount.OrganizationID.String(),
				"client_uuid":        result.Client.ID.String(),
				"client_id":          result.Client.ClientID,
			},
		})
		c.JSON(http.StatusCreated, serviceAccountWithClientResponse{
			ServiceAccount: toSafeServiceAccount(result.ServiceAccount),
			Client:         toSafeClient(result.Client),
			ClientSecret:   result.ClientSecret,
		})
	}
}

func respondBundleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrBundleInvalidInput):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
	case errors.Is(err, service.ErrSAForbidden):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	case errors.Is(err, service.ErrSANotFound):
		// A cross-org reach is NOT FOUND, not a server fault. This switch had
		// no arm for it, so the model's 404 fell through to 500 — a refusal
		// reported as a bug in the server.
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case errors.Is(err, service.ErrSAInvalidInput),
		errors.Is(err, service.ErrSARoleInvalid),
		errors.Is(err, service.ErrSAExpiryInvalid),
		errors.Is(err, service.ErrBundleClientCreate),
		errors.Is(err, service.ErrServiceAccountUnbound),
		errors.Is(err, service.ErrServiceAccountInactive),
		errors.Is(err, service.ErrServiceAccountExpired),
		errors.Is(err, service.ErrServiceAccountOrgMismatch):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
