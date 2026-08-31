package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// ClientsHandlerDeps wires the OAuth-client admin group.
//
// Either ClientService (preferred) OR ClientRepo must be supplied:
//
//   - ClientService present  → mutations are LIVE; bypasses the
//     raw repo.
//   - ClientService nil but ClientRepo present → read endpoints
//     LIVE; mutations 501 (legacy mode
//     from the prior slice).
type ClientsHandlerDeps struct {
	ClientService *service.ClientService
	ClientRepo    repository.ClientRepository
	Audit         audit.Service

	// StartupReport, when wired, receives a fatal fault if neither
	// ClientService nor ClientRepo is supplied — instead of panicking
	// (P-018 NOT-SERVING-JUST-ALERTING). Nil is safe: the fault is then
	// a no-op and the service-missing fallback is still mounted.
	StartupReport *lifecycle.StartupReport
}

// RegisterClientsRoutes wires /api/v1/clients onto router. Mounts
// mw.RequireSiteAdmin so unauthenticated requests 401 and
// non-site-admin requests 403, matching the keys-extraction pattern.
//
// Implemented:
//
//	GET    /api/v1/clients
//	GET    /api/v1/clients/:id
//
// Deferred to a follow-up slice (501):
//
//	POST   /api/v1/clients                       — secret-generation flow
//	PUT    /api/v1/clients/:id                   — service-layer validation
//	DELETE /api/v1/clients/:id                   — tenant guard
//	POST   /api/v1/clients/:id/secret/regenerate — one-shot secret display
//
// The OSS module has no ClientService yet; reproducing
// secret-generation + redirect-URI validation + service-layer guards
// in the handler would risk subtle drift from the monolith. The read
// surface (List + Get) is safe to land today against the OSS
// ClientRepository directly.
func RegisterClientsRoutes(router gin.IRouter, deps ClientsHandlerDeps) {
	if deps.ClientService == nil && deps.ClientRepo == nil {
		// P-018 NOT-SERVING-JUST-ALERTING: a clients surface with neither
		// a service nor a repo cannot answer any request. Previously this
		// panicked at construction time, which would kill the process.
		// Instead, record a fatal startup fault (the runtime then enters
		// NOT-SERVING and the health probe surfaces the gap) and mount a
		// uniform service-missing fallback so the process stays alive and
		// no route silently mishandles a request. The fault is secret-free.
		deps.StartupReport.Fatal(
			"clients-routes",
			"clients management surface unavailable: neither ClientService nor ClientRepo is wired",
		)
		g := router.Group("/api/v1/clients")
		g.Use(mw.RequireSiteAdmin())
		g.GET("", clientsServiceMissing("list"))
		g.GET("/:id", clientsServiceMissing("get"))
		g.POST("", clientsServiceMissing("create"))
		g.PUT("/:id", clientsServiceMissing("update"))
		g.DELETE("/:id", clientsServiceMissing("delete"))
		g.POST("/:id/secret/regenerate", clientsServiceMissing("secret rotation"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	// ORG-ADMIN-ONLY (THE-CLIENTS-GUARD, 2026-08-30): the clients surface is
	// the org's own org_admin's, and ONLY its own. org_admin carries the
	// role-derived clients:* session scopes and every handler pins it to its
	// organization via orgAdminClientScope (list/delete filter by the actor's
	// org; get/update/rotate refuse a client outside it; create force-pins
	// organization_id). site_admin — which the shared scope guard still admits,
	// and which used to see EVERY tenant's clients unscoped — is refused with a
	// clean 403 by requireClientOrgAdmin at each handler
	// (AdminPermissionsModel.md: site_admin cannot manage tenant resources).
	// org_user is refused at the scope guard.
	g := router.Group("/api/v1/clients")

	read := g.Group("")
	read.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeClientsRead))

	// docgen:endpoint
	// docgen:surface=clients
	// docgen:method=GET
	// docgen:path=/api/v1/clients
	// docgen:summary=List OAuth clients (safe projection — never exposes client_secret_hash or inline JWKS material).
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:notes=org_admin actor additionally requires the clients:read scope and sees ONLY its own organization's clients.
	// docgen:response=oss.handlers.safeClient
	read.GET("", HandleListClients(deps))

	// docgen:endpoint
	// docgen:surface=clients
	// docgen:method=GET
	// docgen:path=/api/v1/clients/:id
	// docgen:summary=Show a single OAuth client by client_id (safe projection).
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:notes=org_admin actor additionally requires the clients:read scope; a client outside the actor's org is 404 (indistinguishable from absent).
	// docgen:response=oss.handlers.safeClient
	read.GET("/:id", HandleGetClient(deps))

	if deps.ClientService != nil {
		createG := g.Group("")
		createG.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeClientsCreate))
		updateG := g.Group("")
		updateG.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeClientsUpdate))
		deleteG := g.Group("")
		deleteG.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeClientsDelete))
		// docgen:endpoint
		// docgen:surface=clients
		// docgen:method=POST
		// docgen:path=/api/v1/clients
		// docgen:summary=Create an OAuth client (client_secret returned ONCE in the response body; never stored in cleartext server-side).
		// docgen:tier=oss
		// docgen:auth=org_admin
		// docgen:response=oss.handlers.safeClient
		// docgen:notes=The cleartext client_secret appears in the response body exactly once. The server retains only the hash.
		// docgen:status=201
		createG.POST("", HandleCreateClient(deps))

		// docgen:endpoint
		// docgen:surface=clients
		// docgen:method=PUT
		// docgen:path=/api/v1/clients/:id
		// docgen:summary=Update OAuth client metadata (does not rotate the client_secret).
		// docgen:tier=oss
		// docgen:auth=org_admin
		// docgen:response=oss.handlers.safeClient
		updateG.PUT("/:id", HandleUpdateClient(deps))

		// docgen:endpoint
		// docgen:surface=clients
		// docgen:method=DELETE
		// docgen:path=/api/v1/clients/:id
		// docgen:summary=Delete an OAuth client.
		// docgen:tier=oss
		// docgen:auth=org_admin
		deleteG.DELETE("/:id", HandleDeleteClient(deps))

		// docgen:endpoint
		// docgen:surface=clients
		// docgen:method=POST
		// docgen:path=/api/v1/clients/:id/secret/regenerate
		// docgen:summary=Rotate an OAuth client's client_secret (new secret returned ONCE; old secret invalidated immediately).
		// docgen:tier=oss
		// docgen:auth=org_admin
		// docgen:response=oss.handlers.safeClient
		// docgen:notes=The new cleartext secret appears in the response body exactly once.
		updateG.POST("/:id/secret/regenerate", HandleRegenerateClientSecret(deps))
	} else {
		g.POST("", clientsServiceMissing("create"))
		g.PUT("/:id", clientsServiceMissing("update"))
		g.DELETE("/:id", clientsServiceMissing("delete"))
		g.POST("/:id/secret/regenerate", clientsServiceMissing("secret rotation"))
	}
}

// requireClientInActorOrg fetches the client and refuses (404, written to c)
// when an org-bound actor does not own it. Returns false when the request has
// been answered. 404 rather than 403 so an org_admin cannot probe which client
// UUIDs exist in other tenants — same shape as the read path.
func requireClientInActorOrg(c *gin.Context, deps ClientsHandlerDeps, id uuid.UUID) bool {
	orgFilter := orgAdminClientScope(c)
	if orgFilter == nil {
		return true
	}
	client, err := deps.ClientService.GetClient(c.Request.Context(), id)
	if err != nil || client == nil ||
		client.OrganizationID == nil || *client.OrganizationID != *orgFilter {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return false
	}
	return true
}

// orgAdminClientScope returns the organization filter the acting principal is
// confined to on the clients surface: nil for site_admin (sees everything),
// the actor's own org for an org_admin. The guards upstream have already
// refused everyone else. This is the ORG-BOUND half of ORG-ADMIN-SCOPES —
// the scope claim says WHAT an org_admin may do; this says WHERE.
// requireClientOrgAdmin gates every clients handler on the ONLY role
// AdminPermissionsModel.md lets manage a tenant's OAuth clients: the org's own
// org_admin. THE-CLIENTS-GUARD (2026-08-30) measured site_admin listing EVERY
// org's clients (unscoped) — a separation-of-duties over-reach by the
// installation superuser, which the model forbids ("site_admin ... cannot
// manage the resources ... belong to that organizations"). org_user is already
// refused at the scope guard; this refuses site_admin with a clean 403.
// Mirrors apiResourceActor. The shared route guard still admits site_admin (it
// is used by other families too — their own slices); the enforcement lives
// here, and orgAdminClientScope below is fail-closed as a second line.
func requireClientOrgAdmin(c *gin.Context) bool {
	actor, _ := mw.PrincipalFromContext(c)
	if actor == nil || !actor.IsOrgAdminOnly() {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return false
	}
	return true
}

func orgAdminClientScope(c *gin.Context) *uuid.UUID {
	actor, _ := mw.PrincipalFromContext(c)
	if actor == nil {
		// FAIL CLOSED. Returning nil here would mean "no filter" — an absent
		// principal would see every tenant's clients. The route guards refuse
		// an unauthenticated caller long before this, so nothing reaches it
		// today; that is exactly why the weaker branch could sit here
		// unnoticed. Confine instead: uuid.Nil matches no organization.
		var none uuid.UUID
		return &none
	}
	// THE-CLIENTS-GUARD: site_admin no longer gets an unscoped nil filter (it
	// let the superuser read/manage EVERY tenant's clients, model-forbidden).
	// It is refused outright by requireClientOrgAdmin at each handler; if a
	// future handler forgets that gate, scoping site_admin to its own System
	// org still matches no tenant client — no nil, no cross-tenant read.
	org := actor.OrganizationID
	return &org
}

// safeClient is the JSON projection emitted to /api/v1/clients
// responses. It deliberately omits ClientSecretHash, JWKS (inline
// material is sensitive even if technically public), and any other
// field whose accidental display might leak deployment intent.
type safeClient struct {
	ID       uuid.UUID `json:"id"`
	ClientID string    `json:"client_id"`
	Name     string    `json:"name"`
	// is_public is operator-load-bearing: it is the ONLY honest way to tell a
	// public client from a confidential one on a read (secret presence is NOT
	// a proxy — private_key_jwt clients are secretless AND confidential).
	// Deliberately no omitempty: false must be VISIBLE, not absent (v0.3.1
	// gap A).
	IsPublic                          bool       `json:"is_public"`
	OrganizationID                    *uuid.UUID `json:"organization_id,omitempty"`
	ServiceAccountID                  *uuid.UUID `json:"service_account_id,omitempty"`
	Scope                             string     `json:"scope"`
	RedirectURIs                      []string   `json:"redirect_uris"`
	PostLogoutRedirectURIs            []string   `json:"post_logout_redirect_uris,omitempty"`
	AllowedAudiences                  []string   `json:"allowed_audiences,omitempty"`
	TokenEndpointAuthMethod           string     `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg       string     `json:"token_endpoint_auth_signing_alg,omitempty"`
	JWKSURI                           string     `json:"jwks_uri,omitempty"`
	FrontchannelLogoutURI             string     `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired bool       `json:"frontchannel_logout_session_required,omitempty"`
	BackchannelLogoutURI              string     `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired  bool       `json:"backchannel_logout_session_required,omitempty"`
	CreatedAt                         time.Time  `json:"created_at"`
	UpdatedAt                         time.Time  `json:"updated_at"`
}

func toSafeClient(c *domain.Client) safeClient {
	if c == nil {
		return safeClient{}
	}
	return safeClient{
		ID:                                c.ID,
		ClientID:                          c.ClientID,
		Name:                              c.Name,
		IsPublic:                          c.IsPublic,
		OrganizationID:                    c.OrganizationID,
		ServiceAccountID:                  c.ServiceAccountID,
		Scope:                             c.Scope,
		RedirectURIs:                      c.RedirectURIs,
		PostLogoutRedirectURIs:            c.PostLogoutRedirectURIs,
		AllowedAudiences:                  c.AllowedAudiences,
		TokenEndpointAuthMethod:           c.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg:       c.TokenEndpointAuthSigningAlg,
		JWKSURI:                           c.JWKSUri,
		FrontchannelLogoutURI:             c.FrontchannelLogoutURI,
		FrontchannelLogoutSessionRequired: c.FrontchannelLogoutSessionRequired,
		BackchannelLogoutURI:              c.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  c.BackchannelLogoutSessionRequired,
		CreatedAt:                         c.CreatedAt,
		UpdatedAt:                         c.UpdatedAt,
	}
}

// HandleListClients returns a paginated list of OAuth clients with
// safe DTO projection (no secret hash, no inline JWKS).
func HandleListClients(deps ClientsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireClientOrgAdmin(c) {
			return
		}
		pageSize := parsePositiveQuery(c, "page_size", 50, 200)
		page := parsePositiveQuery(c, "page", 1, 1<<16)
		pagination := repository.Pagination{
			Page:     page,
			PageSize: pageSize,
			Offset:   (page - 1) * pageSize,
		}
		var (
			clients []*domain.Client
			total   int
			err     error
		)
		orgFilter := orgAdminClientScope(c)
		if deps.ClientService != nil {
			clients, total, err = deps.ClientService.ListClients(c.Request.Context(), pagination, orgFilter)
		} else {
			clients, total, err = deps.ClientRepo.List(c.Request.Context(), pagination, orgFilter)
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		out := make([]safeClient, 0, len(clients))
		for _, cl := range clients {
			out = append(out, toSafeClient(cl))
		}
		c.JSON(http.StatusOK, gin.H{
			"clients":   out,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		})
	}
}

// HandleGetClient returns a single client by its UUID id.
func HandleGetClient(deps ClientsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireClientOrgAdmin(c) {
			return
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var client *domain.Client
		if deps.ClientService != nil {
			client, err = deps.ClientService.GetClient(c.Request.Context(), id)
		} else {
			client, err = deps.ClientRepo.GetClientByID(c.Request.Context(), id)
		}
		if err != nil || client == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		// A client outside the actor's org is 404, not 403: an org_admin must
		// not be able to probe which client UUIDs exist in other tenants.
		if orgFilter := orgAdminClientScope(c); orgFilter != nil &&
			(client.OrganizationID == nil || *client.OrganizationID != *orgFilter) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, toSafeClient(client))
	}
}

// HandleCreateClient creates a new OAuth client. Returns the safe
// projection PLUS the plaintext client_secret for confidential
// clients — emitted EXACTLY ONCE in this response.
func HandleCreateClient(deps ClientsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireClientOrgAdmin(c) {
			return
		}
		var req struct {
			Name                              string     `json:"name"`
			OrganizationID                    *uuid.UUID `json:"organization_id,omitempty"`
			ServiceAccountID                  *uuid.UUID `json:"service_account_id,omitempty"`
			RedirectURIs                      []string   `json:"redirect_uris"`
			PostLogoutRedirectURIs            []string   `json:"post_logout_redirect_uris,omitempty"`
			AllowedAudiences                  []string   `json:"allowed_audiences,omitempty"`
			Scope                             string     `json:"scope"`
			IsPublic                          bool       `json:"is_public"`
			TokenEndpointAuthMethod           string     `json:"token_endpoint_auth_method,omitempty"`
			TokenEndpointAuthSigningAlg       string     `json:"token_endpoint_auth_signing_alg,omitempty"`
			JWKSUri                           string     `json:"jwks_uri,omitempty"`
			JWKS                              string     `json:"jwks,omitempty"`
			FrontchannelLogoutURI             string     `json:"frontchannel_logout_uri,omitempty"`
			FrontchannelLogoutSessionRequired bool       `json:"frontchannel_logout_session_required,omitempty"`
			BackchannelLogoutURI              string     `json:"backchannel_logout_uri,omitempty"`
			BackchannelLogoutSessionRequired  bool       `json:"backchannel_logout_session_required,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		// ORG-BOUND: an org_admin creates clients in ITS org only. An explicit
		// organization_id naming a different org is refused loudly (403), and
		// an omitted one is pinned — the same shape CreateUserForActor uses.
		if orgFilter := orgAdminClientScope(c); orgFilter != nil {
			if req.OrganizationID != nil && *req.OrganizationID != *orgFilter {
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			req.OrganizationID = orgFilter
		}
		client, plaintext, err := deps.ClientService.RegisterClient(c.Request.Context(), service.RegisterClientOptions{
			Name:                              req.Name,
			OrganizationID:                    req.OrganizationID,
			ServiceAccountID:                  req.ServiceAccountID,
			RedirectURIs:                      req.RedirectURIs,
			PostLogoutRedirectURIs:            req.PostLogoutRedirectURIs,
			AllowedAudiences:                  req.AllowedAudiences,
			Scope:                             req.Scope,
			IsPublic:                          req.IsPublic,
			TokenEndpointAuthMethod:           req.TokenEndpointAuthMethod,
			TokenEndpointAuthSigningAlg:       req.TokenEndpointAuthSigningAlg,
			JWKSUri:                           req.JWKSUri,
			JWKS:                              req.JWKS,
			FrontchannelLogoutURI:             req.FrontchannelLogoutURI,
			FrontchannelLogoutSessionRequired: req.FrontchannelLogoutSessionRequired,
			BackchannelLogoutURI:              req.BackchannelLogoutURI,
			BackchannelLogoutSessionRequired:  req.BackchannelLogoutSessionRequired,
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		safe := toSafeClient(client)
		out := gin.H{"client": safe}
		if plaintext != "" {
			// One-time display only — never persisted in raw form.
			out["client_secret"] = plaintext
		}
		c.JSON(http.StatusCreated, out)
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:         "client.created",
			Outcome:        "success",
			SubjectID:      client.ID,
			SubjectType:    "oauth_client",
			OrganizationID: orgOf(client.OrganizationID),
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata: map[string]any{
				"client_id": client.ClientID,
				"name":      client.Name,
				"is_public": client.IsPublic,
			},
		}))
	}
}

// HandleUpdateClient mutates a client by UUID id.
func HandleUpdateClient(deps ClientsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireClientOrgAdmin(c) {
			return
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var req struct {
			// THE-SILENT-DROP: Name is a pointer so absent and supplied-blank
			// differ; {"name":""} was answering 200 with an unchanged row.
			Name                              *string    `json:"name,omitempty"`
			Scope                             *string    `json:"scope,omitempty"`
			ServiceAccountID                  *uuid.UUID `json:"service_account_id,omitempty"`
			RedirectURIs                      []string   `json:"redirect_uris,omitempty"`
			PostLogoutRedirectURIs            []string   `json:"post_logout_redirect_uris,omitempty"`
			AllowedAudiences                  []string   `json:"allowed_audiences,omitempty"`
			TokenEndpointAuthMethod           *string    `json:"token_endpoint_auth_method,omitempty"`
			TokenEndpointAuthSigningAlg       *string    `json:"token_endpoint_auth_signing_alg,omitempty"`
			JWKSUri                           *string    `json:"jwks_uri,omitempty"`
			JWKS                              *string    `json:"jwks,omitempty"`
			FrontchannelLogoutURI             *string    `json:"frontchannel_logout_uri,omitempty"`
			FrontchannelLogoutSessionRequired *bool      `json:"frontchannel_logout_session_required,omitempty"`
			BackchannelLogoutURI              *string    `json:"backchannel_logout_uri,omitempty"`
			BackchannelLogoutSessionRequired  *bool      `json:"backchannel_logout_session_required,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if !requireClientInActorOrg(c, deps, id) {
			return
		}
		// Prior binding state, read ONLY when this update touches the SA
		// binding — it decides whether the SA-subject link/unlink audit event
		// below fires and which SA an unbind names.
		var priorSA *uuid.UUID
		if req.ServiceAccountID != nil {
			if prior, perr := deps.ClientService.GetClient(c.Request.Context(), id); perr == nil && prior != nil {
				priorSA = prior.ServiceAccountID
			}
		}
		client, err := deps.ClientService.UpdateClient(c.Request.Context(), id, service.UpdateClientOptions{
			Name:                              req.Name,
			Scope:                             req.Scope,
			ServiceAccountID:                  req.ServiceAccountID,
			RedirectURIs:                      req.RedirectURIs,
			PostLogoutRedirectURIs:            req.PostLogoutRedirectURIs,
			AllowedAudiences:                  req.AllowedAudiences,
			TokenEndpointAuthMethod:           req.TokenEndpointAuthMethod,
			TokenEndpointAuthSigningAlg:       req.TokenEndpointAuthSigningAlg,
			JWKSUri:                           req.JWKSUri,
			JWKS:                              req.JWKS,
			FrontchannelLogoutURI:             req.FrontchannelLogoutURI,
			FrontchannelLogoutSessionRequired: req.FrontchannelLogoutSessionRequired,
			BackchannelLogoutURI:              req.BackchannelLogoutURI,
			BackchannelLogoutSessionRequired:  req.BackchannelLogoutSessionRequired,
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		c.JSON(http.StatusOK, toSafeClient(client))
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:         "client.updated",
			Outcome:        "success",
			SubjectID:      client.ID,
			SubjectType:    "oauth_client",
			OrganizationID: orgOf(client.OrganizationID),
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata:       map[string]any{"client_id": client.ClientID},
		}))
		// A binding change is ALSO a service-account lifecycle event — the
		// SA's own audit trail (subject_id = the SA) must show which client
		// it was bound to or released from (v0.3.2 Order A).
		if req.ServiceAccountID != nil {
			if *req.ServiceAccountID != uuid.Nil {
				_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
					Action:         "service_account.linked_oauth_client",
					Outcome:        "success",
					SubjectID:      *req.ServiceAccountID,
					SubjectType:    "service_account",
					OrganizationID: orgOf(client.OrganizationID),
					IPAddress:      c.ClientIP(),
					UserAgent:      c.Request.UserAgent(),
					Metadata: map[string]any{
						"oauth_client_id":   client.ID.String(),
						"oauth_client_name": client.Name,
					},
				}))
			} else if priorSA != nil && *priorSA != uuid.Nil {
				_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
					Action:         "service_account.unlinked_oauth_client",
					Outcome:        "success",
					SubjectID:      *priorSA,
					SubjectType:    "service_account",
					OrganizationID: orgOf(client.OrganizationID),
					IPAddress:      c.ClientIP(),
					UserAgent:      c.Request.UserAgent(),
					Metadata: map[string]any{
						"oauth_client_id":   client.ID.String(),
						"oauth_client_name": client.Name,
					},
				}))
			}
		}
	}
}

// HandleDeleteClient removes a client by id.
func HandleDeleteClient(deps ClientsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireClientOrgAdmin(c) {
			return
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		// The row is gone after the delete — read its tenant org first so the
		// audit event lands in the right trail (best-effort; a failed read
		// leaves the org empty rather than blocking the delete).
		var clientOrg uuid.UUID
		if prior, perr := deps.ClientService.GetClient(c.Request.Context(), id); perr == nil && prior != nil {
			clientOrg = orgOf(prior.OrganizationID)
		}
		if err := deps.ClientService.DeleteClient(c.Request.Context(), id, orgAdminClientScope(c)); err != nil {
			// Delete is documented-idempotent (P3-14: a miss or a
			// tombstone is a 0-row Exec, no error) — errors here are
			// infrastructure faults, so the old 404 was a pure lie
			// (THE-SIXTEEN-ELSES).
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"deleted": id})
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:         "client.deleted",
			Outcome:        "success",
			SubjectID:      id,
			SubjectType:    "oauth_client",
			OrganizationID: clientOrg,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata:       map[string]any{"client_uuid": id},
		}))
	}
}

// HandleRegenerateClientSecret rotates the client secret. Returns
// the new plaintext EXACTLY ONCE in the response.
func HandleRegenerateClientSecret(deps ClientsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireClientOrgAdmin(c) {
			return
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		if !requireClientInActorOrg(c, deps, id) {
			return
		}
		client, plaintext, err := deps.ClientService.RegenerateClientSecret(c.Request.Context(), id)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"client":        toSafeClient(client),
			"client_secret": plaintext,
		})
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:  "client.secret_rotated",
			Outcome: "success",
			// Resource subject (v0.3.1 gap B) + tenant org + actor identity
			// (v0.3.2 gap B2): subject-keyed audit reads only surface this
			// rotation if the event names its resource, and the tenant clamp
			// only shows it to the org_admin if the event carries the
			// resource's organization.
			SubjectID:      client.ID,
			SubjectType:    "oauth_client",
			OrganizationID: orgOf(client.OrganizationID),
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata:       map[string]any{"client_id": client.ClientID},
		}))
	}
}

// clientsServiceMissing returns a 501 explaining that the named
// operation requires a ClientService relocation that has not landed
// yet. Operators see a clean signal instead of fake success.
func clientsServiceMissing(op string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{
			"error":     "not implemented",
			"operation": op,
			"reason":    "ClientService not yet relocated into the OSS module; " + op + " requires service-layer validation (redirect-URI checks, secret generation, tenant guards).",
		})
	}
}

func parsePositiveQuery(c *gin.Context, key string, defaultVal, maxVal int) int {
	raw := c.Query(key)
	if raw == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return defaultVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}
