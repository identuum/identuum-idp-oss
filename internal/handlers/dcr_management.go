package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// DCRManagementHandlerDeps wires the RFC 7592 §2 client
// management surface that lives at /api/v1/oauth/register/:client_id.
//
// ClientService is required — every operation reads/writes a
// real OAuth client through the same service the /api/v1/clients
// admin surface uses (so validation + secret handling are
// identical on both paths).
//
// RegistrationAccessTokenService is required — without it the
// RFC 7592 surface would have no authentication primitive.
//
// Audit defaults to audit.NoopService{}.
//
// Authority composition: the handler accepts either:
//   - a valid `Authorization: Bearer <registration_access_token>`
//     bound to :client_id, OR
//   - a site_admin principal (fallback so an operator can
//     manage DCR-created clients if the RAT was lost).
//
// Anonymous + non-site-admin principals without a valid RAT are
// rejected with 401 invalid_token.
//
// The surface is also DELIBERATELY restricted to DCR-created
// clients: clients minted via POST /api/v1/clients (the
// site_admin admin surface) carry no RAT row and so are not
// addressable through /api/v1/oauth/register/:client_id. The
// existing /api/v1/clients/:id route remains the canonical
// admin management surface for those.
type DCRManagementHandlerDeps struct {
	ClientService *service.ClientService
	RATService    *service.DCRRegistrationAccessTokenService
	Audit         audit.Service
	// OrgFeatureLookup is the per-request, per-organization gate
	// consulted AFTER the target client is resolved (its
	// OrganizationID is the gate key). When the lookup says false
	// the handler returns the standard `feature not enabled` 403
	// envelope before the management read/update/delete runs.
	// site_admin AND a valid Bearer RAT both cannot bypass.
	//
	// nil defaults to "open for every org" so existing test
	// fixtures continue to reach the management surface.
	OrgFeatureLookup OrgFeatureLookup

	// StartupReport receives a fatal fault if ClientService or RATService
	// is not wired — instead of panicking (P-018). Nil-safe.
	StartupReport *lifecycle.StartupReport
}

// RegisterDCRManagementRoutes mounts the RFC 7592 management
// routes. Panics on missing required deps.
func RegisterDCRManagementRoutes(router gin.IRouter, deps DCRManagementHandlerDeps) {
	if deps.ClientService == nil || deps.RATService == nil {
		// P-018: the RFC 7592 DCR client-management surface is on the
		// client-credential path — security-critical. FATAL. Record the
		// fault (naming the missing dependency) and mount a uniform
		// service-missing fallback instead of panicking.
		missing := "ClientService"
		if deps.ClientService != nil {
			missing = "RATService"
		}
		deps.StartupReport.Fatal(
			"dcr-management-routes",
			"DCR client-management surface unavailable: "+missing+" not wired",
		)
		g := router.Group("/api/v1/oauth/register")
		g.GET("/:client_id", serviceMissingFallback("dcr-management"))
		g.PUT("/:client_id", serviceMissingFallback("dcr-management"))
		g.DELETE("/:client_id", serviceMissingFallback("dcr-management"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	g := router.Group("/api/v1/oauth/register")
	// Per-org gate is mounted INSIDE the dispatcher — see
	// dcrManagementAuthorize where the target client is resolved
	// first and its OrganizationID is then checked against
	// deps.OrgFeatureLookup.

	// NOTE: deliberately NO docgen:endpoint annotations here. The RFC
	// 7592 management surface is NOT mounted by the OSS router (the
	// runtime never constructs DCRRegistrationAccessTokenService) —
	// advanced DCR is Enterprise/CE-only. Annotating it would
	// re-advertise endpoints that 404 in OSS (integrity-audit F6/C1).
	// A CE composition that mounts this Register function documents
	// the routes on its own catalog.
	g.GET("/:client_id", HandleDCRManagementGet(deps))
	g.PUT("/:client_id", HandleDCRManagementPut(deps))
	g.DELETE("/:client_id", HandleDCRManagementDelete(deps))
}

// dcrPutRequest is the safe-mutable subset of RFC 7591 §2
// client metadata accepted on PUT. Fields outside this set are
// silently ignored (RFC 7592 §2.2 allows the server to leave
// unspecified fields untouched and to reject metadata-shape
// violations with `invalid_client_metadata`).
//
// Notable omissions from this struct: `organization_id`,
// `is_public`, `service_account_id`, `client_id_issued_at`,
// `client_secret`, `client_secret_expires_at`. All four are
// either immutable (id / org binding) or one-shot (secret).
type dcrPutRequest struct {
	ClientName                        *string  `json:"client_name,omitempty"`
	RedirectURIs                      []string `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs            []string `json:"post_logout_redirect_uris,omitempty"`
	ResponseTypes                     []string `json:"response_types,omitempty"`
	GrantTypes                        []string `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod           *string  `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg       *string  `json:"token_endpoint_auth_signing_alg,omitempty"`
	Scope                             *string  `json:"scope,omitempty"`
	JWKSUri                           *string  `json:"jwks_uri,omitempty"`
	JWKS                              *string  `json:"jwks,omitempty"`
	FrontchannelLogoutURI             *string  `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired *bool    `json:"frontchannel_logout_session_required,omitempty"`
	BackchannelLogoutURI              *string  `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired  *bool    `json:"backchannel_logout_session_required,omitempty"`
}

// HandleDCRManagementGet returns the safe dcrResponse projection
// of a DCR-registered client. The client_secret field is
// DELIBERATELY omitted — RFC 7592 §3 calls for the original
// client_secret to be available via the registration_client_uri
// only at registration time. A management read does NOT re-emit
// the secret.
func HandleDCRManagementGet(deps DCRManagementHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		client, status := dcrManagementAuthorize(c, deps)
		if status != 0 {
			return // response already written
		}
		// Build the RFC 7591 §3.2.1-shaped projection. Secret is
		// omitted on management reads.
		resp := buildDCRReadResponse(client)
		c.JSON(http.StatusOK, resp)
		_ = deps.Audit.Record(ctx, audit.Event{
			Action:    "dcr.client_read",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"client_id":   client.ClientID,
				"client_uuid": client.ID.String(),
			},
		})
	}
}

// HandleDCRManagementPut updates the safe-mutable subset of a
// DCR-registered client's metadata. The request is validated
// against the same closed allow-lists the DCR registration
// handler enforces — grant_types/response_types/auth_method
// outside the set are rejected with invalid_client_metadata.
//
// Whole-field replacement semantics:
//   - String pointer set to "" → leave unchanged (ClientService
//     UpdateClient treats "" as no-op).
//   - String pointer set to a non-empty value → replace.
//   - Slice non-nil → replace (including empty-slice clearing).
//   - Bool pointer → replace.
//
// Fields not present in the request are NOT touched.
func HandleDCRManagementPut(deps DCRManagementHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		client, status := dcrManagementAuthorize(c, deps)
		if status != 0 {
			return
		}
		var req dcrPutRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "request body is not valid JSON")
			return
		}
		// Validate the request-supplied allow-list values BEFORE
		// dispatching to the service so the metadata error is
		// distinguishable from a service-layer rejection.
		if _, ok := normalizeAllowedSet(req.GrantTypes, dcrAllowedGrantTypes); !ok {
			respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "grant_types contains an unsupported value")
			return
		}
		responseTypes, ok := normalizeAllowedSet(req.ResponseTypes, dcrAllowedResponseTypes)
		if !ok {
			respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "response_types contains an unsupported value")
			return
		}
		if req.TokenEndpointAuthMethod != nil && *req.TokenEndpointAuthMethod != "" {
			if _, ok := dcrAllowedAuthMethods[*req.TokenEndpointAuthMethod]; !ok {
				respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "token_endpoint_auth_method is not supported")
				return
			}
		}
		if len(req.RedirectURIs) > 0 {
			if err := domain.ValidateRedirectURIs(req.RedirectURIs); err != nil {
				respondDCRError(c, http.StatusBadRequest, "invalid_redirect_uri", "one or more redirect_uris are not acceptable")
				return
			}
		}
		opts := service.UpdateClientOptions{}
		// THE-SILENT-DROP: the wire already distinguished absent from
		// supplied-blank here, and this flattened it into a plain string so
		// the service could not — a supplied "" became indistinguishable
		// from "not supplied". Pass the pointer through instead.
		opts.Name = req.ClientName
		if req.RedirectURIs != nil {
			opts.RedirectURIs = req.RedirectURIs
		}
		if req.PostLogoutRedirectURIs != nil {
			opts.PostLogoutRedirectURIs = req.PostLogoutRedirectURIs
		}
		// THE-SILENT-DROP-2: the wire already distinguished absent from
		// supplied-blank for all five, and each was flattened into a plain
		// string so the service could not. Pass the pointers through.
		opts.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
		opts.TokenEndpointAuthSigningAlg = req.TokenEndpointAuthSigningAlg
		opts.Scope = req.Scope
		opts.JWKSUri = req.JWKSUri
		opts.JWKS = req.JWKS
		if req.FrontchannelLogoutURI != nil {
			opts.FrontchannelLogoutURI = req.FrontchannelLogoutURI
		}
		if req.FrontchannelLogoutSessionRequired != nil {
			opts.FrontchannelLogoutSessionRequired = req.FrontchannelLogoutSessionRequired
		}
		if req.BackchannelLogoutURI != nil {
			opts.BackchannelLogoutURI = req.BackchannelLogoutURI
		}
		if req.BackchannelLogoutSessionRequired != nil {
			opts.BackchannelLogoutSessionRequired = req.BackchannelLogoutSessionRequired
		}
		updated, err := deps.ClientService.UpdateClient(ctx, client.ID, opts)
		if err != nil {
			respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "client metadata rejected by the registration service")
			return
		}
		resp := buildDCRReadResponse(updated)
		// Echo the requested response_types back to keep the wire
		// shape symmetrical with POST /register; the underlying
		// domain.Client does not model response_types directly so
		// the field is request-derived, not row-derived.
		if len(responseTypes) > 0 {
			resp.ResponseTypes = responseTypes
		}
		c.JSON(http.StatusOK, resp)
		_ = deps.Audit.Record(ctx, audit.Event{
			Action:    "dcr.client_updated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"client_id":   updated.ClientID,
				"client_uuid": updated.ID.String(),
			},
		})
	}
}

// HandleDCRManagementDelete removes the DCR-registered client.
// The RAT row is removed implicitly via the ON DELETE CASCADE
// on the dcr_client_registration_tokens.client_id foreign key.
// Returns 204 No Content on success.
func HandleDCRManagementDelete(deps DCRManagementHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		client, status := dcrManagementAuthorize(c, deps)
		if status != 0 {
			return
		}
		// Defense-in-depth: revoke the RAT first so that a
		// failure mid-delete cannot leave a dangling RAT row.
		// The Postgres ON DELETE CASCADE handles the happy path
		// alongside ClientService.DeleteClient; the explicit
		// Revoke is a no-op in production but ensures the
		// in-memory test repo does not leak orphans.
		if err := deps.RATService.Revoke(ctx, client.ID); err != nil {
			respondDCRError(c, http.StatusInternalServerError, "server_error", "deletion failed")
			return
		}
		if err := deps.ClientService.DeleteClient(ctx, client.ID, nil); err != nil {
			respondDCRError(c, http.StatusNotFound, "invalid_client", "client not found")
			return
		}
		c.Status(http.StatusNoContent)
		_ = deps.Audit.Record(ctx, audit.Event{
			Action:    "dcr.client_deleted",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"client_id":   client.ClientID,
				"client_uuid": client.ID.String(),
			},
		})
	}
}

// dcrManagementAuthorize is the shared authorization entry point
// for GET/PUT/DELETE under /api/v1/oauth/register/:client_id.
// Returns (client, 0) on success; on any failure it writes the
// response envelope and returns (nil, non-zero status).
//
// Behavioural matrix:
//   - missing/invalid path UUID                       → 404 invalid_client
//   - client not found in oauth_clients               → 404 invalid_client
//   - client has no RAT row AND principal is not site_admin → 404 invalid_client
//     (no enumeration: site-admin-managed clients are
//     invisible to the RFC 7592 surface)
//   - Bearer presented + RAT match                    → ok
//   - no Bearer + site_admin principal                → ok (operator escape hatch)
//   - Bearer presented + RAT mismatch                 → 401 invalid_token
//   - no Bearer + no site_admin principal             → 401 invalid_token
func dcrManagementAuthorize(c *gin.Context, deps DCRManagementHandlerDeps) (*domain.Client, int) {
	ctx := c.Request.Context()
	clientUUID, err := uuid.Parse(c.Param("client_id"))
	if err != nil {
		respondDCRError(c, http.StatusNotFound, "invalid_client", "client not found")
		return nil, http.StatusNotFound
	}
	client, err := deps.ClientService.GetClient(ctx, clientUUID)
	if err != nil || client == nil {
		respondDCRError(c, http.StatusNotFound, "invalid_client", "client not found")
		return nil, http.StatusNotFound
	}

	rawBearer := extractBearerToken(c.Request.Header.Get("Authorization"))

	// Resolve site_admin presence (used as fallback and as the
	// enumeration-suppression rule when the client has no RAT
	// row).
	var siteAdmin bool
	if p, ok := mw.PrincipalFromContext(c); ok && p.IsSiteAdmin() {
		siteAdmin = true
	}

	managed, err := deps.RATService.IsManaged(ctx, clientUUID)
	if err != nil {
		respondDCRError(c, http.StatusInternalServerError, "server_error", "lookup failed")
		return nil, http.StatusInternalServerError
	}
	if !managed {
		// Site-admin-created clients are NOT addressable through
		// RFC 7592. A site_admin can still see them via
		// /api/v1/clients/:id. Return a 404 from this surface
		// (rather than 403) so the existence of non-DCR clients
		// is not enumerated through this endpoint.
		respondDCRError(c, http.StatusNotFound, "invalid_client", "client not found")
		return nil, http.StatusNotFound
	}

	// Bearer path: RAT must match.
	authorized := false
	if rawBearer != "" {
		if err := deps.RATService.Authenticate(ctx, clientUUID, rawBearer); err != nil {
			if errors.Is(err, service.ErrRATInvalid) {
				respondDCRError(c, http.StatusUnauthorized, "invalid_token", "invalid registration access token")
				return nil, http.StatusUnauthorized
			}
			respondDCRError(c, http.StatusInternalServerError, "server_error", "authentication failed")
			return nil, http.StatusInternalServerError
		}
		authorized = true
	} else if siteAdmin {
		// No bearer → site_admin escape hatch only.
		authorized = true
	}
	if !authorized {
		respondDCRError(c, http.StatusUnauthorized, "invalid_token", "authentication required")
		return nil, http.StatusUnauthorized
	}

	// Per-org gate runs AFTER both the client resolution and
	// the bearer/site_admin authorization. The gate key is the
	// resolved client's OrganizationID. An org-less DCR client
	// (e.g. site-admin-created infra-level row) is treated as
	// "no per-org gate" and proceeds; otherwise the lookup is
	// fail-closed against the org row.
	gateOrgID := uuid.Nil
	if client.OrganizationID != nil {
		gateOrgID = *client.OrganizationID
	}
	if gateOrgID != uuid.Nil {
		allowed, ok := resolveOrgFeature(c, deps.OrgFeatureLookup, gateOrgID, service.OrgFeatureDynamicClientRegistration)
		if !ok {
			return nil, http.StatusServiceUnavailable
		}
		if !allowed {
			abortOrgFeatureDisabled(c, service.OrgFeatureDynamicClientRegistration)
			return nil, http.StatusForbidden
		}
	}
	return client, 0
}

// buildDCRReadResponse projects a *domain.Client onto the
// RFC 7591 §3.2.1-shaped wire response WITHOUT a client_secret.
// The handler is responsible for adding client_secret separately
// in the registration response (one-shot at /register time only).
func buildDCRReadResponse(client *domain.Client) dcrResponse {
	return dcrResponse{
		ClientID:                          client.ClientID,
		ClientIDIssuedAt:                  client.CreatedAt.UTC().Unix(),
		ClientSecretExpiresAt:             0,
		ClientName:                        client.Name,
		RedirectURIs:                      client.RedirectURIs,
		PostLogoutRedirectURIs:            client.PostLogoutRedirectURIs,
		TokenEndpointAuthMethod:           strings.TrimSpace(client.TokenEndpointAuthMethod),
		TokenEndpointAuthSigningAlg:       strings.TrimSpace(client.TokenEndpointAuthSigningAlg),
		Scope:                             client.Scope,
		JWKSUri:                           client.JWKSUri,
		FrontchannelLogoutURI:             client.FrontchannelLogoutURI,
		FrontchannelLogoutSessionRequired: client.FrontchannelLogoutSessionRequired,
		BackchannelLogoutURI:              client.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  client.BackchannelLogoutSessionRequired,
	}
}
