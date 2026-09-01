package handlers

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// DCRHandlerDeps wires the RFC 7591 Dynamic Client Registration
// endpoint. ClientService is required — DCR creates a real OAuth
// client via the same service path the /api/v1/clients admin
// surface uses (so identical secret-hashing, redirect-URI
// validation, and SA-binding rules apply).
//
// IATService is optional. When wired, the registration endpoint
// accepts an `Authorization: Bearer <iat>` header in lieu of a
// site_admin principal: the bearer IAT is consumed atomically
// and its constraints (org scope, allowed grant types, allowed
// token endpoint auth methods) are enforced before the client
// is registered. When IATService is nil, only site_admin can
// reach the endpoint (the previous-slice behaviour).
//
// Audit defaults to audit.NoopService{}.
//
// Wire format: RFC 7591 §3.2 (Client Registration Endpoint).
// Response: RFC 7591 §3.2.1 (Client Information Response).
// Error envelope: RFC 7591 §3.2.2 (invalid_client_metadata, etc.).
type DCRHandlerDeps struct {
	ClientService *service.ClientService
	IATService    *service.DCRInitialAccessTokenService
	// OrgFeatureLookup is the per-request, per-organization gate
	// consulted AFTER the relevant org id is resolved (from the
	// IAT, from the request body, or from the registered
	// client). When the lookup says false the handler returns the
	// standard `feature not enabled` 403 envelope before the
	// RegisterClient / Mint side-effect runs. site_admin AND a
	// valid Bearer IAT both cannot bypass — the per-org gate is
	// consulted unconditionally.
	//
	// nil defaults to "open for every org" so test fixtures and
	// downstream consumers that have not wired the lookup keep
	// the foundation reachable. Production wiring binds this to
	// service.OrganizationProtocolSettingsService.IsFeatureEnabledForOrg.
	OrgFeatureLookup OrgFeatureLookup
	// RATService, when non-nil, mints a per-client RFC 7592
	// registration access token (RAT) at /register time and the
	// raw RAT is returned in the registration response under
	// `registration_access_token`. The response also gains a
	// `registration_client_uri` field pointing at the management
	// endpoint. When nil, neither field is emitted and the
	// management surface is not addressable for the registered
	// client.
	RATService *service.DCRRegistrationAccessTokenService
	// RegistrationBaseURL is the absolute base used to compose
	// `registration_client_uri` in the registration response. Empty
	// disables the field but does NOT disable RAT minting; the
	// caller can still authenticate to /api/v1/oauth/register/:client_id
	// directly. Typical production wiring: the deployment's issuer
	// URL.
	RegistrationBaseURL string
	Audit               audit.Service

	// StartupReport receives a fatal fault if ClientService is not wired —
	// instead of panicking (P-018). Nil-safe.
	StartupReport *lifecycle.StartupReport
}

// RegisterDCRRoutes mounts the RFC 7591 Dynamic Client Registration
// endpoint onto router. Mount path is /api/v1/oauth/register.
//
// Authority composition:
//
//   - The route does NOT mount mw.RequireSiteAdmin at the group
//     level. The handler itself dispatches: bearer IAT path → IAT
//     gate; otherwise → site_admin gate.
//   - When IATService is nil, the bearer path is silently absent
//     and only site_admin reaches RegisterClient.
//
// Panics if ClientService is nil — wiring this endpoint without a
// backing service is a bootstrap bug.
func RegisterDCRRoutes(router gin.IRouter, deps DCRHandlerDeps) {
	if deps.ClientService == nil {
		// P-018: DCR mints OAuth clients (credential issuance) —
		// security-critical. FATAL. Record the fault + mount a
		// service-missing fallback instead of panicking.
		deps.StartupReport.Fatal(
			"dcr-routes",
			"DCR registration surface unavailable: ClientService not wired",
		)
		g := router.Group("/api/v1/oauth")
		g.POST("/register", serviceMissingFallback("dcr"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	g := router.Group("/api/v1/oauth")
	// Per-org gate is mounted INSIDE the handler — see
	// HandleDCRRegister where the relevant org id is resolved
	// from the IAT or the request body and then checked against
	// deps.OrgFeatureLookup.

	// docgen:endpoint
	// docgen:surface=oauth
	// docgen:method=POST
	// docgen:path=/api/v1/oauth/register
	// docgen:summary=RFC 7591 Dynamic Client Registration. site_admin or a valid Authorization Bearer IAT may register. client_secret returned ONCE.
	// docgen:tier=oss
	// docgen:auth=site_admin|bearer
	// docgen:feature_gate=dynamic_client_registration
	// docgen:response=oss.handlers.dcrResponse
	// docgen:notes=Bearer auth is only honoured when an IAT service is wired. The cleartext client_secret appears in the response body exactly once. When a RAT service is wired, the response also carries registration_access_token + registration_client_uri (RFC 7592) — both one-shot.
	// docgen:status=201
	g.POST("/register", HandleDCRRegister(deps))
}

// dcrRequest is the RFC 7591 §2 client-metadata wire shape accepted
// by /api/v1/oauth/register. See the prior-slice doc
// IDP_MISSING_FEATURES_DCR_SCIM_FOUNDATION.md §3.2 for the field
// list. The same struct + same allow-lists are used on both the
// site_admin and bearer-IAT paths.
type dcrRequest struct {
	ClientName                        string   `json:"client_name"`
	RedirectURIs                      []string `json:"redirect_uris"`
	PostLogoutRedirectURIs            []string `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes                        []string `json:"grant_types,omitempty"`
	ResponseTypes                     []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod           string   `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg       string   `json:"token_endpoint_auth_signing_alg,omitempty"`
	Scope                             string   `json:"scope,omitempty"`
	JWKSUri                           string   `json:"jwks_uri,omitempty"`
	JWKS                              string   `json:"jwks,omitempty"`
	FrontchannelLogoutURI             string   `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired bool     `json:"frontchannel_logout_session_required,omitempty"`
	BackchannelLogoutURI              string   `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired  bool     `json:"backchannel_logout_session_required,omitempty"`
	SoftwareStatement                 string   `json:"software_statement,omitempty"`
	// OIDC DCR §2. "" = issuer default (EdDSA). RS256 is honored only as
	// this explicit registration — testing-only (THE-PKCE-DECISION).
	IDTokenSignedResponseAlg string `json:"id_token_signed_response_alg,omitempty"`
}

// dcrResponse is the RFC 7591 §3.2.1 client-information response.
//
// `registration_access_token` and `registration_client_uri` are
// the RFC 7592 §3 management credentials returned at registration
// time. Both fields are present only on POST /register responses
// when a RAT service is wired; GET / PUT / DELETE under
// /api/v1/oauth/register/:client_id deliberately OMIT both fields
// (the RAT is one-shot at issuance — re-emitting it on every
// management call would defeat the rotate/revoke story).
type dcrResponse struct {
	ClientID                          string   `json:"client_id"`
	ClientSecret                      string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt                  int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt             int64    `json:"client_secret_expires_at,omitempty"`
	RegistrationAccessToken           string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI             string   `json:"registration_client_uri,omitempty"`
	ClientName                        string   `json:"client_name,omitempty"`
	RedirectURIs                      []string `json:"redirect_uris"`
	PostLogoutRedirectURIs            []string `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes                        []string `json:"grant_types,omitempty"`
	ResponseTypes                     []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod           string   `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg       string   `json:"token_endpoint_auth_signing_alg,omitempty"`
	Scope                             string   `json:"scope,omitempty"`
	JWKSUri                           string   `json:"jwks_uri,omitempty"`
	FrontchannelLogoutURI             string   `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired bool     `json:"frontchannel_logout_session_required,omitempty"`
	BackchannelLogoutURI              string   `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired  bool     `json:"backchannel_logout_session_required,omitempty"`
	IDTokenSignedResponseAlg          string   `json:"id_token_signed_response_alg,omitempty"`
}

// dcrAllowedGrantTypes is the handler-wide allowlist. An IAT may
// impose a tighter (subset) allowlist; it may NOT expand beyond
// this set.
var dcrAllowedGrantTypes = map[string]struct{}{
	"authorization_code": {},
	"refresh_token":      {},
	"client_credentials": {},
}

// dcrAllowedResponseTypes is the handler-wide allowlist.
var dcrAllowedResponseTypes = map[string]struct{}{
	"code": {},
}

// dcrAllowedAuthMethods is the handler-wide allowlist for
// token_endpoint_auth_method.
var dcrAllowedAuthMethods = map[string]struct{}{
	"client_secret_basic": {},
	"client_secret_post":  {},
	"none":                {},
	"private_key_jwt":     {},
}

// HandleDCRRegister implements POST /api/v1/oauth/register.
//
// Authority dispatch:
//
//  1. Extract Authorization: Bearer <iat> if present. When present
//     AND IATService is wired, attempt to Consume the bearer; on
//     success the call proceeds in "IAT mode" and the IAT-derived
//     policy is enforced against the request metadata. On failure
//     (or when the IAT service is not wired), the bearer is treated
//     as never-presented and the site_admin gate runs.
//  2. If no bearer auth, require a site_admin principal. A non-
//     site-admin (org_admin / org_user) or absent principal is
//     rejected with the standard auth-layer 401/403.
//
// Secret handling: the cleartext client_secret appears in the
// response body EXACTLY ONCE for confidential clients. It is
// never written to audit metadata, never logged, never echoed in
// any error path, and never returned for public clients.
func HandleDCRRegister(deps DCRHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req dcrRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "request body is not valid JSON")
			return
		}

		// Authority dispatch.
		var (
			iatPolicy *service.ConsumePolicy
			authMode  string
		)
		rawBearer := extractBearerToken(c.Request.Header.Get("Authorization"))
		if rawBearer != "" && deps.IATService != nil {
			policy, err := deps.IATService.Consume(c.Request.Context(), rawBearer)
			if err != nil {
				if errors.Is(err, service.ErrIATInvalid) {
					respondDCRError(c, http.StatusUnauthorized, "invalid_token", "the supplied initial access token is not valid")
					return
				}
				respondDCRError(c, http.StatusInternalServerError, "server_error", "registration failed")
				return
			}
			iatPolicy = policy
			authMode = "iat"
		} else {
			// site_admin path.
			p, ok := mw.PrincipalFromContext(c)
			if !ok {
				respondDCRError(c, http.StatusUnauthorized, "invalid_token", "authentication required")
				return
			}
			if !p.IsSiteAdmin() {
				respondDCRError(c, http.StatusForbidden, "access_denied", "site_admin role required")
				return
			}
			authMode = "site_admin"
		}

		// Metadata validation (same on both auth paths).
		if strings.TrimSpace(req.ClientName) == "" {
			respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "client_name is required")
			return
		}
		if len(req.RedirectURIs) == 0 {
			respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris must contain at least one URI")
			return
		}
		if err := domain.ValidateRedirectURIs(req.RedirectURIs); err != nil {
			respondDCRError(c, http.StatusBadRequest, "invalid_redirect_uri", "one or more redirect_uris are not acceptable")
			return
		}
		if strings.TrimSpace(req.SoftwareStatement) != "" {
			respondDCRError(c, http.StatusBadRequest, "unapproved_software_statement", "software_statement is not supported by this foundation")
			return
		}

		grantTypes, ok := normalizeAllowedSet(req.GrantTypes, dcrAllowedGrantTypes)
		if !ok {
			respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "grant_types contains an unsupported value")
			return
		}
		responseTypes, ok := normalizeAllowedSet(req.ResponseTypes, dcrAllowedResponseTypes)
		if !ok {
			respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "response_types contains an unsupported value")
			return
		}
		if _, ok := dcrAllowedAuthMethods[req.TokenEndpointAuthMethod]; req.TokenEndpointAuthMethod != "" && !ok {
			respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "token_endpoint_auth_method is not supported")
			return
		}
		if req.IDTokenSignedResponseAlg != "" {
			if err := domain.ValidateClientIDTokenAlg(req.IDTokenSignedResponseAlg); err != nil {
				respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "id_token_signed_response_alg is not supported")
				return
			}
		}

		// IAT-imposed allowlist enforcement (in addition to the
		// handler-wide allowlists above).
		var orgIDForRegistration *uuid.UUID
		if iatPolicy != nil {
			if len(iatPolicy.AllowedGrantTypes) > 0 && !isSubset(grantTypes, iatPolicy.AllowedGrantTypes) {
				respondDCRError(c, http.StatusForbidden, "invalid_client_metadata", "requested grant_types are not permitted by this initial access token")
				return
			}
			if len(iatPolicy.AllowedTokenEndpointAuthMethods) > 0 {
				method := req.TokenEndpointAuthMethod
				if method == "" {
					// Treat absent as the default; the IAT must
					// have whitelisted the default explicitly for
					// the call to proceed.
					method = "client_secret_basic"
				}
				if !dcrSliceContains(iatPolicy.AllowedTokenEndpointAuthMethods, method) {
					respondDCRError(c, http.StatusForbidden, "invalid_client_metadata", "requested token_endpoint_auth_method is not permitted by this initial access token")
					return
				}
			}
			if iatPolicy.OrganizationID != nil {
				orgIDForRegistration = iatPolicy.OrganizationID
			}
		}

		// Per-org gate. Mounted AFTER the IAT consume + the
		// site_admin guard so the lookup has the correct org id
		// in hand (IAT-bound org takes precedence; site_admin
		// org-less DCR is treated as infra-level and allowed —
		// document that convention here for the next reader).
		// The lookup is fail-closed against the org's DB row:
		// neither site_admin nor a valid IAT can bypass.
		gateOrgID := uuid.Nil
		if orgIDForRegistration != nil {
			gateOrgID = *orgIDForRegistration
		}
		if gateOrgID != uuid.Nil {
			allowed, ok := resolveOrgFeature(c, deps.OrgFeatureLookup, gateOrgID, service.OrgFeatureDynamicClientRegistration)
			if !ok {
				return
			}
			if !allowed {
				abortOrgFeatureDisabled(c, service.OrgFeatureDynamicClientRegistration)
				return
			}
		}

		// isPublic per RFC 7591: token_endpoint_auth_method=none
		// → public client. Absent field defaults to confidential.
		isPublic := req.TokenEndpointAuthMethod == "none"

		client, plaintext, err := deps.ClientService.RegisterClient(c.Request.Context(), service.RegisterClientOptions{
			Name:                              req.ClientName,
			OrganizationID:                    orgIDForRegistration,
			RedirectURIs:                      req.RedirectURIs,
			PostLogoutRedirectURIs:            req.PostLogoutRedirectURIs,
			Scope:                             req.Scope,
			IsPublic:                          isPublic,
			TokenEndpointAuthMethod:           req.TokenEndpointAuthMethod,
			TokenEndpointAuthSigningAlg:       req.TokenEndpointAuthSigningAlg,
			JWKSUri:                           req.JWKSUri,
			JWKS:                              req.JWKS,
			FrontchannelLogoutURI:             req.FrontchannelLogoutURI,
			FrontchannelLogoutSessionRequired: req.FrontchannelLogoutSessionRequired,
			BackchannelLogoutURI:              req.BackchannelLogoutURI,
			BackchannelLogoutSessionRequired:  req.BackchannelLogoutSessionRequired,
			IDTokenSignedResponseAlg:          req.IDTokenSignedResponseAlg,
		})
		if err != nil {
			respondDCRError(c, http.StatusBadRequest, "invalid_client_metadata", "client metadata rejected by the registration service")
			return
		}

		// Mint the RFC 7592 registration access token (RAT) if the
		// RAT service is wired. Failure here would leave the client
		// registered but unmanageable — we treat that as a server
		// error and surface a 500 so the caller can retry; the
		// registered client remains, but the operator can clean up
		// via the site_admin /api/v1/clients/:id surface.
		var rawRAT, regClientURI string
		if deps.RATService != nil {
			minted, mintErr := deps.RATService.Mint(c.Request.Context(), client.ID)
			if mintErr != nil {
				respondDCRError(c, http.StatusInternalServerError, "server_error", "registration access token issuance failed")
				return
			}
			rawRAT = minted
			if deps.RegistrationBaseURL != "" {
				regClientURI = strings.TrimRight(deps.RegistrationBaseURL, "/") + "/api/v1/oauth/register/" + client.ID.String()
			}
		}

		resp := dcrResponse{
			ClientID:                          client.ClientID,
			ClientSecret:                      plaintext,
			ClientIDIssuedAt:                  client.CreatedAt.UTC().Unix(),
			ClientSecretExpiresAt:             0,
			RegistrationAccessToken:           rawRAT,
			RegistrationClientURI:             regClientURI,
			ClientName:                        client.Name,
			RedirectURIs:                      client.RedirectURIs,
			PostLogoutRedirectURIs:            client.PostLogoutRedirectURIs,
			GrantTypes:                        grantTypes,
			ResponseTypes:                     responseTypes,
			TokenEndpointAuthMethod:           client.TokenEndpointAuthMethod,
			TokenEndpointAuthSigningAlg:       client.TokenEndpointAuthSigningAlg,
			Scope:                             client.Scope,
			JWKSUri:                           client.JWKSUri,
			FrontchannelLogoutURI:             client.FrontchannelLogoutURI,
			FrontchannelLogoutSessionRequired: client.FrontchannelLogoutSessionRequired,
			BackchannelLogoutURI:              client.BackchannelLogoutURI,
			BackchannelLogoutSessionRequired:  client.BackchannelLogoutSessionRequired,
			IDTokenSignedResponseAlg:          client.IDTokenSignedResponseAlg,
		}
		c.JSON(http.StatusCreated, resp)

		auditMeta := map[string]any{
			"client_id":               client.ClientID,
			"client_name":             client.Name,
			"is_public":               isPublic,
			"grant_types_requested":   grantTypes,
			"response_types_request":  responseTypes,
			"redirect_uri_count":      len(client.RedirectURIs),
			"token_endpoint_auth":     client.TokenEndpointAuthMethod,
			"registration_started_at": time.Now().UTC().Format(time.RFC3339),
			"auth_mode":               authMode,
			"rat_issued":              rawRAT != "",
		}
		if iatPolicy != nil {
			// Capture the IAT id (NOT the raw token) for audit
			// correlation. The raw IAT MUST NEVER appear here.
			auditMeta["iat_id"] = iatPolicy.TokenID.String()
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "client.dcr_registered",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  auditMeta,
		})
	}
}

// extractBearerToken parses an `Authorization: Bearer <token>`
// header. Returns the raw token or "" when the header is absent
// or not Bearer-shaped. Whitespace-only payloads are treated as
// absent.
func extractBearerToken(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(parts[0]))
	if scheme != "bearer" {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// respondDCRError emits an RFC 7591 §3.2.2-shaped error envelope.
func respondDCRError(c *gin.Context, status int, code, desc string) {
	c.JSON(status, gin.H{
		"error":             code,
		"error_description": desc,
	})
}

// normalizeAllowedSet validates that every entry in `in` is a
// member of `allowed` and returns a sorted, de-duplicated copy.
func normalizeAllowedSet(in []string, allowed map[string]struct{}) ([]string, bool) {
	if len(in) == 0 {
		return nil, true
	}
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := allowed[v]; !ok {
			return nil, false
		}
		seen[v] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out, true
}

// isSubset reports whether every element of `want` appears in
// `have`. Used to enforce an IAT's grant_type allowlist against
// the requested grant_types.
func isSubset(want, have []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(have))
	for _, v := range have {
		set[v] = struct{}{}
	}
	for _, v := range want {
		if _, ok := set[v]; !ok {
			return false
		}
	}
	return true
}

// dcrSliceContains reports whether s appears in xs.
func dcrSliceContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
