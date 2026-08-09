package handlers

import (
	"errors"
	"net/http"
	"strings"
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

// DCRInitialAccessTokenHandlerDeps wires the site_admin-facing
// IAT management surface used to mint, list, and revoke the
// initial access tokens consumed by /api/v1/oauth/register.
//
// IATService is required. Audit defaults to audit.NoopService{}.
//
// IAT issue / list / revoke are deliberately NOT per-org-gated:
// they are admin housekeeping for the DCR subsystem itself
// (so an operator can still mint an IAT for an org that wants to
// turn DCR on). The per-org DCR availability gate lives on the
// DCR consume surface (POST /api/v1/oauth/register) and the
// RFC 7592 management surface — those are the user-facing
// endpoints whose availability the org admin actually controls.
type DCRInitialAccessTokenHandlerDeps struct {
	IATService *service.DCRInitialAccessTokenService
	Audit      audit.Service

	// StartupReport receives a fatal fault if IATService is not wired —
	// instead of panicking (P-018). Nil-safe.
	StartupReport *lifecycle.StartupReport
}

// RegisterDCRInitialAccessTokenRoutes mounts the IAT management
// routes under /api/v1/dcr/initial-access-tokens. The group is
// site_admin-only — no IAT may be minted, listed, or revoked by
// anyone other than a site_admin actor.
//
// Panics if IATService is nil — wiring this surface without a
// backing service is a bootstrap bug.
func RegisterDCRInitialAccessTokenRoutes(router gin.IRouter, deps DCRInitialAccessTokenHandlerDeps) {
	if deps.IATService == nil {
		// P-018: DCR initial-access-tokens gate client-credential
		// issuance — security-critical. FATAL. Record the fault and mount
		// a uniform service-missing fallback instead of panicking.
		deps.StartupReport.Fatal(
			"dcr-initial-access-tokens-routes",
			"DCR initial-access-token surface unavailable: IATService not wired",
		)
		g := router.Group("/api/v1/dcr/initial-access-tokens")
		g.POST("", serviceMissingFallback("dcr-initial-access-tokens"))
		g.GET("", serviceMissingFallback("dcr-initial-access-tokens"))
		g.POST("/:id/revoke", serviceMissingFallback("dcr-initial-access-tokens"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	g := router.Group("/api/v1/dcr/initial-access-tokens")
	g.Use(mw.RequireSiteAdmin())

	// NOTE: deliberately NO docgen:endpoint annotations here. This
	// surface is NOT mounted by the OSS router (the runtime never
	// constructs DCRInitialAccessTokenService) — advanced DCR is
	// Enterprise/CE-only. Annotating it would re-advertise endpoints
	// that 404 in OSS (integrity-audit F6/C1). A CE composition that
	// mounts this Register function documents the routes on its own
	// catalog.
	g.POST("", HandleDCRIATIssue(deps))
	g.GET("", HandleDCRIATList(deps))
	g.POST("/:id/revoke", HandleDCRIATRevoke(deps))
}

// dcrIATIssueRequest is the input shape for POST
// /api/v1/dcr/initial-access-tokens.
type dcrIATIssueRequest struct {
	OrganizationID                  *uuid.UUID `json:"organization_id,omitempty"`
	AllowedGrantTypes               []string   `json:"allowed_grant_types,omitempty"`
	AllowedTokenEndpointAuthMethods []string   `json:"allowed_token_endpoint_auth_methods,omitempty"`
	// TTLSeconds is the requested lifetime. 0 → service default
	// (24h). Clamped to the service's [1m, 30d] range.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// MaxUses caps the number of successful DCR registrations
	// the IAT can authorise. 0 → service default (1). Use -1 to
	// request unlimited (stored as 0 in the row).
	MaxUses     int    `json:"max_uses,omitempty"`
	Description string `json:"description,omitempty"`
}

// safeIAT is the JSON projection of a DynamicRegistrationToken
// row. token_hash is DELIBERATELY absent — the repository
// guarantees scrubbing on read; this struct guarantees the wire
// shape never carries it.
type safeIAT struct {
	ID                              uuid.UUID  `json:"id"`
	OrganizationID                  *uuid.UUID `json:"organization_id,omitempty"`
	AllowedGrantTypes               []string   `json:"allowed_grant_types,omitempty"`
	AllowedTokenEndpointAuthMethods []string   `json:"allowed_token_endpoint_auth_methods,omitempty"`
	ExpiresAt                       time.Time  `json:"expires_at"`
	MaxUses                         int        `json:"max_uses"`
	UsesCount                       int        `json:"uses_count"`
	RevokedAt                       *time.Time `json:"revoked_at,omitempty"`
	CreatedByUserID                 *uuid.UUID `json:"created_by_user_id,omitempty"`
	Description                     string     `json:"description,omitempty"`
	CreatedAt                       time.Time  `json:"created_at"`
	UpdatedAt                       time.Time  `json:"updated_at"`
}

// dcrIATIssueResponse is the wire shape for POST
// /api/v1/dcr/initial-access-tokens. The raw IAT appears in the
// `initial_access_token` field EXACTLY ONCE — operators must
// persist it before the response is dropped.
type dcrIATIssueResponse struct {
	InitialAccessToken string  `json:"initial_access_token"`
	Token              safeIAT `json:"token"`
}

// dcrIATListResponse is the wire shape for GET
// /api/v1/dcr/initial-access-tokens.
type dcrIATListResponse struct {
	Tokens []safeIAT `json:"tokens"`
	Total  int       `json:"total"`
}

// HandleDCRIATIssue mints a new IAT and returns the raw token
// once. The handler resolves the site_admin actor's user id and
// stamps it on the IAT row for audit correlation.
func HandleDCRIATIssue(deps DCRInitialAccessTokenHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req dcrIATIssueRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		// IAT-imposed allow-lists must be subsets of the
		// handler-wide DCR allow-lists; otherwise the IAT could
		// never be consumed (the DCR handler rejects out-of-set
		// values regardless of the IAT). Fail at issue time so
		// the operator sees the mismatch immediately.
		if !isSubsetAllowed(req.AllowedGrantTypes, dcrAllowedGrantTypes) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "allowed_grant_types contains an unsupported value"})
			return
		}
		if !isSubsetAllowed(req.AllowedTokenEndpointAuthMethods, dcrAllowedAuthMethods) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "allowed_token_endpoint_auth_methods contains an unsupported value"})
			return
		}
		actorUserID := siteAdminActorUserID(c)
		ttl := time.Duration(req.TTLSeconds) * time.Second

		issued, err := deps.IATService.Issue(c.Request.Context(), service.IssueOptions{
			OrganizationID:                  req.OrganizationID,
			AllowedGrantTypes:               req.AllowedGrantTypes,
			AllowedTokenEndpointAuthMethods: req.AllowedTokenEndpointAuthMethods,
			TTL:                             ttl,
			MaxUses:                         req.MaxUses,
			CreatedByUserID:                 actorUserID,
			Description:                     req.Description,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusCreated, dcrIATIssueResponse{
			InitialAccessToken: issued.RawIAT,
			Token:              toSafeIAT(issued.Token),
		})
		// Audit metadata MUST NOT carry the raw IAT.
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "dcr.iat_issued",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"iat_id":      issued.TokenID.String(),
				"max_uses":    issued.Token.MaxUses,
				"expires_at":  issued.Token.ExpiresAt.UTC().Format(time.RFC3339),
				"org_scoped":  issued.Token.OrganizationID != nil,
				"description": issued.Token.Description,
			},
		})
	}
}

// HandleDCRIATList returns the IAT collection in newest-first
// order. The safe-projection guarantee is enforced by the
// repository and re-asserted by the safeIAT struct.
func HandleDCRIATList(deps DCRInitialAccessTokenHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := deps.IATService.List(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		out := make([]safeIAT, 0, len(rows))
		for _, r := range rows {
			out = append(out, toSafeIAT(r))
		}
		c.JSON(http.StatusOK, dcrIATListResponse{Tokens: out, Total: len(out)})
	}
}

// HandleDCRIATRevoke marks an IAT revoked. Idempotent on a
// revoked row; 404 when no row matches the supplied id.
func HandleDCRIATRevoke(deps DCRInitialAccessTokenHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		if err := deps.IATService.Revoke(c.Request.Context(), id); err != nil {
			if errors.Is(err, repository.ErrDynamicRegistrationTokenNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": id.String(), "status": "revoked"})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "dcr.iat_revoked",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"iat_id": id.String(),
			},
		})
	}
}

// toSafeIAT projects a *domain.DynamicRegistrationToken onto the
// safe wire shape. token_hash is NEVER carried (the repository
// scrubs it; this struct re-asserts the omission at the wire).
func toSafeIAT(t *domain.DynamicRegistrationToken) safeIAT {
	if t == nil {
		return safeIAT{}
	}
	return safeIAT{
		ID:                              t.ID,
		OrganizationID:                  t.OrganizationID,
		AllowedGrantTypes:               t.AllowedGrantTypes,
		AllowedTokenEndpointAuthMethods: t.AllowedTokenEndpointAuthMethods,
		ExpiresAt:                       t.ExpiresAt,
		MaxUses:                         t.MaxUses,
		UsesCount:                       t.UsesCount,
		RevokedAt:                       t.RevokedAt,
		CreatedByUserID:                 t.CreatedByUserID,
		Description:                     t.Description,
		CreatedAt:                       t.CreatedAt,
		UpdatedAt:                       t.UpdatedAt,
	}
}

// siteAdminActorUserID returns the principal's UserID when
// present, or nil. The IAT row's CreatedByUserID field is
// optional so a non-cookie site_admin path (e.g. a bootstrap
// token) does not block IAT issuance.
func siteAdminActorUserID(c *gin.Context) *uuid.UUID {
	p, ok := mw.PrincipalFromContext(c)
	if !ok || p.UserID == uuid.Nil {
		return nil
	}
	id := p.UserID
	return &id
}

// isSubsetAllowed reports whether every entry in `in` (after
// whitespace trim) appears in `allowed`. Used to validate the
// IAT-imposed allow-lists at issue time.
func isSubsetAllowed(in []string, allowed map[string]struct{}) bool {
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := allowed[v]; !ok {
			return false
		}
	}
	return true
}
