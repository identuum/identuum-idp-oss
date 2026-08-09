package handlers

// organization_lookup.go — OSS implementation of the public
// organization-lookup route the identuum-ui login flow consumes:
//
//	GET /api/v1/auth/organization-lookup?domain=<host>
//	GET /api/v1/auth/organization-lookup?slug=<org-slug>
//
// The route is PUBLIC (unauthenticated) — it powers the
// pre-authentication email step of the UI. It returns a SAFE projection
// of an organization's wire-visible auth configuration, with NEVER any
// row-level secret (no IdP client secret, no internal_base_url, no
// signing key, no token state).
//
// Contract source: identuum-idp/internal/handlers/handler_organization_public.go
// (HandleOrganizationLookup). This is a behaviour-compatible port — the
// JSON shape mirrors monolith types/discovery.OrganizationPublicConfig
// (slug, name, domain, auth_policy, login_url, identity_providers) so
// the existing identuum-ui idp-client.orgLookup helper consumes either
// backend without diverging. We do NOT import monolith or CE code; the
// types are reproduced locally with the same JSON tags.
//
// Authority decision per
// identuum-idp/docs/open-core/IDP_MONOLITH_HANDLER_ALLOCATION_DECISION.md
// (Group 5): organization_public is OSS-owned Starter functionality.
//
// Safety posture:
//
//   - PUBLIC route: no bearer / cookie requirement.
//   - Lookup miss returns 404 with the same error sentinel as monolith
//     ("organization not found"). The UI helper at
//     identuum-ui/src/lib/idp-client.ts treats HTTP 404 as a successful
//     "no org config" signal and falls through to the PASSWORD step,
//     so the wire shape stays graceful.
//   - Inactive / soft-deleted orgs collapse to the same 404 — never
//     surface an "inactive" state in the public response.
//   - The IdP projection includes ONLY (id, type, name, login_url,
//     email_domains) — never the upstream issuer_url, client_id,
//     client_secret, attribute_mapping, or any other ProviderConfig
//     field. For an active type=oidc provider, login_url is the OSS
//     login-initiation route /api/v1/auth/idp/{id}/login — basic
//     single-provider upstream OIDC login (OSS as relying-party to one
//     generic OIDC provider) is SHIPPED OSS-core, end-to-end (config →
//     initiation → callback + strict validation → JIT + email_domains
//     gate → session + return-URL redirect). login_url is a same-origin
//     relative path derived only from the provider ID; it carries no
//     provider internals. Per-org managed/multi-IdP federation + LDAP/AD
//     remain CE (allocation doc Group 6) and have no OSS login surface,
//     so their login_url stays empty.
//   - The response carries no token, no cookie, no signing key
//     material. Nothing in the handler logs the response body.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OrganizationLookupOrgSource is the narrow seam the lookup handler
// consumes from the organization repository. *PgxOrganizationRepository
// (and any other repository.OrganizationRepository) satisfies it. Defined
// locally so tests can stub only the three lookup methods without
// satisfying the full ~30-method CRUD interface.
type OrganizationLookupOrgSource interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*domain.Organization, error)
	GetByDomain(ctx context.Context, domain string) (*domain.Organization, error)
}

// OrganizationLookupVerifiedDomainSource is the narrow seam for the
// verified-domain global index. Optional — when nil the handler falls
// back to OrganizationLookupOrgSource.GetByDomain.
type OrganizationLookupVerifiedDomainSource interface {
	GetVerifiedOrganizationDomainByDomain(ctx context.Context, domainName string) (*domain.OrganizationDomain, error)
}

// OrganizationLookupIDPSource is the narrow seam for listing active
// IdPs of a given organization. Optional — when nil the handler returns
// an empty identity_providers list.
type OrganizationLookupIDPSource interface {
	ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*domain.IdentityProvider, error)
}

// OrganizationLookupHandlerDeps wires the public organization-lookup
// route. OrganizationRepo is REQUIRED. OrganizationDomainRepo is
// OPTIONAL: when present the handler tries the verified-domain global
// index first (richer monolith parity); when absent it falls back to
// the organizations.domain column alone. IdentityProviderRepo is
// OPTIONAL: when present the handler enumerates active IdPs and
// projects them; when absent the response carries an empty
// identity_providers list (the OSS-only deployment posture).
type OrganizationLookupHandlerDeps struct {
	OrganizationRepo       OrganizationLookupOrgSource
	OrganizationDomainRepo OrganizationLookupVerifiedDomainSource
	IdentityProviderRepo   OrganizationLookupIDPSource
	Audit                  audit.Service
	// HideIdentityProviderEmailDomains, when true, OMITS email_domains from
	// this PUBLIC projection (operator hardening: the org's federated email
	// domains are no longer disclosed on the unauthenticated lookup). Default
	// false ⇒ email_domains is exposed exactly as before. id/type/name/
	// login_url are ALWAYS returned, so SSO login is unaffected (the login
	// page falls back to a manual provider picker). This gates ONLY the public
	// lookup — the authenticated org-admin identity-provider API still returns
	// email_domains regardless.
	HideIdentityProviderEmailDomains bool
}

// organizationLookupResponse mirrors monolith
// types.OrganizationPublicConfig by JSON tags only. We do NOT import
// the monolith types package — identuum-idp-oss must not have any
// runtime dependency on identuum-idp. Defining the type locally keeps
// the OSS module self-contained AND keeps the wire contract pinned.
type organizationLookupResponse struct {
	Name              string                   `json:"name"`
	Slug              string                   `json:"slug"`
	Domain            string                   `json:"domain"`
	AuthPolicy        string                   `json:"auth_policy"`
	LoginURL          string                   `json:"login_url"`
	IdentityProviders []publicIdentityProvider `json:"identity_providers"`
}

// publicIdentityProvider is the safe-to-publish IdP projection (no
// secrets, no internal URLs). Mirrors monolith types.PublicIDPInfo by
// JSON tags only.
type publicIdentityProvider struct {
	ID           uuid.UUID `json:"id"`
	Type         string    `json:"type"`
	Name         string    `json:"name"`
	LoginURL     string    `json:"login_url"`
	EmailDomains []string  `json:"email_domains,omitempty"`
}

// RegisterOrganizationLookupRoute mounts the public
// GET /api/v1/auth/organization-lookup route onto router. Registration
// is conditional on OrganizationRepo being non-nil — the same
// fail-closed posture every other OSS handler family uses.
func RegisterOrganizationLookupRoute(router gin.IRouter, deps OrganizationLookupHandlerDeps) {
	if deps.OrganizationRepo == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	// docgen:endpoint
	// docgen:surface=auth
	// docgen:method=GET
	// docgen:path=/api/v1/auth/organization-lookup
	// docgen:summary=Public organization-lookup. Returns a safe projection of the organization's wire-visible auth configuration (slug, name, domain, auth_policy, login_url, identity_providers) for the pre-authentication UI email step. 404 on unknown / inactive / soft-deleted organizations. Never carries IdP secrets, internal URLs, or signing-key material.
	// docgen:tier=oss
	// docgen:auth=public
	// docgen:notes=Accepts either ?domain=<host> or ?slug=<org-slug>. Tries the verified-domain global index first when OrganizationDomainRepo is wired; falls back to the organizations.domain column. IdentityProvider projection includes only (id, type, name, login_url, email_domains); for an active oidc provider login_url is the OSS login-initiation route /api/v1/auth/idp/{id}/login (same-origin relative path, no provider internals). Empty list when no IdPs are configured.
	router.GET("/api/v1/auth/organization-lookup", HandleOrganizationLookup(deps))
}

// HandleOrganizationLookup is the gin handler. Behaviour-compatible
// with the monolith's HandleOrganizationLookup wire contract:
//
//   - 400 {"error":"invalid_request"} when neither ?domain= nor ?slug=
//     is supplied (or both are empty after trim).
//   - 404 {"error":"organization_not_found"} when no organization
//     matches OR the matched org is inactive / soft-deleted.
//   - 200 + organizationLookupResponse on success.
//
// No path other than the success path logs the response body. All
// projection happens in pure code from the persisted row; no secret,
// no internal URL, no token material is ever read into the response.
func HandleOrganizationLookup(deps OrganizationLookupHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		domainParam := strings.ToLower(strings.TrimSpace(c.Query("domain")))
		slugParam := strings.ToLower(strings.TrimSpace(c.Query("slug")))
		if domainParam == "" && slugParam == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		ctx := c.Request.Context()
		var org *domain.Organization
		var err error
		switch {
		case slugParam != "":
			org, err = deps.OrganizationRepo.GetBySlug(ctx, slugParam)
		default:
			// Domain path: prefer the verified-domain global index
			// when wired (matches monolith's PreferredVerifiedDomain
			// lookup); fall back to the legacy organizations.domain
			// column when not wired or when no verified row exists.
			if deps.OrganizationDomainRepo != nil {
				if row, vdErr := deps.OrganizationDomainRepo.GetVerifiedOrganizationDomainByDomain(ctx, domainParam); vdErr == nil && row != nil {
					org, err = deps.OrganizationRepo.GetByID(ctx, row.OrganizationID)
				} else {
					org, err = deps.OrganizationRepo.GetByDomain(ctx, domainParam)
				}
			} else {
				org, err = deps.OrganizationRepo.GetByDomain(ctx, domainParam)
			}
		}

		// Lookup failures + inactive / soft-deleted collapse to 404 so
		// the public surface does not enumerate which orgs exist in
		// any state other than "active".
		if err != nil {
			if errors.Is(err, domain.ErrOrganizationNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "organization_not_found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		if org == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "organization_not_found"})
			return
		}
		if !org.Active || org.DeletedAt != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "organization_not_found"})
			return
		}

		idps := projectActiveIdentityProviders(ctx, deps.IdentityProviderRepo, org.ID, deps.HideIdentityProviderEmailDomains)

		c.JSON(http.StatusOK, organizationLookupResponse{
			Name:       org.Name,
			Slug:       org.OrgSlug,
			Domain:     org.Domain,
			AuthPolicy: org.AuthPolicy,
			// Org-level login affordance: the (single, per-org) active OIDC
			// provider's OSS login-initiation route, or "" when none. OSS is
			// one-OIDC-provider-per-org, so the first projected LoginURL is
			// the org's. Managed/multi-IdP federation + LDAP/AD stay CE.
			LoginURL:          firstLoginURL(idps),
			IdentityProviders: idps,
		})
	}
}

// projectActiveIdentityProviders enumerates the active IdPs for an
// organization and projects them through publicIdentityProvider. Returns
// a non-nil empty slice when:
//
//   - the IdentityProviderRepo is not wired (OSS-only deployment);
//   - the lookup itself errors (treated as "no IdPs configured" — we
//     do NOT leak repo errors on a PUBLIC route);
//   - no IdP rows are Active=true for this organization.
//
// We return a non-nil empty slice so the JSON serialises as
// `"identity_providers": []` rather than `null` — preserves the wire
// contract identuum-ui's idp-client expects (Array<PublicIDPInfo>).
//
// LoginURL is populated for each active type=oidc provider with the OSS
// login-initiation route /api/v1/auth/idp/{id}/login (SHIPPED: basic
// single-provider upstream OIDC login is OSS-core — config → initiation →
// callback → JIT+gate → session, all end-to-end). It is a same-origin
// relative path derived purely from the provider ID + the fixed route —
// NO provider internals (client_id, client_secret, issuer/discovery URL,
// attribute mapping) are ever read into it. Non-OIDC transports
// (per-org managed/multi-IdP federation + LDAP/AD) remain CE and have no
// OSS login surface, so their LoginURL stays empty. The UI's idp-client
// treats empty LoginURL as "no SSO redirect possible" and falls through
// to the PASSWORD step.
//
// hideEmailDomains (operator hardening flag) OMITS email_domains from every
// projected IdP when true; id/type/name/login_url are still returned, so SSO
// login is unaffected. Default false ⇒ email_domains is exposed as before.
func projectActiveIdentityProviders(ctx context.Context, repo OrganizationLookupIDPSource, orgID uuid.UUID, hideEmailDomains bool) []publicIdentityProvider {
	out := make([]publicIdentityProvider, 0)
	if repo == nil {
		return out
	}
	rows, err := repo.ListByOrganization(ctx, orgID)
	if err != nil {
		// Public route: never leak repo errors. Treat as no-IdPs.
		return out
	}
	for _, idp := range rows {
		if idp == nil || !idp.Active {
			continue
		}
		// Safe projection: ID + Type + Name + (optionally) EmailDomains.
		// Config (issuer URL, client_id, encrypted client_secret,
		// attribute mapping, etc.) is NEVER read into the response.
		var emailDomains []string
		if !hideEmailDomains {
			emailDomains = make([]string, 0, len(idp.Config.EmailDomains))
			emailDomains = append(emailDomains, idp.Config.EmailDomains...)
		}
		out = append(out, publicIdentityProvider{
			ID:           idp.ID,
			Type:         string(idp.Type),
			Name:         idp.Name,
			LoginURL:     oidcLoginURL(idp),
			EmailDomains: emailDomains, // nil when hidden ⇒ omitted (omitempty)
		})
	}
	return out
}

// oidcLoginURL returns the OSS login-initiation path for an active
// type=oidc provider, or "" for any other transport. The URL is a
// same-origin relative path built ONLY from the provider ID + the fixed
// Slice-4 route — it exposes no provider internals.
func oidcLoginURL(idp *domain.IdentityProvider) string {
	if idp == nil || idp.Type != domain.IDPTypeOIDC {
		return ""
	}
	return "/api/v1/auth/idp/" + idp.ID.String() + "/login"
}

// firstLoginURL returns the first non-empty per-IdP LoginURL, used as the
// org-level login affordance. OSS is one-OIDC-provider-per-org, so at most
// one projected IdP carries a LoginURL. Empty when no active OIDC provider.
func firstLoginURL(idps []publicIdentityProvider) string {
	for _, p := range idps {
		if p.LoginURL != "" {
			return p.LoginURL
		}
	}
	return ""
}
