// Package api hosts the OSS Gin route registration for the Identuum
// identity provider. It is the production-style replacement for the
// stdlib net/http smoke handler in internal/server: same endpoints,
// real Gin engine, real middleware order matching the monolith
// shape. Only the always-public surface lands in this slice
// (system/info, health, metrics, discovery, JWKS) — subsequent
// slices will register additional groups behind feature gates and
// dependency seams.
//
// Composition contract:
//
//	oss.RegisterOSSRoutes(engine, ossDeps)   // this package
//	ce.RegisterCERoutes(engine,  ceDeps)     // CE module — later
//
// OSS must not import CE. CE may compose OSS + CE.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/buildinfo"
	"github.com/identuum/identuum-idp-oss/internal/features"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/internal/setup"
	// httpmw is the standalone HTTP-middleware package that owns the body-size
	// cap (mw.BodyLimitMiddleware). It is a DIFFERENT package than internal/mw
	// above (both are named `mw`), so it is aliased. P2-1 mounts its body limit
	// globally; before this it had no production caller.
	httpmw "github.com/identuum/identuum-idp-oss/mw"
	"github.com/identuum/identuum-idp-oss/ratelimit"
)

// SessionLookupWithStatus is the session-store seam shared by the
// authorization_code grant (GetByID → resolve a code's session) and the
// bearer-path Stage-1 + R3 combined live-status check
// (GetSessionWithUserAndOrgStatus → reject revoked sessions, banned/deleted
// users, and inactive/deleted orgs in one round-trip). The real session
// repository satisfies both; a single field feeds both consumers.
type SessionLookupWithStatus interface {
	handlers.SessionByIDLookup
	mw.SessionRevocationLookup
}

// OSSRouterDeps is the dependency bundle the OSS Gin scaffold
// requires. The fields are intentionally narrow: the always-public
// surface needs only product metadata, discovery config, and a JWKS
// provider. As route groups land, this struct will grow — never
// pass an aggregate "*Application" through.
type OSSRouterDeps struct {
	// Version is the human-readable build identifier surfaced at
	// /system/info and /health. Empty defaults to "identuum-idp-oss
	// (unknown version)".
	Version string

	// DiscoveryConfig drives /.well-known/openid-configuration.
	// Empty fields fall back to the localhost placeholders defined
	// by server.ResolveDiscoveryConfig.
	DiscoveryConfig server.OIDCDiscoveryConfig

	// JWKSProvider backs /.well-known/jwks.json. nil is replaced
	// with server.EmptyJWKSProvider{} so the endpoint reliably
	// returns {"keys":[]} instead of 500 or 404.
	JWKSProvider server.JWKSProvider

	// KeyService backs the /api/v1/keys handler group. When nil,
	// the group is NOT registered — operators running --gin-serve
	// without --jwks-db (or another DB-wired pathway) won't see
	// keys endpoints at all.
	KeyService *service.KeyService

	// Audit is the audit-emission seam used by the keys handler
	// group (and future protected handlers). nil is replaced with
	// audit.NoopService{} so callers cannot accidentally crash on
	// nil-dispatch.
	Audit audit.Service

	// AuditReader is the read seam behind GET /api/v1/audit/events (L-2).
	// nil leaves the route mounted as a P-018 service-missing fallback.
	AuditReader handlers.AuditReader

	// DBPinger, when wired, is the Postgres liveness check surfaced as the
	// `database` component of GET /api/v1/health/details (THE-HEALTH-DETAILS).
	// nil (no-DB scaffold) makes that component ABSENT — never zero-faked.
	DBPinger func(ctx context.Context) error

	// TokenVerifier, when non-nil, is wired in front of every
	// route group so an incoming `Authorization: Bearer <jwt>` is
	// translated into a populated principal. Routes that require
	// authorization (e.g. /api/v1/keys) remain fail-closed when
	// TokenVerifier is nil — they 401 because no upstream populator
	// runs.
	TokenVerifier mw.TokenVerifier

	// ClientRepo, APIResourceRepo, ScopeTemplateRepo back the
	// OAuth-admin handler groups landed in the OAuth/admin batch
	// extraction slice. Each is independently conditional: a nil
	// repo means the corresponding group is not registered at all
	// (404 on those paths), so partial wirings are safe.
	ClientRepo        repository.ClientRepository
	APIResourceRepo   repository.APIResourceRepository
	ScopeTemplateRepo repository.ScopeTemplateRepository

	// ClientService, APIResourceService, ScopeTemplateService are
	// the OSS service-layer versions of the same three groups. When
	// supplied, the handlers route mutations through these and the
	// 501 stubs flip to live behaviour. Independent of the legacy
	// XRepo fields — supplying both is fine; the service wins.
	ClientService        *service.ClientService
	APIResourceService   *service.APIResourceService
	ScopeTemplateService *service.ScopeTemplateService

	// UserRepo, OrganizationRepo back the identity-admin handler
	// groups landed in the identity-admin batch extraction slice.
	// Read-only when only the repo is supplied; mutations 501.
	UserRepo         repository.UserRepository
	OrganizationRepo repository.OrganizationRepository

	// OrganizationDomainRepo + IdentityProviderRepo back the public
	// organization-lookup route (GET /api/v1/auth/organization-lookup).
	// Both are OPTIONAL: when absent the route still registers (the
	// minimum requirement is OrganizationRepo) but the verified-domain
	// global index path and the IdP enumeration become no-ops. See
	// internal/handlers/organization_lookup.go.
	OrganizationDomainRepo repository.OrganizationDomainRepository
	IdentityProviderRepo   repository.IdentityProviderRepository

	// UserService, OrganizationService, OrganizationDomainService
	// are the OSS service-layer versions of the identity-admin
	// groups. When supplied, mutations are LIVE; otherwise the
	// respective stubs return 501.
	UserService               *service.UserService
	OrganizationService       *service.OrganizationService
	OrganizationDomainService *service.OrganizationDomainService

	// UserProfileService owns the optional OIDC §5.1 profile row
	// (THE-PROFILE-CLAIMS): PUT/GET /api/v1/profile, the admin user
	// surface, userinfo and the id_token read/write it. Nil = every profile
	// field unset and profile writes refused (503).
	UserProfileService *service.UserProfileService

	// OrgRoleService backs the RBAC route family (/me/roles,
	// /organizations/:id/roles[/...], /users/:id/roles[/...]).
	// When nil, no RBAC routes register; the paths 404.
	OrgRoleService *service.OrgRoleService

	// ServiceAccountService backs the service-account admin
	// route family (/api/v1/organizations/:id/service-accounts,
	// /api/v1/service-accounts/:id, and the enable/disable
	// affordances). When nil, no SA admin routes register.
	ServiceAccountService *service.ServiceAccountService

	// ServiceAccountClientBundleService backs the combined-create
	// route POST /api/v1/organizations/:id/service-accounts/with-client.
	// When nil, the route does not register.
	ServiceAccountClientBundleService *service.ServiceAccountClientBundleService

	// AgentCommunicationAuthorizationService backs the agent-communication
	// admin surface /api/v1/agent-communication-authorizations (AYGHU-1
	// foundation + AYGHU-2 admin API: create, list, get, revoke — org_admin
	// own-org only). When nil, no routes register. Issuance + DPoP (AYGHU-3)
	// and introspection/revocation propagation (AYGHU-4) are later slices.
	AgentCommunicationAuthorizationService *service.AgentCommunicationAuthorizationService

	// LocalLogin backs POST /api/v1/auth/login. When nil, the
	// login route does not register.
	LocalLogin *service.LocalLoginService

	// MFAEnrollment backs the pending-MFA login routes added
	// alongside the MFA policy gate:
	//
	//   POST /api/v1/auth/login/mfa/enroll/initiate
	//   POST /api/v1/auth/login/mfa/enroll/complete
	//   POST /api/v1/auth/login/mfa
	//
	// When nil, the three routes do not register and the legacy
	// single-step contract stays in force.
	MFAEnrollment *service.MFAEnrollmentService

	// MFAVerifier verifies a TOTP code for an enrolled user. Backs the
	// THE-HONEST-ACR step-up ceremony (GET/POST /api/v1/auth/step-up)
	// together with CookieSession + SessionRepo; nil leaves it unmounted.
	MFAVerifier *service.MFAVerifierService

	// RequestObjectService verifies and merges OIDC §6 request objects for
	// /authorize (THE-JAR-REQUEST-OBJECT). nil → request objects refused.
	RequestObjectService *service.RequestObjectService

	// UserSessionService backs POST /api/v1/auth/session/refresh
	// and POST /api/v1/auth/logout. When nil, both routes do not
	// register.
	UserSessionService *service.UserSessionService

	// SessionRepo, when non-nil, lets the account-settings
	// sessions list + revoke routes register:
	//
	//   GET  /api/v1/sessions
	//   POST /api/v1/revoke
	//
	// Both routes require an authenticated principal (bearer
	// middleware) AND require this repo for the list / GetByID
	// lookups. The revoke route additionally requires
	// UserSessionService for the actual revoke call.
	SessionRepo repository.SessionRepository

	// UserToken, when wired, lets POST /api/v1/auth/login and
	// POST /api/v1/auth/session/refresh return a fresh signed
	// access token in addition to the session refresh token.
	UserToken *service.UserTokenService

	// UserLookup is the user-by-ID seam the refresh handler
	// consults to load a user row when minting a fresh access
	// token after rotation.
	UserLookup handlers.UserByIDLookup

	// AuthorizationCodeService backs the authorization_code grant
	// on /api/v1/oauth/token. When nil (or when any of UserToken /
	// UserLookup / SessionLookup are nil), the grant returns
	// unsupported_grant_type — preserving the legacy posture.
	AuthorizationCodeService *service.AuthorizationCodeService

	// SessionLookup is the session-store seam consulted by BOTH the
	// authorization_code grant (resolve a code's session_id →
	// *domain.Session for acr / auth_time / amr stamping) AND the
	// bearer-path Stage-1 + R3 combined live-status check
	// (GetSessionWithUserAndOrgStatus). The real session repository
	// satisfies both method sets.
	SessionLookup SessionLookupWithStatus

	// AuthorizeService backs GET /api/v1/oauth/authorize. When
	// nil, the route is NOT registered (404). Discovery does not
	// advertise authorization_code unless this service AND the
	// IDTokenService (or at least the AuthorizationCodeService
	// + UserToken set) are wired into the token endpoint.
	AuthorizeService *service.AuthorizeService

	// IDTokenService backs OIDC ID token issuance in the
	// authorization_code grant. When wired, a code consumed with
	// the "openid" scope returns an `id_token` in the token
	// response. When nil, the response stays plain OAuth.
	IDTokenService *service.IDTokenService

	// CookieSession backs the cookie-driven browser flow on
	// /authorize, the browser login form, the consent UI, and
	// end-session. When nil, only the bearer flow is supported.
	CookieSession *service.CookieSessionService

	// ConsentService backs interactive consent persistence (the
	// `oauth_consents` table). When nil, only the
	// SkipConsent=true clients can complete /authorize without
	// the consent screen.
	ConsentService *service.ConsentService

	// IDTokenVerifier, when wired, lets the /api/v1/oidc/logout
	// handler verify the `id_token_hint` query parameter and
	// resolve the client + session it points at. Without it,
	// hints are silently ignored (cookie-driven logout only).
	IDTokenVerifier *service.IDTokenVerifier

	// CSRF, when wired, gates POST /api/v1/auth/browser-login
	// and POST /api/v1/oauth/consent with a double-submit
	// HMAC-bound CSRF token. The GET form handlers issue the
	// token + cookie.
	CSRF *service.BrowserCSRFService

	// FrontchannelLogoutEnabled toggles registration of the
	// minimal GET /api/v1/oidc/frontchannel-logout endpoint AND
	// flips `frontchannel_logout_supported` from false to true
	// in discovery. Defaults to false until operators explicitly
	// opt in.
	FrontchannelLogoutEnabled bool

	// HidePublicIDPEmailDomains, when true, OMITS email_domains from the
	// PUBLIC organization-lookup projection (operator hardening — the org's
	// federated email domains are no longer disclosed on the unauthenticated
	// lookup). Default false ⇒ exposed as before. Gates ONLY the public
	// lookup; the authenticated org-admin identity-provider API is unaffected.
	HidePublicIDPEmailDomains bool

	// BrowserTokens, when wired, swaps the browser cookie value
	// from a raw user-session refresh token to an opaque
	// browser-session token resolved through the
	// browser_session_tokens indirection table.
	BrowserTokens *service.BrowserSessionTokenService

	// BackchannelLogoutService, when wired, lets the
	// /api/v1/oidc/logout handler POST a logout_token to the
	// resolved client's `backchannel_logout_uri`. The discovery
	// composer flips `backchannel_logout_supported` to true
	// only when this service is wired.
	BackchannelLogoutService *service.BackchannelLogoutService

	// BackchannelDeliveryAdminService, when wired, mounts the
	// site_admin-only operator surface at
	// /api/v1/admin/backchannel-logout-deliveries (list/get/replay).
	BackchannelDeliveryAdminService *service.BackchannelDeliveryAdminService

	// IntrospectionService backs POST /api/v1/oauth/introspection
	// and is reused by POST /api/v1/oauth/revoke for verifier
	// access. When nil, neither OAuth route registers (404).
	IntrospectionService *service.IntrospectionService

	// OAuthClientAuth, when non-nil, mounts canonical RFC 7662 §2.1
	// / RFC 7009 §2.1 `client_secret_basic` + `client_secret_post`
	// authentication in front of the OAuth introspection +
	// revocation routes. When nil, those routes fall back to
	// RequireSiteAdmin so an OSS deployment that has not yet wired
	// client auth still gets a protected surface.
	OAuthClientAuth mw.OAuthClientAuthenticator

	// SessionRevoker is the fan-out hook the revocation handler
	// fires on a successfully verified token. nil defaults to
	// service.NoopSessionRevoker so the revocation route remains
	// safely callable in OSS-only deployments.
	SessionRevoker service.SessionRevoker

	// TokenRevocationService, when non-nil, persists a per-jti
	// revocation row from the /oauth/revoke handler AND backs the
	// IntrospectionService's revocation-aware path (revoked jti →
	// `{"active":false}`). When nil, the OSS deployment is
	// effectively session-revoke-only.
	TokenRevocationService *service.TokenRevocationService

	// RefreshTokenService, when non-nil, enables the
	// grant_type=refresh_token branch on /api/v1/oauth/token AND
	// the refresh-token revocation branch on /api/v1/oauth/revoke.
	// When nil, refresh_token requests on the token endpoint are
	// rejected as unsupported_grant_type and the revoke endpoint
	// continues to handle access tokens only.
	RefreshTokenService *service.RefreshTokenService

	// TokenService backs POST /api/v1/oauth/token (RFC 6749 §4.4
	// client_credentials grant). When nil OR when OAuthClientAuth
	// is nil, the route is NOT registered — token issuance must
	// always run behind client authentication.
	TokenService *service.TokenService

	// FeatureGate is the OSS-owned commercial-feature gate consumed
	// by mw.RequireFeature on the route groups that the monolith
	// gates with features.AuthorizationServer (api-resources,
	// scope-templates).
	//
	// Default policy: a nil FeatureGate resolves to features.OpenGate
	// so the OSS scaffold does NOT lose route reachability before CE
	// composition wires a tier-aware gate. Operators who want
	// fail-closed semantics can wire features.ClosedGate or a
	// features.NewStaticGate explicitly.
	FeatureGate features.FeatureGate

	// DCRInitialAccessTokenService backs the RFC 7591 §2.1
	// initial-access-token (IAT) lifecycle. When wired:
	//
	//   - POST /api/v1/oauth/register accepts `Authorization: Bearer
	//     <iat>` in lieu of a site_admin principal; IAT-imposed
	//     org-scope / grant-type / token-endpoint-auth-method
	//     constraints are enforced before client registration runs.
	//   - the IAT management surface
	//     (POST/GET /api/v1/dcr/initial-access-tokens and
	//     POST /api/v1/dcr/initial-access-tokens/:id/revoke) is
	//     registered, site_admin-gated.
	//
	// When nil, DCR remains site_admin-only and the management
	// surface is absent (404).
	DCRInitialAccessTokenService *service.DCRInitialAccessTokenService

	// DCRRegistrationAccessTokenService backs the RFC 7592 §2
	// registration-access-token (RAT) lifecycle bound to each DCR-
	// created client. When wired:
	//
	//   - POST /api/v1/oauth/register mints a one-shot RAT and
	//     returns it in the response under registration_access_token
	//     + registration_client_uri.
	//   - the management surface
	//     (GET / PUT / DELETE /api/v1/oauth/register/:client_id)
	//     registers and authenticates Bearer RAT (or site_admin
	//     fallback).
	//
	// When nil, no RAT is minted and the management surface is
	// absent (404).
	DCRRegistrationAccessTokenService *service.DCRRegistrationAccessTokenService

	// DCRRegistrationBaseURL is the absolute base used to compose
	// the registration_client_uri field in the DCR /register
	// response. Empty disables the field but does NOT disable RAT
	// minting. Typical production wiring: the deployment's issuer
	// URL.
	DCRRegistrationBaseURL string

	// UIPublicBaseURL is the browser-facing base URL of the identuum-ui
	// frontend. It composes the activation link returned beside a freshly
	// issued activation token (THE-UNUSABLE-TOKEN).
	//
	// It must be the UI origin, NOT the issuer: /activate is a UI page, so
	// an issuer-based link would 404. Empty is supported — the handlers
	// then return the token with an honest reason naming the setting
	// instead of a guessed link.
	UIPublicBaseURL string

	// PasswordReset, EmailVerification, OrganizationActivation,
	// and Claim back the account-lifecycle route family:
	//
	//   POST /api/v1/auth/password/reset-request
	//   POST /api/v1/auth/password/reset
	//   GET  /api/v1/auth/verify-email
	//   POST /api/v1/auth/resend-verification
	//   GET  /api/v1/auth/organizations/activate/:token
	//   POST /api/v1/auth/organizations/activate
	//   GET  /api/v1/auth/claim/validate
	//   POST /api/v1/auth/claim
	//
	// Each service field gates registration of its corresponding
	// routes — partial wirings are safe. Routes return 404 when
	// the backing service is nil.
	PasswordResetService          *service.PasswordResetService
	EmailVerificationService      *service.EmailVerificationService
	OrganizationActivationService *service.OrganizationActivationService
	ClaimService                  *service.ClaimService

	// WebAuthnService backs the OSS WebAuthn / passkeys family
	// (registration begin/finish, login begin/finish, credential
	// list/delete). When nil, none of the WebAuthn routes register
	// (404 on those paths).
	//
	// The login routes additionally require UserSessionService +
	// UserToken + UserLookup so a successful assertion can mint a
	// real session + access token + Set-Cookie. With WebAuthnService
	// wired but those three absent, only the registration +
	// credential-management routes are reachable.
	WebAuthnService *service.WebAuthnService

	// OrganizationProtocolSettingsService backs the per-org DCR +
	// SCIM availability check consulted by every DCR + SCIM
	// handler at request time. Owner correction (2026-06-04):
	// protocol availability is per-org DB state stored in
	// `organization_protocol_settings`, NOT a global env flag.
	// See identuum-idp/docs/open-core/IDP_DCR_SCIM_ORG_LEVEL_DB_CONFIG_CORRECTION.md.
	//
	// When nil, every DCR/SCIM request is allowed (the
	// documented OSS scaffold default — test fixtures and smoke
	// binaries that have not wired the service keep the
	// foundation reachable). Production wiring binds this to the
	// Postgres-backed service.
	OrganizationProtocolSettingsService *service.OrganizationProtocolSettingsService

	// OIDCProviderConfigService backs the org-admin config API for an
	// organization's single upstream OIDC identity provider (OSS basic
	// single-provider login). When nil, the routes mount a uniform
	// service-missing fallback (P-018). It never manages a list of
	// providers (multi-IdP is CE).
	OIDCProviderConfigService *service.OIDCProviderConfigService

	// OIDCLoginService backs the always-public upstream-OIDC login
	// initiation endpoint (GET /api/v1/auth/idp/:id/login). When nil the
	// route is not mounted (optional until a provider is configured +
	// wired). It resolves the ONE provider by id — never a list.
	OIDCLoginService *service.OIDCLoginService

	// OIDCCallbackService backs the always-public upstream-OIDC callback
	// endpoint (GET /api/v1/auth/idp/:id/callback): consume state, exchange
	// code, strictly validate the ID token → validated ExternalUser. When
	// nil the route is not mounted.
	OIDCCallbackService *service.OIDCCallbackService

	// SetupService backs the appliance setup foundation:
	//
	//   GET  /api/setup/status
	//   POST /api/setup/verify-token
	//   POST /api/setup/complete
	//
	// When nil, those routes are NOT registered. Production --gin-serve
	// always wires this so the wizard is reachable on a freshly-migrated
	// install; tests that exercise unrelated routes may leave it nil.
	SetupService *setup.Service

	// SetupDataDir is the persistent data directory the setup service
	// reads/writes for the on-disk token file. Required when SetupService
	// is non-nil.
	SetupDataDir string

	// StartupReport is the P-018 NOT-SERVING-JUST-ALERTING fault
	// accumulator. When wired (the runtime always wires one), the
	// top-level NotServingGuard is mounted and the health probe becomes
	// mode-aware: any fatal fault recorded during route registration /
	// dependency wiring flips the process to NOT-SERVING (every normal
	// route 503s, /health 503s with the fault) instead of crashing. When
	// nil (minimal test engines), the guard is not mounted and /health
	// keeps its static healthy contract — preserving prior behaviour.
	StartupReport *lifecycle.StartupReport

	// RateLimitConfig holds per-route rate limit thresholds for the OSS
	// ceremony routes. LoginLimit governs the WebAuthn login begin/finish
	// routes; RegisterLimit governs WebAuthn register begin/finish.
	// When RequestsPerWindow < 1 (zero-value / unconfigured), the
	// corresponding limiter is a noop — safe for test environments that
	// do not need rate limiting. Production wiring should load these from
	// the runtime's env-derived config (defaults: 5/1m login, 10/1h register;
	// see internal/runtime.resolveRateLimitConfig).
	RateLimitConfig ratelimit.RateLimitConfig

	// CORSAllowedOrigins is the deny-by-default, exact-match CORS origin
	// allowlist handed to the global CORS middleware (internal/mw.CORS).
	// The CLI entrypoint populates it from the
	// IDENTUUM_IDP_CORS_ALLOWED_ORIGINS env var. Empty (the default)
	// denies all cross-origin requests; same-origin traffic is
	// unaffected.
	CORSAllowedOrigins []string

	// TrustedProxies is the operator-supplied list of trusted reverse-proxy
	// addresses/CIDRs handed to gin's SetTrustedProxies. Empty (the default)
	// trusts NO proxy, so c.ClientIP() — used by rate limiting AND
	// audit/security-event attribution — resolves to the direct peer address
	// and a forged X-Forwarded-For cannot spoof it. The CLI entrypoint
	// populates it from IDENTUUM_IDP_TRUSTED_PROXIES. Operators fronting the
	// app with a proxy MUST set this or client IPs will be the proxy's.
	TrustedProxies []string
}

const (
	// jwksFetchTimeout caps how long the Gin scaffold waits on the
	// JWKS provider before failing the request. Matches the smoke
	// server's value so both surfaces have the same SLO.
	jwksFetchTimeout = 5 * time.Second
)

// NewOSSEngine constructs a Gin engine pre-configured with the
// OSS-safe middleware subset and the OSS route surface. Uses
// gin.New() — never gin.Default() — so middleware mounts are
// explicit and reviewable.
//
// Global middleware in this slice:
//   - gin.Recovery       (panic-safe HTTP layer; first line of
//     defence before any handler runs)
//
// Additional OSS-safe middleware from the monolith (RequestID,
// CorrelationID, Fingerprint, BodyLimit, Metrics,
// UnconfiguredSystemBlocker, RequestTimeout, DatabaseReadiness,
// CORS, Secure(CSP), RateLimit) will land in follow-up slices as
// the relevant route groups are extracted — premature middleware
// without consumer routes would be dead weight.
func NewOSSEngine(deps OSSRouterDeps) *gin.Engine {
	// Force release mode so test runs and live boot do not print the Gin
	// debug banner to stderr. This is UNCONDITIONAL by design: gin reads
	// GIN_MODE once at package init, and this call overrides it either way —
	// there is NO GIN_MODE override (an earlier comment claimed one; it never
	// existed, because this SetMode always runs). It is now a pure logging
	// concern: THE-DEBUG-BANNER-SWITCH decoupled cookie Secure from gin.Mode
	// (see cookieSecureForRequest), so no security property rides on it.
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	// P2-2: default to trusting NO proxy. gin's zero-value trusts ALL proxies,
	// so X-Forwarded-For would be honoured from any peer — letting an attacker
	// forge c.ClientIP() (used by rate limiting AND audit/security-event
	// attribution). Empty deps.TrustedProxies ⇒ SetTrustedProxies(nil) ⇒ the
	// direct peer address is used. Operators behind a proxy set
	// IDENTUUM_IDP_TRUSTED_PROXIES to the proxy CIDRs.
	if err := r.SetTrustedProxies(deps.TrustedProxies); err != nil {
		// Malformed operator CIDR: fail CLOSED (trust none) and, when a startup
		// report is wired, record a fatal fault so the process enters
		// NOT-SERVING-JUST-ALERTING (P-018) instead of silently trusting the
		// wrong set.
		_ = r.SetTrustedProxies(nil)
		if deps.StartupReport != nil {
			deps.StartupReport.Fatal("NewOSSEngine.SetTrustedProxies",
				"invalid IDENTUUM_IDP_TRUSTED_PROXIES; refusing to trust any proxy")
		}
	}
	r.Use(gin.Recovery())
	RegisterOSSRoutes(r, deps)
	return r
}

// RegisterOSSRoutes attaches the always-public OSS endpoints to
// router. Use this overload when composing into a larger engine —
// e.g. when CE wires its own routes onto the same gin.Engine after
// OSS has registered the OSS-safe surface.
//
// Endpoints registered:
//
//	GET  /system/info
//	GET  /api/v1/component
//	GET  /health
//	GET  /.well-known/openid-configuration
//	GET  /.well-known/jwks.json
//
// (/metrics is NOT on this public engine — it serves on the separate,
// internal-only listener; see internal/runtime.Runtime.startMetricsListener
// and TestNewOSSEngine_MetricsNotOnPublicRouter.)
//
// Non-GET on any of the JSON endpoints returns 405 + Allow: GET;
// gin's mux is configured to call HandleMethodNotAllowed for that
// behaviour — see engine.HandleMethodNotAllowed below.
func RegisterOSSRoutes(router gin.IRouter, deps OSSRouterDeps) {
	resolved := resolvedDeps(deps)

	// orgFeatureLookup adapts the OSS protocol-settings service
	// onto the narrow handler-side interface; nil propagates so
	// handlers retain their open-default behaviour when the
	// service is not wired (test fixtures, smoke binaries). Used
	// by DCR, DCR-management, and SCIM mounts.
	var orgFeatureLookup handlers.OrgFeatureLookup
	if resolved.OrganizationProtocolSettingsService != nil {
		orgFeatureLookup = resolved.OrganizationProtocolSettingsService
	}

	// Each helper below performs its own nil-guard at the head so the
	// top-level body stays free of branching. The 2026-06-24 refactor
	// reduced this function from cyclomatic complexity 57 to ~3.

	// Security response headers are written first so they appear on EVERY
	// response, including the NOT-SERVING 503 and auth 4xx rejections.
	mountSecurityHeaders(router)
	// AUTH-503: one correlation id per request (incoming X-Request-ID when
	// well-formed, else a fresh uuid), bound into the request context so
	// every ERROR log line and every 503 body carry the same id.
	router.Use(mw.CorrelationIDMiddleware())
	mountCORS(router, resolved)
	// P2-1: cap request bodies GLOBALLY (before any handler reads the body) so
	// an oversized payload on ANY route — including the public unauthenticated
	// ones (setup, login, password-reset, WebAuthn, DCR) — cannot force
	// unbounded allocation. Mounted as global middleware so it covers every
	// group registered below.
	mountBodyLimit(router)

	// P-018: the NOT-SERVING guard is the first GUARD in the chain
	// (before bearer auth and every group) so that, when a fatal startup
	// fault has been recorded, every normal route is refused with 503
	// while the health/liveness probes remain reachable.
	mountNotServingGuard(router, resolved)
	mountBearerAuth(router, resolved)
	mountPublicSurface(router, resolved)
	mountSetup(router, resolved)
	mountKeys(router, resolved)
	mountClients(router, resolved)
	mountDCR(router, resolved, orgFeatureLookup)
	// Advanced DCR (initial-access-token management + RFC 7592 client
	// management) is Enterprise/CE-only and is NOT mounted here — the
	// backing services were never constructed by the OSS runtime, so the
	// routes could only ever 404 while the contract advertised them
	// (integrity-audit F6/C1). A CE composition mounts that surface via
	// its own router with real services.
	mountAPIResources(router, resolved)
	mountScopeTemplates(router, resolved)
	mountUserSurface(router, resolved)
	mountOrganizations(router, resolved)
	mountOrganizationProtocolSettings(router, resolved)
	mountOrganizationIdentityProvider(router, resolved)
	mountAuditRoutes(router, resolved)
	mountSystemHealthRoutes(router, resolved)
	mountOrganizationDomains(router, resolved)
	mountOrganizationLookup(router, resolved)
	mountRBAC(router, resolved)
	mountServiceAccounts(router, resolved)
	mountServiceAccountClientBundle(router, resolved)
	mountAgentCommunicationAuthorizations(router, resolved)
	mountAccountLifecycle(router, resolved)
	mountWebAuthn(router, resolved)
	mountSessions(router, resolved)
	mountAuthSessions(router, resolved)
	mountIntrospectionAndRevocation(router, resolved)
	mountToken(router, resolved)
	mountAuthorize(router, resolved)
	mountBrowserLogin(router, resolved)
	mountOIDCLogin(router, resolved)
	mountOIDCCallback(router, resolved)
	mountConsent(router, resolved)
	mountFrontchannelLogout(router, resolved)
	mountBackchannelDeliveries(router, resolved)
	mountEndSession(router, resolved)
}

// notServingAllowlist is the set of paths that remain reachable while
// the process is in NOT-SERVING mode: the readiness probe (/health, so
// it can REPORT the fault), the liveness probe (/livez, so orchestrators
// do not kill+restart a process that is intentionally staying alive to
// alert), and /metrics (so operators keep observability). Everything
// else is refused with 503.
var notServingAllowlist = map[string]struct{}{
	"/health": {},
	"/livez":  {},
	// NOTE: no "/metrics" — it is not registered on this public engine
	// (it serves on the separate internal-only listener), so an allowlist
	// entry here would never match.
}

// mountNotServingGuard mounts the P-018 NOT-SERVING interceptor as the
// first middleware in the chain. It is only mounted when a StartupReport
// is wired (the runtime always wires one); minimal test engines without
// a report keep their prior behaviour (no guard).
// mountSecurityHeaders registers the global security-headers middleware
// (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and a
// frame-ancestors CSP) using the hardened defaults. Applied to every
// response on the engine; a downstream handler may still override a
// specific header (e.g. the frontchannel-logout page's page CSP).
func mountSecurityHeaders(router gin.IRouter) {
	router.Use(mw.SecurityHeaders())
}

// mountCORS registers the deny-by-default CORS middleware using the
// operator-configured exact-match origin allowlist. With an empty
// allowlist (the default) no cross-origin request is granted access;
// same-origin traffic is unaffected.
func mountCORS(router gin.IRouter, resolved OSSRouterDeps) {
	router.Use(mw.CORS(resolved.CORSAllowedOrigins))
}

// mountBodyLimit installs the global request-body cap (mw.MaxBodySize = 1 MB).
// No per-route overrides are supplied: an audit of every body-bearing OSS route
// (POST/PUT/PATCH — auth, DCR client registration incl. inline JWKS, WebAuthn
// attestation, org/user admin, bulk-user create) found none whose legitimate
// payload approaches 1 MB (SCIM, the only bulk protocol, is not mounted in OSS;
// there is no file-upload route). If a future route needs a larger body, pass a
// httpmw.RouteBodyLimits{"<c.FullPath()>": n} override here.
func mountBodyLimit(router gin.IRouter) {
	router.Use(httpmw.BodyLimitMiddleware())
}

func mountNotServingGuard(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.StartupReport == nil {
		return
	}
	router.Use(NotServingGuard(resolved.StartupReport))
}

// NotServingGuard returns the middleware that, when the report carries a
// fatal startup fault, refuses every non-allowlisted route with 503 +
// Retry-After and a secret-free body naming the faults. When the report
// is serving (no fatal fault) it is a transparent pass-through. The
// fatal check is a lock-free atomic read so the hot path stays cheap.
func NotServingGuard(report *lifecycle.StartupReport) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !report.HasFatal() {
			c.Next()
			return
		}
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		if _, ok := notServingAllowlist[path]; ok {
			c.Next()
			return
		}
		c.Header("Retry-After", "30")
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_serving",
			"faults": report.Faults(),
		})
	}
}

// mountBearerAuth attaches the bearer-token populator BEFORE any
// handler/group is registered. With a verifier wired, an
// Authorization: Bearer header is parsed into a *domain.Principal and
// stored in gin.Context; downstream RequireSiteAdmin /
// RequireScopesAny make the authorization decision. Without a
// verifier, the chain is a no-op and protected groups fail closed at
// the guard layer.
func mountBearerAuth(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.TokenVerifier == nil {
		return
	}
	// resolved.SessionLookup (SessionLookupWithStatus) wires the bearer-path
	// Stage-1 session-revocation check AND the R3 combined user/org live-
	// status check via GetSessionWithUserAndOrgStatus. When nil (no session
	// store wired, e.g. the no-DB scaffold) the middleware skips the check.
	// resolved.TokenRevocationService wires the RFC 7009 per-token (jti)
	// revocation gate that applies to EVERY bearer token — including M2M /
	// service-account tokens with no session (P0-6). Fail-closed on store error.
	router.Use(mw.BearerPrincipal(resolved.StartupReport, resolved.TokenVerifier, resolved.SessionLookup, resolved.TokenRevocationService))
}

func mountPublicSurface(router gin.IRouter, resolved OSSRouterDeps) {
	// docgen:endpoint
	// docgen:surface=top-level
	// docgen:method=GET
	// docgen:path=/system/info
	// docgen:summary=System info: deployment metadata + module identifier.
	// docgen:tier=oss
	// docgen:auth=public
	router.GET("/system/info", systemInfoHandler(resolved))

	// docgen:endpoint
	// docgen:surface=top-level
	// docgen:method=GET
	// docgen:path=/api/v1/component
	// docgen:summary=Component discovery: safe OSS product/API capability facts.
	// docgen:tier=oss
	// docgen:auth=public
	router.GET("/api/v1/component", componentHandler(resolved))

	// docgen:endpoint
	// docgen:surface=top-level
	// docgen:method=GET
	// docgen:path=/health
	// docgen:summary=Health probe (liveness + readiness).
	// docgen:tier=oss
	// docgen:auth=public
	router.GET("/health", healthHandler(resolved))

	// Liveness probe — always 200 while the process is up, including
	// NOT-SERVING mode (P-018: live but not ready; readiness is /health).
	// Intentionally NOT api-docgen-annotated: it is an operational probe,
	// not part of the documented API surface, so it does not alter the
	// canonical endpoint count. (Cataloguing it — count + golden + wiki —
	// belongs to a separate docs slice.)
	router.GET("/livez", livezHandler())

	// /metrics is INTENTIONALLY NOT mounted here. It is served on its
	// own listener (internal/runtime.Runtime.startMetricsListener,
	// gated by Config.MetricsAddr) — never on the public API surface.
	// This closes the tenant/IDP-enumeration exposure noted in
	// docs/audit/changelog/security-headers-middleware.md: some
	// Prometheus metric labels (org_id, provider_id, provider_name)
	// are fine for an internal-only scrape target but not for a
	// public, unauthenticated port. See
	// docs/audit/changelog/metrics-separate-listener.md.

	// docgen:endpoint
	// docgen:surface=top-level
	// docgen:method=GET
	// docgen:path=/.well-known/openid-configuration
	// docgen:summary=OIDC discovery document.
	// docgen:tier=oss
	// docgen:auth=public
	router.GET("/.well-known/openid-configuration", discoveryHandler(resolved))

	// docgen:endpoint
	// docgen:surface=top-level
	// docgen:method=GET
	// docgen:path=/.well-known/jwks.json
	// docgen:summary=Public JWKS (signing key public material only — never the private half).
	// docgen:tier=oss
	// docgen:auth=public
	router.GET("/.well-known/jwks.json", jwksHandler(resolved))
}

// mountSetup mounts appliance first-run setup routes. Always-public,
// unauthenticated: the setup token is the wizard-authorization
// credential and is checked at the handler layer. Mounted alongside
// the other public endpoints and BEFORE any protected groups so the
// wizard is reachable on a freshly-migrated install where no admin
// user exists yet.
func mountSetup(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.SetupService == nil {
		return
	}
	RegisterSetupRoutes(router, SetupRoutesDeps{
		Service: resolved.SetupService,
		DataDir: resolved.SetupDataDir,
	})
}

// Admin/protected route groups. Each group is registered only when
// its backing service is wired — operators running --gin-serve
// without --jwks-db (or another DB pathway) get a minimal public-only
// surface and unrelated 404s for the admin endpoints.

func mountKeys(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.KeyService == nil {
		return
	}
	handlers.RegisterKeysRoutes(router, handlers.KeysHandlerDeps{
		KeyService:    resolved.KeyService,
		Audit:         resolved.Audit,
		StartupReport: resolved.StartupReport,
	})
}

func mountClients(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.ClientService == nil && resolved.ClientRepo == nil {
		// Both deps absent: the clients surface is intentionally not
		// mounted (e.g. the no-DB --gin-serve scaffold — a documented
		// partial mode, NOT a fault). Leave the group absent, exactly as
		// before. The P-018 fatal-fault path in RegisterClientsRoutes is
		// reached only by a direct caller that forces both deps nil.
		return
	}
	handlers.RegisterClientsRoutes(router, handlers.ClientsHandlerDeps{
		ClientService: resolved.ClientService,
		ClientRepo:    resolved.ClientRepo,
		Audit:         resolved.Audit,
		StartupReport: resolved.StartupReport,
	})
}

func mountDCR(router gin.IRouter, resolved OSSRouterDeps, orgFeatureLookup handlers.OrgFeatureLookup) {
	if resolved.ClientService == nil {
		return
	}
	handlers.RegisterDCRRoutes(router, handlers.DCRHandlerDeps{
		ClientService:       resolved.ClientService,
		IATService:          resolved.DCRInitialAccessTokenService,
		RATService:          resolved.DCRRegistrationAccessTokenService,
		RegistrationBaseURL: resolved.DCRRegistrationBaseURL,
		Audit:               resolved.Audit,
		OrgFeatureLookup:    orgFeatureLookup,
		StartupReport:       resolved.StartupReport,
	})
}

func mountAPIResources(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.APIResourceService == nil && resolved.APIResourceRepo == nil {
		return
	}
	handlers.RegisterAPIResourcesRoutes(router, handlers.APIResourcesHandlerDeps{
		APIResourceService: resolved.APIResourceService,
		APIResourceRepo:    resolved.APIResourceRepo,
		Audit:              resolved.Audit,
		FeatureGate:        resolved.FeatureGate,
		StartupReport:      resolved.StartupReport,
	})
}

func mountScopeTemplates(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.ScopeTemplateService == nil && resolved.ScopeTemplateRepo == nil {
		return
	}
	handlers.RegisterScopeTemplatesRoutes(router, handlers.ScopeTemplatesHandlerDeps{
		ScopeTemplateService: resolved.ScopeTemplateService,
		ScopeTemplateRepo:    resolved.ScopeTemplateRepo,
		Audit:                resolved.Audit,
		FeatureGate:          resolved.FeatureGate,
		StartupReport:        resolved.StartupReport,
	})
}

// mountUserSurface mounts the /api/v1/users, /me/profile, and SCIM
// route groups. UserDeps carries optional session-revoker and
// refresh-token-revoker seams so admin MFA reset can fan out
// post-disable revocations when those services are wired.
func mountUserSurface(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.UserService == nil && resolved.UserRepo == nil {
		return
	}
	userDeps := handlers.UsersHandlerDeps{
		UserService:   resolved.UserService,
		UserRepo:      resolved.UserRepo,
		Audit:         resolved.Audit,
		StartupReport: resolved.StartupReport,
		// Target-org password policy for the admin user paths
		// (THE-TWO-DEBTS); nil-safe — unwired keeps the strict defaults.
		PolicyOrgs: resolved.OrganizationRepo,
		// THE-PROFILE-CLAIMS: the optional profile row behind GET/PUT
		// /profile and the admin user surface. Nil-safe in the handlers.
		ProfileService: resolved.UserProfileService,
	}
	// Wire the OSS session revoker only when the runtime has
	// constructed UserSessionService; absent that, the handler
	// keeps its NoopSessionRevoker default so the rest of the
	// /api/v1/users surface stays mountable in scaffold /
	// smoke-only deployments.
	if resolved.UserSessionService != nil {
		userDeps.SessionRevoker = resolved.UserSessionService
	}
	// Same nil-safe wiring for the OAuth refresh-token side:
	// admin MFA reset fans out to RefreshTokenService when
	// available so an attacker who already minted a refresh
	// token cannot keep rotating it post-recovery.
	if resolved.RefreshTokenService != nil {
		userDeps.RefreshTokenRevoker = resolved.RefreshTokenService
	}
	handlers.RegisterUsersRoutes(router, userDeps)
	handlers.RegisterProfileRoute(router, userDeps)
	// SCIM v2 (a paid CE feature — Professional and above) was removed from the
	// OSS tree to close a licensing leak — see
	// docs/audit/changelog/scim-oss-leak-removal.md.
	// The /api/v1/scim/v2 surface is no longer mounted here; the per-org
	// protocol-settings infra (shared with DCR) and the scim=false capability
	// signal are retained.
}

func mountOrganizations(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.OrganizationService == nil && resolved.OrganizationRepo == nil {
		return
	}
	orgDeps := handlers.OrganizationsHandlerDeps{
		OrganizationService: resolved.OrganizationService,
		OrganizationRepo:    resolved.OrganizationRepo,
		Audit:               resolved.Audit,
		StartupReport:       resolved.StartupReport,
	}
	// Lifecycle→revocation cascade seams (nil-safe: only set from a
	// non-nil concrete so the interface field is not a typed-nil). The
	// session revoker reuses the existing org-scoped RevokeByOrganizationID;
	// the refresh revoker + member lister drive the per-member refresh sweep.
	if resolved.SessionRepo != nil {
		orgDeps.SessionRevoker = resolved.SessionRepo
	}
	if resolved.RefreshTokenService != nil {
		orgDeps.RefreshTokenRevoker = resolved.RefreshTokenService
	}
	if resolved.UserService != nil {
		orgDeps.MemberLister = resolved.UserService
	}
	if resolved.OrganizationActivationService != nil {
		orgDeps.ActivationResender = resolved.OrganizationActivationService
		orgDeps.ActivationIssuer = resolved.OrganizationActivationService
	}
	// THE-UNUSABLE-TOKEN: the UI origin, passed through verbatim. Empty
	// stays empty — the handlers refuse to guess a link.
	orgDeps.ActivationLinkBaseURL = resolved.UIPublicBaseURL
	if resolved.UserRepo != nil {
		orgDeps.AdminCounter = resolved.UserRepo
	}
	handlers.RegisterOrganizationsRoutes(router, orgDeps)
}

// mountOrganizationProtocolSettings mounts the site-admin admin
// surface for per-org DCR + SCIM toggles. Requires BOTH services so
// the GET/PUT can validate org existence + upsert the row atomically.
func mountOrganizationProtocolSettings(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.OrganizationProtocolSettingsService == nil || resolved.OrganizationService == nil {
		return
	}
	handlers.RegisterOrganizationProtocolSettingsRoutes(router, handlers.OrganizationProtocolSettingsHandlerDeps{
		ProtocolSettingsService: resolved.OrganizationProtocolSettingsService,
		OrganizationService:     resolved.OrganizationService,
		Audit:                   resolved.Audit,
		StartupReport:           resolved.StartupReport,
	})
}

// mountOrganizationIdentityProvider mounts the org-admin config API for an
// organization's single upstream OIDC provider. It is an OPTIONAL surface:
// when the config service is not wired (nil), the routes are NOT mounted —
// the early return below leaves them absent, with no fault. When the service
// is wired, the four org-admin identity-provider routes (POST/GET/PUT/DELETE
// /api/v1/organizations/:id/identity-provider) are mounted. Mirrors
// mountOrganizationProtocolSettings.
func mountOrganizationIdentityProvider(router gin.IRouter, resolved OSSRouterDeps) {
	// Optional feature: when the config service is not wired (synthetic /
	// partial-wiring setups), the surface is simply absent — no fault. The
	// production runtime always wires it. Mirrors mountOrganizationProtocolSettings.
	if resolved.OIDCProviderConfigService == nil {
		return
	}
	handlers.RegisterOrganizationIdentityProviderRoutes(router, handlers.OrganizationIdentityProviderHandlerDeps{
		OIDCProviderConfigService: resolved.OIDCProviderConfigService,
		Audit:                     resolved.Audit,
		StartupReport:             resolved.StartupReport,
	})
}

// mountAuditRoutes mounts the OSS audit-log read surface (L-2). The reader is
// resolved.AuditReader (the pgx audit repo); Audit is the writer seam the
// guard uses to emit scope-denial events.
func mountAuditRoutes(router gin.IRouter, resolved OSSRouterDeps) {
	// Optional feature: when the reader is not wired (synthetic / no-DB
	// scaffold) the surface is simply absent — no fault, no route. The
	// production runtime always wires it. Mirrors mountOrganizationIdentityProvider.
	if resolved.AuditReader == nil {
		return
	}
	handlers.RegisterAuditRoutes(router, handlers.AuditHandlerDeps{
		AuditReader:   resolved.AuditReader,
		Audit:         resolved.Audit,
		StartupReport: resolved.StartupReport,
	})
}

// mountSystemHealthRoutes mounts the site_admin runtime-info surface, GET
// /api/v1/health/details (THE-HEALTH-DETAILS). Always mounted (site_admin
// gated); the `database` component is present only when a DB pinger is wired,
// `audit_system` only when the audit reader is wired, and `redis` is always
// absent on OSS.
func mountSystemHealthRoutes(router gin.IRouter, resolved OSSRouterDeps) {
	handlers.RegisterSystemHealthRoutes(router, handlers.SystemHealthDeps{
		Version:       resolved.Version,
		DBPinger:      resolved.DBPinger,
		AuditWired:    resolved.AuditReader != nil,
		StartupReport: resolved.StartupReport,
	})
}

func mountOrganizationDomains(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.OrganizationDomainService == nil {
		return
	}
	handlers.RegisterOrganizationDomainsRoutes(router, handlers.OrganizationDomainsHandlerDeps{
		OrganizationDomainService: resolved.OrganizationDomainService,
		Audit:                     resolved.Audit,
		StartupReport:             resolved.StartupReport,
	})
}

// mountOrganizationLookup mounts the public organization-lookup route
// — UI login flow dependency. Registers only when OrganizationRepo is
// wired; the verified-domain index path and IdP enumeration become
// no-ops when their respective repos are nil.
func mountOrganizationLookup(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.OrganizationRepo == nil {
		return
	}
	handlers.RegisterOrganizationLookupRoute(router, handlers.OrganizationLookupHandlerDeps{
		OrganizationRepo:                 resolved.OrganizationRepo,
		OrganizationDomainRepo:           resolved.OrganizationDomainRepo,
		IdentityProviderRepo:             resolved.IdentityProviderRepo,
		Audit:                            resolved.Audit,
		HideIdentityProviderEmailDomains: resolved.HidePublicIDPEmailDomains,
	})
}

func mountRBAC(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.OrgRoleService == nil {
		return
	}
	handlers.RegisterRBACRoutes(router, handlers.RBACHandlerDeps{
		OrgRoleService: resolved.OrgRoleService,
		Audit:          resolved.Audit,
		FeatureGate:    resolved.FeatureGate,
		StartupReport:  resolved.StartupReport,
	})
}

func mountServiceAccounts(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.ServiceAccountService == nil {
		return
	}
	handlers.RegisterServiceAccountsRoutes(router, handlers.ServiceAccountsHandlerDeps{
		ServiceAccountService: resolved.ServiceAccountService,
		Audit:                 resolved.Audit,
	})
}

// mountAgentCommunicationAuthorizations mounts the AYGHU-2 admin surface
// (/api/v1/agent-communication-authorizations) when its service is wired.
func mountAgentCommunicationAuthorizations(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.AgentCommunicationAuthorizationService == nil {
		return
	}
	handlers.RegisterAgentCommunicationAuthorizationRoutes(router, handlers.AgentCommunicationAuthorizationsHandlerDeps{
		Service: resolved.AgentCommunicationAuthorizationService,
		Audit:   resolved.Audit,
	})
}

func mountServiceAccountClientBundle(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.ServiceAccountClientBundleService == nil {
		return
	}
	handlers.RegisterServiceAccountClientBundleRoutes(router, handlers.ServiceAccountClientBundleHandlerDeps{
		BundleService: resolved.ServiceAccountClientBundleService,
		Audit:         resolved.Audit,
	})
}

func mountAccountLifecycle(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.PasswordResetService == nil &&
		resolved.EmailVerificationService == nil &&
		resolved.OrganizationActivationService == nil &&
		resolved.ClaimService == nil {
		return
	}
	handlers.RegisterAccountLifecycleRoutes(router, handlers.AccountLifecycleHandlerDeps{
		PasswordReset: resolved.PasswordResetService,
		EmailVerify:   resolved.EmailVerificationService,
		OrgActivation: resolved.OrganizationActivationService,
		Claim:         resolved.ClaimService,
		Audit:         resolved.Audit,
		// Per-IP rate limit on the abuse-prone password-reset routes only
		// (tight). Noop when RateLimitConfig is zero-value.
		PasswordResetLimiter: mw.NewRateLimitMiddleware(resolved.RateLimitConfig.PasswordResetLimit, "password-reset"),
	})
}

func mountWebAuthn(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.WebAuthnService == nil {
		return
	}
	waDeps := handlers.WebAuthnHandlerDeps{
		WebAuthn:      resolved.WebAuthnService,
		UserSession:   resolved.UserSessionService,
		UserToken:     resolved.UserToken,
		UserLookup:    resolved.UserLookup,
		Audit:         resolved.Audit,
		LoginFinisher: resolved.WebAuthnService,
		// R7: per-IP rate limiters on ceremony routes (keyed on c.ClientIP()
		// which honours SetTrustedProxies — forged X-Forwarded-For from
		// untrusted sources falls back to RemoteAddr).
		// Default thresholds: LoginLimit 5/1m, RegisterLimit 10/1h — matching
		// the ancestor loginLimiter / registerLimiter thresholds from d5c10fb.
		// When RequestsPerWindow < 1 (zero-value OSSRouterDeps in tests),
		// NewRateLimitMiddleware returns a noop (c.Next() only).
		LoginLimiter:    mw.NewRateLimitMiddleware(resolved.RateLimitConfig.LoginLimit, "webauthn-login"),
		RegisterLimiter: mw.NewRateLimitMiddleware(resolved.RateLimitConfig.RegisterLimit, "webauthn-register"),
	}
	// UserOrgLookup reloads the org-bearing user projection so the
	// login-finish idp_only seal + MFA gate can read auth_policy/mfa_policy.
	// Nil-safe: only set from a non-nil concrete (avoid a typed-nil iface).
	if resolved.UserRepo != nil {
		waDeps.UserOrgLookup = resolved.UserRepo
	}
	handlers.RegisterWebAuthnRoutes(router, waDeps)
}

func mountSessions(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.SessionRepo == nil {
		return
	}
	handlers.RegisterSessionsRoutes(router, handlers.SessionsHandlerDeps{
		SessionList: resolved.SessionRepo,
		SessionRepo: resolved.SessionRepo,
		UserSession: resolved.UserSessionService,
		Audit:       resolved.Audit,
	})
}

// mountAuthSessions wires the /me/sessions + /me/mfa surface. The
// session-revoker and refresh-token-revoker seams wire only when the
// underlying service is present; absent those, the handler keeps its
// Noop defaults so the rest of the /me surface stays mountable.
func mountAuthSessions(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.LocalLogin == nil && resolved.UserSessionService == nil {
		return
	}
	authDeps := handlers.AuthSessionsHandlerDeps{
		LocalLogin:    resolved.LocalLogin,
		UserSession:   resolved.UserSessionService,
		UserToken:     resolved.UserToken,
		UserLookup:    resolved.UserLookup,
		SessionLookup: resolved.SessionLookup,
		TokenVerifier: resolved.TokenVerifier,
		MFAEnrollment: resolved.MFAEnrollment,
		Audit:         resolved.Audit,
	}
	if resolved.UserSessionService != nil {
		authDeps.SessionRevoker = resolved.UserSessionService
	}
	if resolved.RefreshTokenService != nil {
		authDeps.RefreshTokenRevoker = resolved.RefreshTokenService
	}
	if resolved.UserRepo != nil {
		// Self-service POST /api/v1/auth/change-password (THE-V036-PASSWORD).
		// Min-length 0 ⇒ the service's own default floor (8, mirroring
		// password reset). R2 parked: no session/refresh revocation wired.
		authDeps.ChangePassword = service.NewChangePasswordService(resolved.UserRepo, 0)
	}
	handlers.RegisterAuthSessionRoutes(router, authDeps)
}

// mountIntrospectionAndRevocation mounts the introspection + revocation
// + userinfo trio. The revocation checker is composed into the
// introspection service so a revoked jti returns `{"active":false}`;
// the composition is idempotent — calling WithRevocationChecker with
// the same service twice is a no-op.
func mountIntrospectionAndRevocation(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.IntrospectionService == nil {
		return
	}
	if resolved.TokenRevocationService != nil {
		resolved.IntrospectionService.WithRevocationChecker(resolved.TokenRevocationService)
	}
	handlers.RegisterIntrospectionRoutes(router, handlers.IntrospectionHandlerDeps{
		IntrospectionService: resolved.IntrospectionService,
		Audit:                resolved.Audit,
		ClientAuth:           resolved.OAuthClientAuth,
		StartupReport:        resolved.StartupReport,
		// Per-client introspection rate limit (very generous). Noop when
		// RateLimitConfig is zero-value.
		Limiter: mw.NewRateLimitMiddlewareWithKeyFn(resolved.RateLimitConfig.IntrospectionLimit, "oauth-introspection", oauthClientRateLimitKey),
		// CONF-9: IP-keyed, mounted before the auth guard by the handler.
		PreAuthLimiter: mw.NewRateLimitMiddleware(resolved.RateLimitConfig.IntrospectionLimit, "oauth-introspection-preauth"),
	})
	handlers.RegisterRevocationRoutes(router, handlers.RevocationHandlerDeps{
		IntrospectionService:   resolved.IntrospectionService,
		SessionRevoker:         resolved.SessionRevoker,
		TokenRevocationService: resolved.TokenRevocationService,
		RefreshTokenService:    resolved.RefreshTokenService,
		ClientAuth:             resolved.OAuthClientAuth,
		Audit:                  resolved.Audit,
		StartupReport:          resolved.StartupReport,
		// CONF-7: mounted BEFORE the client-auth guard inside the handler, so
		// it bounds FAILED authentications too — which is the point, since the
		// guard aborts and a limiter behind it never sees a wrong secret.
		// NOTE: because it runs pre-auth, oauthClientRateLimitKey always
		// returns "" here and the bucket is PER IP, never per client. The key
		// function is passed for symmetry and future-proofing only. Noop when
		// RateLimitConfig is zero-value.
		Limiter: mw.NewRateLimitMiddlewareWithKeyFn(resolved.RateLimitConfig.RevocationLimit, "oauth-revocation", oauthClientRateLimitKey),
	})
	handlers.RegisterUserinfoRoutes(router, handlers.UserinfoHandlerDeps{
		IntrospectionService: resolved.IntrospectionService,
		Audit:                resolved.Audit,
		// CONF-10: the SAME liveness verdict the bearer middleware applies, so
		// the access_token FORM-FIELD door (which bypasses that middleware by
		// design) cannot admit a banned user the header door refuses. One
		// construction site: mw.NewSessionSubjectResolver.
		SubjectResolver: mw.NewSessionSubjectResolver(resolved.SessionLookup),
		// profile-scope claims (`name`) come from the user record; nil
		// (a composition without a user lookup) omits them.
		UserLookup: resolved.UserLookup,
		// THE-PROFILE-CLAIMS: the remaining §5.1 profile claims come from
		// the optional profile row; nil omits them (never a placeholder).
		ProfileLookup: profileLookupFor(resolved),
	})
}

// profileLookupFor returns the profile read seam, or a true nil interface
// when no UserProfileService is wired — a typed-nil pointer inside the
// interface would pass the handlers' nil checks and then dereference.
func profileLookupFor(resolved OSSRouterDeps) handlers.ProfileByUserLookup {
	if resolved.UserProfileService == nil {
		return nil
	}
	return resolved.UserProfileService
}

// oauthClientRateLimitKey buckets an OAuth request by the authenticated
// client (planted in context by mw.RequireOAuthClient). Returning "" when
// no client is present makes NewRateLimitMiddlewareWithKeyFn fall back to
// the client IP, so a request is never un-bucketed.
func oauthClientRateLimitKey(c *gin.Context) string {
	if client, ok := mw.AuthenticatedClientFromContext(c); ok && client != nil {
		return client.ClientID
	}
	return ""
}

func mountToken(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.TokenService == nil || resolved.OAuthClientAuth == nil {
		return
	}
	handlers.RegisterTokenRoutes(router, handlers.TokenHandlerDeps{
		TokenService:    resolved.TokenService,
		ClientAuth:      resolved.OAuthClientAuth,
		Audit:           resolved.Audit,
		AuthCodeService: resolved.AuthorizationCodeService,
		UserToken:       resolved.UserToken,
		UserLookup:      resolved.UserLookup,
		SessionLookup:   resolved.SessionLookup,
		// CONF-9: IP-keyed, mounted before the auth guard by the handler.
		PreAuthLimiter: mw.NewRateLimitMiddleware(resolved.RateLimitConfig.TokenLimit, "oauth-token-preauth"),
		OrgLookup:      resolved.OrganizationRepo,
		IDToken:        resolved.IDTokenService,
		UserSession:    resolved.UserSessionService,
		// offline_access mints an OAuth refresh token (the kind the
		// refresh_token grant consumes) when this is wired.
		RefreshTokens: resolved.RefreshTokenService,
		// THE-PROFILE-CLAIMS: profile-family id_token claims read the
		// optional profile row.
		ProfileLookup: profileLookupFor(resolved),
		StartupReport: resolved.StartupReport,
		// Per-client token-endpoint rate limit (generous). Noop when
		// RateLimitConfig is zero-value (matching login/register).
		Limiter: mw.NewRateLimitMiddlewareWithKeyFn(resolved.RateLimitConfig.TokenLimit, "oauth-token", oauthClientRateLimitKey),
	})
}

func mountAuthorize(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.AuthorizeService == nil {
		return
	}
	handlers.RegisterAuthorizeRoutes(router, handlers.AuthorizeHandlerDeps{
		AuthorizeService: resolved.AuthorizeService,
		CookieSession:    resolved.CookieSession,
		Audit:            resolved.Audit,
		RequestObjects:   resolved.RequestObjectService,
	})
}

// mountOIDCLogin mounts the always-public upstream-OIDC login-initiation
// endpoint. Nil service ⇒ the route is absent (optional feature), matching the
// browser-login guard.
func mountOIDCLogin(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.OIDCLoginService == nil {
		return
	}
	handlers.RegisterOIDCLoginRoutes(router, handlers.OIDCLoginHandlerDeps{
		OIDCLogin: resolved.OIDCLoginService,
		Audit:     resolved.Audit,
	})
}

// mountOIDCCallback mounts the always-public upstream-OIDC callback endpoint.
// Nil service OR nil CookieSession ⇒ the route is absent (login cannot complete
// without the session-cookie tail). BrowserTokens is optional (same cookie
// indirection as browser login).
func mountOIDCCallback(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.OIDCCallbackService == nil || resolved.CookieSession == nil {
		return
	}
	handlers.RegisterOIDCCallbackRoutes(router, handlers.OIDCCallbackHandlerDeps{
		OIDCCallback:  resolved.OIDCCallbackService,
		CookieSession: resolved.CookieSession,
		BrowserTokens: resolved.BrowserTokens,
		Audit:         resolved.Audit,
	})
}

func mountBrowserLogin(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.LocalLogin == nil || resolved.CookieSession == nil {
		return
	}
	handlers.RegisterBrowserLoginRoutes(router, handlers.BrowserLoginHandlerDeps{
		LocalLogin:    resolved.LocalLogin,
		CookieSession: resolved.CookieSession,
		CSRF:          resolved.CSRF,
		BrowserTokens: resolved.BrowserTokens,
		Audit:         resolved.Audit,
	})
	// THE-HONEST-ACR: the TOTP step-up ceremony /authorize refers to when
	// acr_values asks for the password+TOTP rung. Needs the cookie session,
	// the MFA verifier and the session store (RecordACRUplift).
	if resolved.MFAVerifier == nil || resolved.SessionRepo == nil {
		return
	}
	handlers.RegisterStepUpRoutes(router, handlers.StepUpHandlerDeps{
		CookieSession: resolved.CookieSession,
		CSRF:          resolved.CSRF,
		Verifier:      resolved.MFAVerifier,
		Sessions:      resolved.SessionRepo,
		Audit:         resolved.Audit,
	})
	// THE-PHISHING-RESISTANT-ACR: the passkey step-up ceremony (WebAuthn
	// assertion on the SAME browser session). Needs the WebAuthn service.
	if resolved.WebAuthnService == nil {
		return
	}
	handlers.RegisterPasskeyStepUpRoutes(router, handlers.PasskeyStepUpHandlerDeps{
		CookieSession: resolved.CookieSession,
		WebAuthn:      resolved.WebAuthnService,
		Sessions:      resolved.SessionRepo,
		Audit:         resolved.Audit,
	})
}

func mountConsent(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.ConsentService == nil ||
		resolved.AuthorizeService == nil ||
		resolved.CookieSession == nil ||
		resolved.ClientService == nil {
		return
	}
	handlers.RegisterConsentRoutes(router, handlers.ConsentHandlerDeps{
		ConsentService:   resolved.ConsentService,
		AuthorizeService: resolved.AuthorizeService,
		CookieSession:    resolved.CookieSession,
		Clients:          resolved.ClientService,
		CSRF:             resolved.CSRF,
		Audit:            resolved.Audit,
	})
}

func mountFrontchannelLogout(router gin.IRouter, resolved OSSRouterDeps) {
	if !resolved.FrontchannelLogoutEnabled ||
		resolved.CookieSession == nil ||
		resolved.UserSessionService == nil {
		return
	}
	var clients handlers.ConsentClientLookup
	if resolved.ClientService != nil {
		clients = resolved.ClientService
	}
	handlers.RegisterFrontchannelLogoutRoutes(router, handlers.FrontchannelLogoutHandlerDeps{
		CookieSession: resolved.CookieSession,
		UserSession:   resolved.UserSessionService,
		Clients:       clients,
		Issuer:        server.ResolveDiscoveryConfig(resolved.DiscoveryConfig).Issuer,
		Audit:         resolved.Audit,
	})
}

func mountBackchannelDeliveries(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.BackchannelDeliveryAdminService == nil {
		return
	}
	handlers.RegisterBackchannelDeliveriesRoutes(router, handlers.BackchannelDeliveriesHandlerDeps{
		Admin: resolved.BackchannelDeliveryAdminService,
		Audit: resolved.Audit,
	})
}

func mountEndSession(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.CookieSession == nil || resolved.UserSessionService == nil {
		return
	}
	var clients handlers.ConsentClientLookup
	if resolved.ClientService != nil {
		clients = resolved.ClientService
	}
	handlers.RegisterEndSessionRoutes(router, handlers.EndSessionHandlerDeps{
		CookieSession:       resolved.CookieSession,
		UserSession:         resolved.UserSessionService,
		Clients:             clients,
		IDTokenVerifier:     resolved.IDTokenVerifier,
		BackchannelDelivery: resolved.BackchannelLogoutService,
		BrowserTokens:       resolved.BrowserTokens,
		Audit:               resolved.Audit,
	})
}

// resolvedDeps fills in zero-value defaults so handlers never have
// to check for nil. The original struct is returned by value with
// no mutation.
func resolvedDeps(d OSSRouterDeps) OSSRouterDeps {
	if d.Version == "" {
		d.Version = "identuum-idp-oss (unknown version)"
	}
	if d.JWKSProvider == nil {
		d.JWKSProvider = server.EmptyJWKSProvider{}
	}
	if d.Audit == nil {
		d.Audit = audit.NoopService{}
	}
	if d.FeatureGate == nil {
		d.FeatureGate = features.OpenGate{}
	}
	return d
}

// systemInfoHandler returns the spec-compliant minimal liveness
// surface (per monolith §7.11): just enough to confirm the binary
// is up without exposing deployment enumeration.
func systemInfoHandler(deps OSSRouterDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"version": deps.Version,
			"mode":    "oss",
			// The build-provenance announce (STALE-BINARY-1): the commit
			// this binary was built from, so the dev smoke can refuse a
			// process that does not match the working tree.
			"build_commit": buildinfo.Commit,
		})
	}
}

// componentHandler returns the UI-facing discovery contract for
// product/API capability facts. It is intentionally static for OSS:
// these are not per-user permissions, tenant settings, license
// envelopes, or environment-derived deployment details.
func componentHandler(deps OSSRouterDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"component":                     "identuum-idp",
			"product":                       "identuum-idp-oss",
			"version":                       deps.Version,
			"status":                        "ok",
			"capability_map_schema_version": "idp-capabilities.v1",
			"capabilities": gin.H{
				"identity_provider":           true,
				"component_discovery":         true,
				"license_status":              true,
				"auth_provider_discovery":     true,
				"account_self_service":        true,
				"user_sessions":               true,
				"mfa":                         true,
				"webauthn":                    true,
				"authorization_server":        true,
				"oauth_clients":               true,
				"api_resources":               true,
				"service_accounts":            true,
				"scope_templates":             true,
				"org_roles":                   true,
				"protocol_settings":           true,
				"client_credentials":          true,
				"dynamic_client_registration": true,
				"scim":                        false,
				"audit_log":                   true,
				"audit_chain":                 false,
				"reporting":                   false,
				"anomaly_detection":           false,
				"observability":               false,
			},
			"auth": gin.H{
				"authority":     "identuum-idp",
				"provider_mode": "local",
			},
			"license": gin.H{
				"status":          "valid",
				"product":         "identuum-idp-oss",
				"tier":            "starter",
				"deployment_mode": "self_hosted",
				"license_type":    "oss",
				"expires_at":      nil,
				"days_remaining":  nil,
			},
		})
	}
}

// healthHandler is the longer-form health surface for
// load-balancer probes. Retained for backward compatibility with
// existing LB health checks; new callers should target
// /system/info.
func healthHandler(deps OSSRouterDeps) gin.HandlerFunc {
	report := deps.StartupReport
	return func(c *gin.Context) {
		// P-018 readiness contract. The probe never depends on the
		// faulted components — it reads only the StartupReport — so it
		// stays answerable in NOT-SERVING mode. report is nil-safe:
		// HasFatal/Faults return the healthy default when unwired.
		faults := report.Faults()
		switch {
		case report.HasFatal():
			// NOT-SERVING: at least one fatal startup fault.
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":  "not_serving",
				"version": deps.Version,
				"mode":    "oss",
				"tier":    "starter",
				"faults":  faults,
			})
		case len(faults) > 0:
			// Serving, but an optional surface is degraded.
			c.JSON(http.StatusOK, gin.H{
				"status":  "degraded",
				"version": deps.Version,
				"mode":    "oss",
				"tier":    "starter",
				"faults":  faults,
			})
		default:
			c.JSON(http.StatusOK, gin.H{
				"status":  "healthy",
				"version": deps.Version,
				"mode":    "oss",
				"tier":    "starter",
			})
		}
	}
}

// livezHandler is the P-018 liveness probe: it reports only that the
// process is up and answering, independent of serving mode. It stays 200
// in NOT-SERVING mode so orchestrators do not kill+restart a process
// that is intentionally staying alive to alert (live, but not ready —
// readiness is /health).
func livezHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "live"})
	}
}

// discoveryHandler serves the OSS OIDC discovery document. Reuses
// server.DiscoveryDocument so the signing-algorithm policy lives
// in exactly one place across the net/http smoke handler and this
// Gin scaffold.
//
// Endpoints that are conditionally registered (introspection,
// revocation) are advertised ONLY when their backing service is
// wired. token_endpoint_auth_methods_supported is filtered the
// same way: client_secret_basic + client_secret_post appear only
// when OAuthClientAuth is supplied.
func discoveryHandler(deps OSSRouterDeps) gin.HandlerFunc {
	body := server.DiscoveryDocument(deps.DiscoveryConfig)
	// Resolve issuer so we can synthesize endpoint URLs that
	// match the same prefix /.well-known/openid-configuration is
	// served under. ResolveDiscoveryConfig handles the empty-issuer
	// → localhost fallback.
	resolved := server.ResolveDiscoveryConfig(deps.DiscoveryConfig)
	// Pre-compute the auth-methods slice once — the same set
	// applies to token / introspection / revocation endpoints
	// because mw.RequireOAuthClient is the single chokepoint.
	authMethods := []string{}
	if deps.OAuthClientAuth != nil {
		authMethods = append(authMethods, "client_secret_basic", "client_secret_post")
		if hasJWTAssertion(deps.OAuthClientAuth) {
			authMethods = append(authMethods, "private_key_jwt")
		}
	}
	if deps.IntrospectionService != nil {
		body["introspection_endpoint"] = resolved.Issuer + "/api/v1/oauth/introspection"
		body["revocation_endpoint"] = resolved.Issuer + "/api/v1/oauth/revoke"
		if len(authMethods) > 0 {
			body["introspection_endpoint_auth_methods_supported"] = authMethods
			body["revocation_endpoint_auth_methods_supported"] = authMethods
		}
		// Userinfo is registered side-by-side with introspection in
		// RegisterOSSRoutes; advertise its endpoint here so OIDC
		// discovery callers can find it without scraping the router.
		body["userinfo_endpoint"] = resolved.Issuer + "/api/v1/oidc/userinfo"
	}
	if deps.TokenService != nil && deps.OAuthClientAuth != nil {
		// token_endpoint is OVERRIDING the static placeholder from
		// server.DiscoveryDocument with the LIVE OSS path. The
		// placeholder remains for deployments without a TokenService
		// wired — operators reading the document at boot can still
		// see the canonical OAuth URL shape, but the actual route is
		// only registered when this branch executes.
		body["token_endpoint"] = resolved.Issuer + "/api/v1/oauth/token"
		body["token_endpoint_auth_methods_supported"] = authMethods
		grants := []string{"client_credentials"}
		if deps.TokenService.HasRefreshTokenGrant() && deps.RefreshTokenService != nil {
			grants = append(grants, "refresh_token")
		}
		// authorization_code is advertised ONLY when the full
		// upstream chain is live: /authorize handler (so callers can
		// actually obtain a code) AND every dep the token-side grant
		// needs to consume the code and mint an access token. ID
		// token issuance is independent — OIDC discovery advertises
		// the grant regardless of openid scope support; the
		// id_token_signing_alg_values_supported field tells callers
		// whether ID tokens are issuable.
		hasAuthCodeGrant := deps.AuthorizeService != nil &&
			deps.AuthorizationCodeService != nil &&
			deps.UserToken != nil &&
			deps.UserLookup != nil &&
			deps.SessionLookup != nil
		if hasAuthCodeGrant {
			grants = append(grants, "authorization_code")
			body["authorization_endpoint"] = resolved.Issuer + "/api/v1/oauth/authorize"
			body["response_types_supported"] = []string{"code"}
			body["code_challenge_methods_supported"] = []string{"S256"}
			// THE-ADDRESS-PHONE-CLAIMS: address and phone are modeled on
			// user_profiles and released consent-gated like profile/email.
			scopes := []string{"openid", "profile", "email", "address", "phone"}
			// offline_access is advertised only when the auth-code
			// grant can actually mint a refresh token — i.e. the
			// UserSessionService is wired into the token endpoint.
			if deps.UserSessionService != nil {
				scopes = append(scopes, "offline_access")
			}
			body["scopes_supported"] = scopes
			// THE-PKCE-DECISION (owner ruling, verbatim): "Add RS256
			// into the list BUT DO NOT USE except testing and put this
			// into documentation CLEARLY." RS256 is a real capability —
			// key, JWKS, id_token signing — but fires ONLY on an
			// explicit per-client id_token_signed_response_alg=RS256
			// registration; EdDSA stays the default. Testing-only:
			// docs/TESTING-OPERATORS.md. Must stay in sync with
			// domain.IDTokenSigningAlgorithms and the smoke-handler list
			// in internal/server/smoke.go.
			body["id_token_signing_alg_values_supported"] = []string{"EdDSA", "ES256", "RS256"}
			body["subject_types_supported"] = []string{"public"}
			// claims_supported enumerates the claims the OP actually
			// emits — in the id_token (IDTokenService) or at userinfo
			// (HandleUserinfo) — nothing it cannot supply. Same gate as
			// id_token_signing_alg_values_supported — only advertised
			// when the auth-code grant chain is live.
			body["claims_supported"] = []string{
				"sub", "iss", "aud", "exp", "iat", "jti",
				"auth_time", "nonce", "acr", "amr",
				// OIDC Core §5.1 profile family (THE-PROFILE-CLAIMS):
				// modeled on user_profiles, emitted only when set.
				"name", "given_name", "family_name", "middle_name", "nickname",
				"preferred_username", "profile", "picture", "website", "gender",
				"birthdate", "zoneinfo", "locale", "updated_at",
				"email", "email_verified",
				// THE-ADDRESS-PHONE-CLAIMS: address (§5.1.1 object, set
				// members only), phone_number, and phone_number_verified
				// (always false — no verification event exists; emitted
				// only alongside phone_number).
				"address", "phone_number", "phone_number_verified",
				"organization_id", "role",
			}
			// THE-CLAIMS-PARAMETER: the OIDC Core §5.5 `claims` request
			// parameter is honored for the emittable identity claims
			// (domain.EmittableIdentityClaims), consent-gated and
			// role-intersected; unknown claims are ignored per §5.5.1.
			body["claims_parameter_supported"] = true
			// THE-HONEST-ACR (owner ruling): advertise ONLY the contexts a
			// local login actually performs — password, and password+TOTP.
			// A request for one of them is honored (step-up when the
			// session is below and TOTP is enrolled) or refused with
			// unmet_authentication_requirements; the id_token acr is
			// always the context performed, never the one requested.
			body["acr_values_supported"] = service.AdvertisedACRValues()
			// Identuum issuance posture beyond the three listed: never
			// `none`, never HS*, never RS384/512 or PS*. Asserted in
			// tests as well.
		}
		// end_session_endpoint is advertised only when the OSS
		// logout route is live (CookieSession + UserSession both
		// wired). Frontchannel/backchannel logout remain
		// unadvertised — they are not implemented.
		if deps.CookieSession != nil && deps.UserSessionService != nil {
			body["end_session_endpoint"] = resolved.Issuer + "/api/v1/oidc/logout"
			// frontchannel_logout_supported flips to true ONLY
			// when the frontchannel-logout route is live (which
			// requires explicit operator opt-in via
			// FrontchannelLogoutEnabled). frontchannel_logout_session
			// _supported stays false until per-client sid round-
			// tripping is wired in a follow-up slice.
			body["frontchannel_logout_supported"] = deps.FrontchannelLogoutEnabled
			// frontchannel_logout_session_supported reports
			// whether the OP appends `iss` + `sid` to the
			// iframe URL for clients that opt in via
			// `frontchannel_logout_session_required`. We can
			// emit those parameters as long as the frontchannel
			// route is live AND the discovery composer can
			// resolve an issuer (it always can — discovery
			// itself needs one).
			body["frontchannel_logout_session_supported"] = deps.FrontchannelLogoutEnabled
			// backchannel_logout_supported flips to true only
			// when the BackchannelLogoutService delivery path is
			// wired (the per-client backchannel_logout_uri
			// metadata now exists on oauth_clients).
			body["backchannel_logout_supported"] = deps.BackchannelLogoutService != nil
			// backchannel_logout_session_supported reports
			// whether the OP can include the `sid` claim — true
			// iff the delivery path is wired (the
			// BackchannelLogoutService honors the client's
			// BackchannelLogoutSessionRequired flag).
			body["backchannel_logout_session_supported"] = deps.BackchannelLogoutService != nil
		}
		body["grant_types_supported"] = grants
		if hasJWTAssertion(deps.OAuthClientAuth) {
			// OIDC Discovery 1.0 §3 — this field describes the
			// JWS algorithms the OP accepts on INBOUND
			// `private_key_jwt` client-authentication assertions
			// from registered confidential clients. It is the
			// per-client `token_endpoint_auth_signing_alg` matrix
			// reflected up to discovery.
			//
			// It is NOT the OP's OUTBOUND issuance posture:
			// access tokens, ID tokens, and logout_tokens are
			// always signed with EdDSA or ES256 (see
			// `id_token_signing_alg_values_supported`). RS256 is
			// listed here only because a confidential client
			// MAY authenticate to the token endpoint using an
			// RS256 assertion — the OP verifies it, then mints
			// its own non-RS256 response tokens.
			body["token_endpoint_auth_signing_alg_values_supported"] = service.PrivateKeyJWTAssertionAlgorithms
		}
	}
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, body)
	}
}

// hasJWTAssertion reports whether the wired OAuth client
// authenticator also implements the assertion path (the
// private_key_jwt seam in service.OAuthClientAuthService).
func hasJWTAssertion(authn mw.OAuthClientAuthenticator) bool {
	if authn == nil {
		return false
	}
	type hasAssertion interface {
		HasAssertionValidator() bool
	}
	if h, ok := authn.(hasAssertion); ok {
		return h.HasAssertionValidator()
	}
	return false
}

// jwksHandler serves the public JWKS. Provider errors surface as
// 500 + generic body; provider-internal error text never reaches
// the client. Per-request timeout matches the smoke handler.
func jwksHandler(deps OSSRouterDeps) gin.HandlerFunc {
	provider := deps.JWKSProvider
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), jwksFetchTimeout)
		defer cancel()
		set, err := provider.PublicJWKS(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		// Use the response writer directly so we re-encode through
		// the same encoder/buffer path the net/http smoke handler
		// uses. Gin's c.JSON would also serialise correctly, but
		// going through encoding/json keeps the byte-level shape
		// identical for snapshot tests.
		c.Header("Content-Type", "application/json")
		c.Status(http.StatusOK)
		_ = json.NewEncoder(c.Writer).Encode(set)
	}
}
