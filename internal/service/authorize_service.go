// Package service — AuthorizeService validates an OAuth 2.0 /
// OIDC /authorize request and, on success, issues an authorization
// code through AuthorizationCodeService. The OSS slice supports
// response_type=code only and PKCE S256 only (the OAuth 2.1 baseline).
//
// What the service WILL NOT do:
//
//   - Render HTML. The handler decides between 302-redirect and 400-
//     direct based on the sentinel kind. There is no consent screen
//     in this slice — see Authorize.Consent semantics below.
//   - Authenticate the caller. The handler extracts the bearer
//     principal via mw.BearerPrincipal + mw.PrincipalFromContext
//     before calling Authorize. The service receives a
//     *domain.Principal and trusts the verified JWT signature.
//   - Set cookies. /authorize is bearer-driven in OSS; cookie-based
//     browser sessions are deferred to a future slice.
//
// Consent model (this slice):
//
//	The OSS slice supports the pre-approved-only path. The client's
//	SkipConsent flag (already present on domain.Client) gates the
//	code issuance:
//
//	  - SkipConsent = true  → code is issued (no consent UI shown).
//	  - SkipConsent = false → ErrAuthorizeConsentRequired is returned;
//	                          the handler maps it to a redirect with
//	                          error=consent_required, leaving the
//	                          interactive consent screen for a future
//	                          slice that lands the HTML form +
//	                          oauth_consents persistence.
//
//	This mirrors the monolith's shouldSkipConsent fast path
//	(handler_oidc_consent_helper.go) but stops short of the
//	stored-consent lookup. A "trusted first-party app" is exactly
//	what SkipConsent already means in the OSS domain layer.
package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// AuthorizeService validates and codes an /authorize request.
type AuthorizeService struct {
	clients   AuthorizeClientLookup
	audiences AudienceLookup
	sessions  AuthorizeSessionLookup
	orgs      OrgLiveLookup
	consent   *ConsentService
	codes     *AuthorizationCodeService
	issuer    string
	now       func() time.Time
}

// AuthorizeClientLookup is the seam the service consults to resolve
// client_id → *domain.Client. *ClientService satisfies it via
// GetClientByClientID.
type AuthorizeClientLookup interface {
	GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// AuthorizeSessionLookup is the optional seam used to verify the
// caller's session is still live (not revoked, not expired) at
// /authorize time. Without it, the service trusts the bearer JWT's
// signature/expiry verification done upstream by the bearer middleware.
type AuthorizeSessionLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error)
}

// OrgLiveLookup resolves organization_id → *domain.Organization so an
// auth/issuance path can refuse a credential whose tenant is no longer
// operational (domain.Organization.IsOperational: deleted_at IS NULL AND
// active). It is the SAME seam the P0-1/P0-2 token-exchange fix uses
// (handlers.OrganizationByIDLookup); *PgxOrganizationRepository satisfies
// it via GetByID (whose SQL already filters to operational orgs, so a nil
// result likewise means "not operational"). Shared by AuthorizeService,
// CookieSessionService, and OIDCCallbackService so tenant-liveness uses
// ONE predicate everywhere.
type OrgLiveLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error)
}

// AuthorizeServiceOptions configures the AuthorizeService. Issuer is
// required (RFC 9207 `iss` redirect parameter).
type AuthorizeServiceOptions struct {
	Issuer string
}

// NewAuthorizeService builds the service. clients + codes + issuer
// are required. audiences and sessions are optional.
func NewAuthorizeService(report *lifecycle.StartupReport, clients AuthorizeClientLookup, codes *AuthorizationCodeService, opts AuthorizeServiceOptions) *AuthorizeService {
	if clients == nil {
		report.Fatal("NewAuthorizeService", "service: NewAuthorizeService requires a non-nil client lookup")
	}
	if codes == nil {
		report.Fatal("NewAuthorizeService", "service: NewAuthorizeService requires a non-nil AuthorizationCodeService")
	}
	if opts.Issuer == "" {
		report.Fatal("NewAuthorizeService", "service: NewAuthorizeService requires a non-empty Issuer")
	}
	return &AuthorizeService{
		clients: clients,
		codes:   codes,
		issuer:  opts.Issuer,
		now:     time.Now,
	}
}

// WithAudienceLookup composes the RFC 8707 audience validation seam.
func (s *AuthorizeService) WithAudienceLookup(a AudienceLookup) *AuthorizeService {
	s.audiences = a
	return s
}

// WithSessionLookup composes the session-revocation-check seam.
func (s *AuthorizeService) WithSessionLookup(l AuthorizeSessionLookup) *AuthorizeService {
	s.sessions = l
	return s
}

// WithOrganizationLookup composes the tenant-liveness seam. When wired,
// Authorize refuses to mint a code for a principal whose organization is
// not operational (P0-5).
func (s *AuthorizeService) WithOrganizationLookup(o OrgLiveLookup) *AuthorizeService {
	s.orgs = o
	return s
}

// WithConsentService composes the remembered-consent seam. When
// wired, /authorize bypasses ErrAuthorizeConsentRequired iff
// ConsentService.Lookup reports Covered=true for the requested
// scope. Without it, the slice's pre-approved-only (SkipConsent)
// path is the only consent gate.
func (s *AuthorizeService) WithConsentService(c *ConsentService) *AuthorizeService {
	s.consent = c
	return s
}

// AuthorizeRequest carries every input the service needs. The
// handler populates it from query-string parameters + the bearer
// principal.
type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	Audience            string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string

	// Principal is the authenticated user (populated upstream by
	// the bearer middleware). Required.
	Principal *domain.Principal
}

// AuthorizeResult is what the handler returns to the user-agent on
// success. RedirectURL is a fully-formed absolute URL with code +
// state + iss appended.
type AuthorizeResult struct {
	RedirectURL string
	Code        string
	State       string
	ExpiresAt   time.Time
	ClientID    string
}

// Sentinel errors. The handler maps each to either a 302 redirect
// (with redirect_uri + error + state) or a 400 direct response. The
// "redirect-safe" set requires a validated redirect_uri.
var (
	// Direct-400 sentinels (redirect_uri NOT yet validated).
	ErrAuthorizeMissingParameters  = errors.New("service: authorize missing required parameters")
	ErrAuthorizeInvalidClient      = errors.New("service: authorize invalid_client")
	ErrAuthorizeInvalidRedirectURI = errors.New("service: authorize invalid_redirect_uri")

	// Redirect-safe sentinels (the handler builds a Location URL
	// with error= + state= against the validated redirect_uri).
	ErrAuthorizeUnsupportedResponseType = errors.New("service: authorize unsupported_response_type")
	ErrAuthorizeUnsupportedChallenge    = errors.New("service: authorize unsupported PKCE method")
	// ErrAuthorizeInvalidScope is intentionally NOT returned by Authorize:
	// per RFC 6749 §3.3 (and R6) the service CLAMPS the requested scope to
	// the client's registered set (see ClampScopeToRegistered) rather than
	// rejecting an over-broad request. The sentinel is retained for the
	// handler's error-mapping table (and a possible future hard-reject mode);
	// it is a deliberately unused-by-the-service value, not dead code to
	// remove from the mapping.
	ErrAuthorizeInvalidScope    = errors.New("service: authorize invalid_scope")
	ErrAuthorizeInvalidTarget   = errors.New("service: authorize invalid_target")
	ErrAuthorizeLoginRequired   = errors.New("service: authorize login_required")
	ErrAuthorizeConsentRequired = errors.New("service: authorize consent_required")
	ErrAuthorizeServerError     = errors.New("service: authorize server_error")
)

// Authorize runs the request through the validation pipeline. On
// success it returns an AuthorizeResult; on failure it returns one
// of the sentinels above.
//
// Validation order (RFC 6749 §3.1.2 + OIDC Core §3.1.2):
//
//  1. Required parameters present (client_id + redirect_uri +
//     code_challenge).
//  2. Client lookup. Unknown client_id → ErrAuthorizeInvalidClient
//     (400 direct).
//  3. Redirect URI exact-match against client allowlist. Mismatch →
//     ErrAuthorizeInvalidRedirectURI (400 direct).
//  4. Now in the redirect-safe phase. From here, every error returns
//     302 with error=... + state=...
//  5. response_type validation (code only).
//  6. PKCE code_challenge_method == "S256".
//  7. Audience validation (when wired).
//  8. Principal must be authenticated (UserID, SessionID, Email).
//     Missing → ErrAuthorizeLoginRequired (login_required).
//  9. Session validity check (when SessionLookup is wired).
//
// 10. SkipConsent gate. SkipConsent==false → consent_required.
// 11. Code creation via AuthorizationCodeService.Create.
// 12. Build the redirect URL.
func (s *AuthorizeService) Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResult, error) {
	// Phase 1: pre-redirect-uri validation. Direct 400 on failure.
	if strings.TrimSpace(req.ClientID) == "" || strings.TrimSpace(req.RedirectURI) == "" {
		return nil, ErrAuthorizeMissingParameters
	}
	client, err := s.clients.GetClientByClientID(ctx, req.ClientID)
	if err != nil || client == nil {
		return nil, ErrAuthorizeInvalidClient
	}
	if !client.IsRedirectURIAllowed(req.RedirectURI) {
		return nil, ErrAuthorizeInvalidRedirectURI
	}

	// Phase 2: redirect-safe validation.
	rt := strings.TrimSpace(req.ResponseType)
	if rt == "" {
		rt = "code"
	}
	if rt != "code" {
		return nil, ErrAuthorizeUnsupportedResponseType
	}
	if strings.TrimSpace(req.CodeChallenge) == "" {
		return nil, ErrAuthorizeMissingParameters
	}
	method := req.CodeChallengeMethod
	if method == "" {
		method = "S256"
	}
	if method != "S256" {
		return nil, ErrAuthorizeUnsupportedChallenge
	}

	// Audience validation. Only when both an audience is supplied
	// AND a lookup is wired. Otherwise we leave the audience for
	// the token endpoint to police (it already does).
	if s.audiences != nil && strings.TrimSpace(req.Audience) != "" {
		res, lookupErr := s.audiences.LookupAudience(ctx, req.Audience)
		if lookupErr != nil || res == nil {
			return nil, ErrAuthorizeInvalidTarget
		}
	}

	// Phase 3: caller must be authenticated.
	if req.Principal == nil ||
		req.Principal.UserID == uuid.Nil ||
		req.Principal.SessionID == uuid.Nil {
		return nil, ErrAuthorizeLoginRequired
	}

	if s.sessions != nil {
		session, sessErr := s.sessions.GetByID(ctx, req.Principal.SessionID)
		if sessErr != nil || session == nil {
			return nil, ErrAuthorizeLoginRequired
		}
		if canUse, _ := session.CanBeUsed(s.now().UTC()); !canUse {
			return nil, ErrAuthorizeLoginRequired
		}
	}

	// P0-5: tenant deletion is an authentication boundary. Re-check the
	// principal's organization is operational IMMEDIATELY before minting a
	// code. A site_admin principal carries a nil org (no tenant to gate).
	// Same predicate as the token-exchange fix (IsOperational).
	if s.orgs != nil && req.Principal.OrganizationID != uuid.Nil {
		org, orgErr := s.orgs.GetByID(ctx, req.Principal.OrganizationID)
		if orgErr != nil || org == nil || !org.IsOperational() {
			return nil, ErrAuthorizeLoginRequired
		}
	}

	// R6: clamp the requested scope to the client's registered scope set
	// (RFC 6749 §3.3 — the AS may issue a narrower scope than requested),
	// reusing the already-loaded client (no extra query). Only scopes the
	// client is registered for survive the intersection; unregistered
	// scopes — INCLUDING openid / offline_access — are dropped so they
	// cannot drive id_token or refresh issuance. The clamped scope flows
	// into BOTH the consent lookup (Phase 4) and the minted code (Phase 5),
	// so the token-response scope reflects exactly what was granted. A
	// client with NO registered scopes is treated as unrestricted
	// (pass-through) rather than locked out — see ClampScopeToRegistered.
	req.Scope = ClampScopeToRegistered(req.Scope, client.Scope)

	// Phase 4: consent gate. The order is:
	//
	//   1. prompt=consent always forces the consent page.
	//   2. client.SkipConsent==true bypasses the gate (trusted
	//      first-party).
	//   3. ConsentService.Lookup reports Covered=true → bypass.
	//   4. Otherwise → ErrAuthorizeConsentRequired (handler routes
	//      to the consent page or, with prompt=none, returns the
	//      consent_required redirect error).
	if strings.EqualFold(req.Prompt, "consent") {
		return nil, ErrAuthorizeConsentRequired
	}
	if !client.SkipConsent {
		if s.consent == nil {
			return nil, ErrAuthorizeConsentRequired
		}
		decision, err := s.consent.Lookup(ctx, req.Principal.UserID, req.ClientID, req.Audience, req.Scope)
		if err != nil || decision == nil || !decision.Covered {
			return nil, ErrAuthorizeConsentRequired
		}
	}

	// Phase 5: mint the authorization code.
	orgPtr := orgIDPtr(req.Principal.OrganizationID)
	created, err := s.codes.Create(ctx, CreateAuthorizationCodeInput{
		ClientID:            req.ClientID,
		UserID:              req.Principal.UserID,
		OrganizationID:      orgPtr,
		SessionID:           req.Principal.SessionID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Audience:            req.Audience,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: method,
		Nonce:               req.Nonce,
	})
	if err != nil {
		// AuthorizationCodeService input errors are programmer
		// bugs (we just constructed the input). Map everything
		// to server_error.
		switch {
		case errors.Is(err, ErrAuthCodeUnsupportedChallenge):
			return nil, ErrAuthorizeUnsupportedChallenge
		case errors.Is(err, ErrAuthCodeInvalidInput):
			return nil, ErrAuthorizeMissingParameters
		default:
			return nil, ErrAuthorizeServerError
		}
	}

	// Phase 6: build the redirect URL.
	redirectURL, buildErr := s.buildRedirect(req.RedirectURI, created.Code, req.State)
	if buildErr != nil {
		return nil, ErrAuthorizeServerError
	}
	return &AuthorizeResult{
		RedirectURL: redirectURL,
		Code:        created.Code,
		State:       req.State,
		ExpiresAt:   created.ExpiresAt,
		ClientID:    req.ClientID,
	}, nil
}

// buildRedirect appends code + state + iss to the supplied
// redirect_uri. RFC 6749 §4.1.2 mandates code + state echo; RFC 9207
// adds iss to defend against mix-up attacks.
func (s *AuthorizeService) buildRedirect(redirectURI, code, state string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ClampScopeToRegistered narrows requested to the intersection with the
// client's registered scope set (registered is the space-separated
// client.Scope field). The result preserves the order of requested and
// keeps only scopes the client is registered for — mirroring the ancestor's
// intersectScopes (RFC 6749 §3.3: the AS may issue a narrower scope than
// requested). It is exported so the consent-submit handler can apply the
// SAME narrowing before persisting consent.
//
// DISPOSITION — empty registered set: a client with NO registered scopes
// (empty client.Scope) is treated as UNRESTRICTED and the request passes
// through unchanged, rather than being clamped to the empty set (which would
// lock out every legacy/unconfigured OSS client that never declared scopes).
// Clients that DO declare a scope set are clamped. This is a deliberate,
// non-breaking deviation from a literal empty-set intersection; the security
// narrowing applies wherever a client actually declares its scopes.
func ClampScopeToRegistered(requested, registered string) string {
	reg := strings.Fields(registered)
	if len(reg) == 0 {
		return requested // unconfigured client ⇒ unrestricted (no clamp)
	}
	allowed := make(map[string]struct{}, len(reg))
	for _, s := range reg {
		allowed[s] = struct{}{}
	}
	var kept []string
	for _, s := range strings.Fields(requested) {
		if _, ok := allowed[s]; ok {
			kept = append(kept, s)
		}
	}
	return strings.Join(kept, " ")
}

// BuildErrorRedirect builds the error redirect URL for one of the
// redirect-safe sentinels. Exposed so the handler can call into the
// service to keep URL construction in one place.
func (s *AuthorizeService) BuildErrorRedirect(redirectURI, errCode, state string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("error", errCode)
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func orgIDPtr(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	cp := id
	return &cp
}
