package service

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// OAuthClientAuthService is the unified OAuth client-auth seam.
// It calls ClientService.AuthenticateClient first; on failure
// AND when the optional APIResourceService is wired, it falls
// back to APIResourceService.AuthenticateAPIResource (treating
// the supplied client_id as the api-resource audience). This
// mirrors the monolith's "client OR api-resource" credential
// chain that drives /api/v1/auth/introspect.
//
// The service is intentionally narrow: it returns a small
// AuthenticatedClient struct that carries only the SAFE identity
// fields needed by downstream handlers (id, name, kind). Raw
// secrets, hashes, JWKS, redirect URIs, and scope assignments are
// NEVER attached.
type OAuthClientAuthService struct {
	clientSvc        *ClientService
	apiResource      *APIResourceService
	assertionVerify  *ClientAssertionValidator
	clientByClientID ClientByClientIDLookup
}

// ClientByClientIDLookup is the seam the assertion path uses to
// resolve a `client_id` form value to a `*domain.Client` record
// (so it can read JWKS / JWKSUri / EffectiveSigningAlg fields).
// *ClientService satisfies it via GetClientByClientID.
type ClientByClientIDLookup interface {
	GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// NewOAuthClientAuthService constructs the service.
// clientSvc is required. apiResource is optional — when nil, the
// api-resource fallback is skipped and only confidential
// /public-clients-with-secret can authenticate.
func NewOAuthClientAuthService(report *lifecycle.StartupReport, clientSvc *ClientService, apiResource *APIResourceService) *OAuthClientAuthService {
	if clientSvc == nil {
		report.Fatal("NewOAuthClientAuthService", "service: NewOAuthClientAuthService requires a non-nil ClientService")
	}
	return &OAuthClientAuthService{clientSvc: clientSvc, apiResource: apiResource}
}

// WithAssertionValidator wires the private_key_jwt assertion
// validator and the client-lookup seam so the service can route
// AuthenticateAssertion calls through it. lookup may be nil — the
// service falls back to clientSvc.GetClientByClientID in that
// case.
//
// Without WithAssertionValidator, AuthenticateAssertion returns
// ErrClientAssertionInvalid for every request — operators that
// have not opted in to JWT client auth keep the pre-this-slice
// behavior (Basic / Post only).
//
// Returns the receiver so the call composes with construction.
func (s *OAuthClientAuthService) WithAssertionValidator(v *ClientAssertionValidator, lookup ClientByClientIDLookup) *OAuthClientAuthService {
	s.assertionVerify = v
	if lookup != nil {
		s.clientByClientID = lookup
	}
	return s
}

// AuthenticatedClient is the safe identity projection of a
// successful credential check. Either Client or APIResourceID is
// populated (never both); the Kind field disambiguates.
//
// Sensitive fields (secret hashes, JWKS, redirect URIs) are
// deliberately omitted. AllowedScopes is the one exception: the
// api-resource path populates it from the resource's declared
// scope set so the TokenService can intersect requested scopes
// against the resource's policy. The oauth_client path leaves
// it nil — there is no per-client scope policy in OSS yet.
type AuthenticatedClient struct {
	Kind     AuthenticatedClientKind
	ClientID string
	// AuthRecordID is the internal UUID of the underlying record
	// (oauth_clients.id or api_resources.id). Callers MUST NOT
	// expose this on the wire — it is for OSS-internal binding
	// only (e.g. token revocation cross-client checks).
	AuthRecordID uuid.UUID
	// Name is the operator-friendly display name (Client.Name or
	// APIResource.Name). Safe for log lines.
	Name string
	// OrganizationID identifies the owning tenant when set.
	// Client.OrganizationID for oauth clients; the equivalent
	// field on api resources. uuid.Nil when not applicable
	// (system clients, cross-tenant resources).
	OrganizationID uuid.UUID
	// IsPublic mirrors domain.Client.IsPublic for the oauth_client
	// path. The api_resource path is always confidential, so the
	// field is false for that kind.
	IsPublic bool
	// AllowedScopes is the set of scope names this identity is
	// authorized to receive on issued tokens. Populated by the
	// api_resource path from APIResource.Scopes; nil for the
	// oauth_client path until per-client scope policy lands. The
	// TokenService MUST intersect requested scopes against this
	// set — never grant a scope not present here.
	AllowedScopes []string
	// IDTokenAlg is the client's effective id_token_signed_response_alg
	// (Client.EffectiveIDTokenAlg — default "EdDSA"). Empty on the
	// api_resource path, which never receives id_tokens. RS256 lands
	// here only via the client's explicit registration —
	// testing-only, never the issuer default (THE-PKCE-DECISION).
	IDTokenAlg string
}

// AuthenticatedClientKind disambiguates client vs api-resource
// auth.
type AuthenticatedClientKind string

const (
	AuthenticatedClientKindOAuth       AuthenticatedClientKind = "oauth_client"
	AuthenticatedClientKindAPIResource AuthenticatedClientKind = "api_resource"
)

// Client-auth method identifiers, matching domain.Client.EffectiveAuthMethod's
// return values for secret-based methods. The middleware reports the OBSERVED
// method; Authenticate requires it to equal the resolved client's registered
// EffectiveAuthMethod, so the strongest method cannot be downgraded (P0-7).
const (
	ClientAuthMethodBasic = "client_secret_basic"
	ClientAuthMethodPost  = "client_secret_post"
)

// Authenticate runs the OAuth-client-then-API-resource fallback
// chain. Returns ErrInvalidOAuthClientCredentials on any failure;
// the failure is opaque to the caller so missing-record and
// wrong-secret are indistinguishable at the wire.
//
// clientID may be either an oauth client_id OR an api-resource
// audience URL — the chain tries both.
func (s *OAuthClientAuthService) Authenticate(ctx context.Context, clientID, clientSecret, authMethod string) (*AuthenticatedClient, error) {
	if clientID == "" {
		return nil, ErrInvalidOAuthClientCredentials
	}
	c, err := s.clientSvc.AuthenticateClient(ctx, clientID, clientSecret)
	if domain.IsAuthStoreUnavailable(err) {
		// AUTH-503: the client STORE erred — no verdict was reached; do not
		// fall through to the api-resource chain and the opaque 401.
		return nil, err
	}
	if err == nil {
		// P0-7: the secret verified, but a secret presentation is valid ONLY
		// for a client REGISTERED for that exact secret method. Reject the
		// downgrade — a private_key_jwt (assertion-only) or public ("none")
		// client, or a basic↔post mismatch, MUST NOT authenticate via a
		// secret. EffectiveAuthMethod resolves the empty default to
		// client_secret_basic (RFC 6749 default).
		if c.EffectiveAuthMethod() != authMethod {
			return nil, ErrInvalidOAuthClientCredentials
		}
		out := &AuthenticatedClient{
			Kind:         AuthenticatedClientKindOAuth,
			ClientID:     c.ClientID,
			AuthRecordID: c.ID,
			Name:         c.Name,
			IsPublic:     c.IsPublic,
			IDTokenAlg:   c.EffectiveIDTokenAlg(),
		}
		if c.OrganizationID != nil {
			out.OrganizationID = *c.OrganizationID
		}
		// Populate AllowedScopes for the oauth_client path from the
		// existing per-client `scope` column. This is the OSS
		// fulfillment of the "oauth_client allowed-scope policy"
		// gap — no schema change required because the column has
		// always been there. An empty Scope means no per-client
		// policy and falls back to the (audience set) ∩ () in
		// TokenService, which then rejects any non-empty requested
		// scope (negotiateScope contract).
		if scopes := splitClientScope(c.Scope); len(scopes) > 0 {
			out.AllowedScopes = scopes
		}
		return out, nil
	}
	if s.apiResource != nil && clientSecret != "" {
		if r, err := s.apiResource.AuthenticateAPIResource(ctx, clientID, clientSecret); err == nil {
			allowed := make([]string, 0, len(r.Scopes))
			for _, sc := range r.Scopes {
				if sc.Name != "" {
					allowed = append(allowed, sc.Name)
				}
			}
			return &AuthenticatedClient{
				Kind:           AuthenticatedClientKindAPIResource,
				ClientID:       r.Audience,
				AuthRecordID:   r.ID,
				Name:           r.Name,
				OrganizationID: r.OrganizationID,
				AllowedScopes:  allowed,
			}, nil
		}
	}
	return nil, ErrInvalidOAuthClientCredentials
}

// ErrInvalidOAuthClientCredentials is the opaque sentinel for the
// unified OAuth client-auth chain. Wire callers map this to 401 +
// WWW-Authenticate + invalid_client per RFC 6749 §5.2.
var ErrInvalidOAuthClientCredentials = errors.New("service: invalid oauth client credentials")

// AuthenticateAssertion is the private_key_jwt counterpart of
// Authenticate. clientID is the form-supplied `client_id` value;
// assertionJWT is the form-supplied `client_assertion` value.
//
// Returns ErrInvalidOAuthClientCredentials for any verification
// failure so the wire mapping stays a single opaque 401 +
// WWW-Authenticate + invalid_client response. The raw assertion
// JWT is NEVER echoed or returned.
//
// Without a wired ClientAssertionValidator (set via
// WithAssertionValidator), every call returns
// ErrInvalidOAuthClientCredentials so legacy deployments that
// have not opted in get the pre-this-slice behavior.
func (s *OAuthClientAuthService) AuthenticateAssertion(ctx context.Context, clientID, assertionJWT string) (*AuthenticatedClient, error) {
	if s.assertionVerify == nil {
		return nil, ErrInvalidOAuthClientCredentials
	}
	if clientID == "" || assertionJWT == "" {
		return nil, ErrInvalidOAuthClientCredentials
	}
	lookup := s.clientByClientID
	if lookup == nil {
		lookup = s.clientSvc
	}
	client, err := lookup.GetClientByClientID(ctx, clientID)
	if err != nil || client == nil {
		// AUTH-503: "no such client" is the verdict; any other lookup error
		// is the store class and surfaces as such.
		if err != nil && !errors.Is(err, domain.ErrClientNotFound) {
			return nil, domain.AuthStoreUnavailable("client", err)
		}
		return nil, ErrInvalidOAuthClientCredentials
	}
	// Only clients configured for private_key_jwt may authenticate
	// via assertion. A Basic-only client whose secret was stolen
	// cannot pivot to assertion-mode auth via a self-signed JWT.
	if client.EffectiveAuthMethod() != "private_key_jwt" {
		return nil, ErrInvalidOAuthClientCredentials
	}
	if _, err := s.assertionVerify.Validate(ctx, client, assertionJWT); err != nil {
		return nil, ErrInvalidOAuthClientCredentials
	}
	out := &AuthenticatedClient{
		Kind:         AuthenticatedClientKindOAuth,
		ClientID:     client.ClientID,
		AuthRecordID: client.ID,
		Name:         client.Name,
		IsPublic:     client.IsPublic,
		IDTokenAlg:   client.EffectiveIDTokenAlg(),
	}
	if client.OrganizationID != nil {
		out.OrganizationID = *client.OrganizationID
	}
	if scopes := splitClientScope(client.Scope); len(scopes) > 0 {
		out.AllowedScopes = scopes
	}
	return out, nil
}

// HasAssertionValidator reports whether the assertion path is
// wired. Discovery uses this to decide whether
// `private_key_jwt` lands in token_endpoint_auth_methods_supported.
func (s *OAuthClientAuthService) HasAssertionValidator() bool {
	return s != nil && s.assertionVerify != nil
}

// splitClientScope splits a per-client `scope` column value into
// individual scope tokens. RFC 6749 §3.3 defines scope as a
// space-separated list. Empty / whitespace-only input returns nil.
func splitClientScope(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return nil
	}
	return parts
}
