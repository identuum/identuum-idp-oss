package domain

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// dangerousRedirectURISchemes lists URI schemes that must never be accepted as
// redirect URIs. All are script / data-URL schemes that turn an "OAuth redirect"
// into a primitive for executing attacker-controlled code or exfiltrating data
// in the user-agent context. Modern browsers block most of these in Location
// headers, but non-browser OIDC clients (native apps, MCP agents, CLI tools)
// may follow them as-is.
var dangerousRedirectURISchemes = []string{"javascript", "data", "vbscript", "file"}

// isValidURIScheme reports whether s matches the RFC 3986 §3.1 `scheme`
// production: first character must be ALPHA, subsequent characters may be
// ALPHA / DIGIT / "+" / "." / "-". This rejects malformed schemes like `"1abc"`
// or `"scheme with spaces"` that some URL parsers accept leniently.
func isValidURIScheme(s string) bool {
	if s == "" {
		return false
	}
	first := s[0]
	isAlpha := (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')
	if !isAlpha {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '+' || c == '-' || c == '.':
		default:
			return false
		}
	}
	return true
}

// ValidateRedirectURIs performs per-URI format validation at registration and
// update time. The §2.14 spec promises "strict enforcement of permitted
// redirect URIs to prevent impersonation and hijacking" — the exact-string
// match at authorize time is strict for the comparison step, but the stored
// value must also be format-validated so dangerous schemes never land in the
// allowlist in the first place.
//
// Rules:
//   - Each URI must parse via `url.Parse`.
//   - Scheme must be non-empty and match RFC 3986 §3.1 character class.
//   - Scheme must not be in the dangerous-scheme denylist (case-insensitive).
//
// HTTPS is NOT required. RFC 8252 explicitly permits custom schemes
// (`com.example.app:/callback`) for native apps, and `http://localhost*` is
// conventional for local development. The validator's job is to reject
// dangerous schemes, not to mandate a specific safe one.
func ValidateRedirectURIs(uris []string) error {
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("%w: redirect_uri %q is not a parseable URI: %v", ErrInvalidRequest, raw, err)
		}
		if !isValidURIScheme(u.Scheme) {
			return fmt.Errorf("%w: redirect_uri %q must have a valid scheme (RFC 3986 §3.1)", ErrInvalidRequest, raw)
		}
		for _, denied := range dangerousRedirectURISchemes {
			if strings.EqualFold(u.Scheme, denied) {
				return fmt.Errorf("%w: redirect_uri scheme %q is not permitted (dangerous scheme)", ErrInvalidRequest, u.Scheme)
			}
		}
	}
	return nil
}

// ValidateLogoutURI enforces the OSS-side admin policy for the
// per-client `frontchannel_logout_uri` and `backchannel_logout_uri`
// fields. Empty input is OK (the column is nullable). Non-empty
// input MUST:
//
//   - parse via url.Parse,
//   - carry an HTTPS scheme (HTTP is rejected — no local-dev
//     opt-out at the admin layer; the BackchannelLogoutService
//     handles that knob separately for tests),
//   - have no `#fragment`,
//   - have no `user:password@` userinfo,
//   - be absolute (have a host).
//
// Returns nil on success or an ErrInvalidRequest-wrapped sentinel.
func ValidateLogoutURI(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("%w: logout_uri %q is not parseable: %v", ErrInvalidRequest, s, err)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: logout_uri %q must be absolute", ErrInvalidRequest, s)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: logout_uri %q must use https", ErrInvalidRequest, s)
	}
	if u.Fragment != "" || strings.Contains(s, "#") {
		return fmt.Errorf("%w: logout_uri %q must not contain a fragment", ErrInvalidRequest, s)
	}
	if u.User != nil {
		return fmt.Errorf("%w: logout_uri %q must not contain userinfo", ErrInvalidRequest, s)
	}
	return nil
}

// AllowedClientAuthMethods enumerates the valid token_endpoint_auth_method values.
var AllowedClientAuthMethods = map[string]struct{}{
	"client_secret_basic": {},
	"client_secret_post":  {},
	"none":                {},
	"private_key_jwt":     {},
}

// ValidateClientAuthMethod and ValidateClientSigningAlg enforce the two
// allow-lists above. THE-SILENT-DROP-2: both maps existed with ZERO
// production callers, so the oauth_clients_auth_method_check and
// oauth_clients_signing_alg_check CHECK constraints were the only thing
// actually refusing an unlisted value — the service handed anything through
// and read the answer back from the database.
//
// Neither accepts the empty string, and that is why blank cannot mean CLEAR
// for these two fields: both columns are NOT NULL with a DEFAULT, and the
// repository silently substitutes that default for a blank value. "Clearing"
// them would hand the caller client_secret_basic / EdDSA without being asked.
func ValidateClientAuthMethod(method string) error {
	if _, ok := AllowedClientAuthMethods[method]; !ok {
		return fmt.Errorf("%w: token_endpoint_auth_method %q is not a supported value", ErrInvalidRequest, method)
	}
	return nil
}

func ValidateClientSigningAlg(alg string) error {
	if _, ok := PrivateKeyJWTSigningAlgorithms[alg]; !ok {
		return fmt.Errorf("%w: token_endpoint_auth_signing_alg %q is not a supported value", ErrInvalidRequest, alg)
	}
	return nil
}

// AuthMethodUsesClientSecret reports whether a token_endpoint_auth_method
// authenticates the client with a shared secret.
//
// Only "client_secret_basic" and "client_secret_post" do. "private_key_jwt"
// authenticates with a signed assertion and "none" does not authenticate at
// all, so for both of those a stored client_secret_hash is dead credential
// material: the auth layer already refuses to consult it, but leaving it on the
// row means a secret nobody can use, and nobody has rotated, sits in the
// database indefinitely (P0-7b).
func AuthMethodUsesClientSecret(method string) bool {
	switch method {
	case "client_secret_basic", "client_secret_post":
		return true
	default:
		return false
	}
}

// PrivateKeyJWTSigningAlgorithms is the allowed set of per-client configured
// signing algorithms for private_key_jwt assertions (inbound verification only).
// This is intentionally broader than AcceptableAssertionAlgorithms to support
// common enterprise client integrations.
//
// Identuum DOES NOT issue JWTs with these algorithms — this set governs
// inbound assertion verification only. RS256 issuance remains banned;
// Identuum-issued tokens remain EdDSA (default) and ES256.
//
// Rejected: none, HS*, ES512, and any EC curve other than P-256 or P-384.
var PrivateKeyJWTSigningAlgorithms = map[string]struct{}{
	"EdDSA": {},
	"ES256": {},
	"ES384": {},
	"RS256": {},
	"RS384": {},
	"RS512": {},
	"PS256": {},
	"PS384": {},
	"PS512": {},
}

// Client represents an OAuth2/OIDC Client application
type Client struct {
	UpdatedAt        time.Time
	CreatedAt        time.Time
	OrganizationID   *uuid.UUID
	ServiceAccountID *uuid.UUID
	Scope            string
	Name             string
	ClientSecretHash string
	ClientID         string
	// TokenEndpointAuthMethod declares which client authentication method this
	// client uses at the token endpoint. One of "client_secret_basic",
	// "client_secret_post", "none", or "private_key_jwt". Empty string is treated
	// as "client_secret_basic" (confidential) or "none" (public) by EffectiveAuthMethod.
	TokenEndpointAuthMethod string
	// JWKSUri is the HTTPS URL of the client's public JWKS endpoint.
	// Only valid when TokenEndpointAuthMethod == "private_key_jwt".
	// Mutually exclusive with JWKS.
	JWKSUri string
	// JWKS is the inline JSON-encoded JWK Set containing the client's public key(s).
	// Only valid when TokenEndpointAuthMethod == "private_key_jwt".
	// Mutually exclusive with JWKSUri.
	JWKS string
	// TokenEndpointAuthSigningAlg is the per-client JWT signing algorithm for
	// private_key_jwt assertions. Must be one of the values in
	// PrivateKeyJWTSigningAlgorithms. Empty string defaults to "EdDSA" via
	// EffectiveSigningAlg.
	TokenEndpointAuthSigningAlg string
	RedirectURIs                []string
	PostLogoutRedirectURIs      []string
	AllowedAudiences            []string
	ID                          uuid.UUID
	IsPublic                    bool
	SkipConsent                 bool
	TokenTTLSecs                *int
	// FrontchannelLogoutURI is the registered RP front-channel
	// logout URL. When non-empty AND the OP frontchannel-logout
	// route is live, the OP renders an iframe loading this URI
	// during /api/v1/oidc/logout. Spec: OIDC Front-Channel Logout
	// 1.0 §3.
	FrontchannelLogoutURI string
	// FrontchannelLogoutSessionRequired reports whether the RP
	// requires `iss` + `sid` query parameters appended to its
	// FrontchannelLogoutURI when the OP renders the iframe.
	FrontchannelLogoutSessionRequired bool
	// BackchannelLogoutURI is the registered RP back-channel
	// logout endpoint. When non-empty AND the OP backchannel
	// delivery service is wired, the OP POSTs a `logout_token`
	// here during /api/v1/oidc/logout.
	BackchannelLogoutURI string
	// BackchannelLogoutSessionRequired reports whether the RP
	// requires the `sid` claim in the logout_token.
	BackchannelLogoutSessionRequired bool
}

// EffectiveAuthMethod returns the resolved token_endpoint_auth_method, applying
// the backward-compat default (empty stored value → "none" for public clients,
// "client_secret_basic" for confidential clients).
func (c *Client) EffectiveAuthMethod() string {
	if c.TokenEndpointAuthMethod != "" {
		return c.TokenEndpointAuthMethod
	}
	if c.IsPublic {
		return "none"
	}
	return "client_secret_basic"
}

// EffectiveSigningAlg returns the per-client signing algorithm, defaulting to
// "EdDSA" when the stored value is empty (operator decision #2 default).
func (c *Client) EffectiveSigningAlg() string {
	if c.TokenEndpointAuthSigningAlg != "" {
		return c.TokenEndpointAuthSigningAlg
	}
	return "EdDSA"
}

// Validate performs domain-level validation.
// Note: scope string is intentionally NOT validated against the static scope list here —
// dynamic API Resource scopes are user-defined and not present in that list.
// Scope permission enforcement is handled by service.validateScopePermissions.
func (c *Client) Validate() error {
	if c.ClientID == "" {
		return errors.New("client_id is required")
	}
	// Required means required after trimming (REQUIRED-NAME-NOT-WHITESPACE-1).
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("name is required")
	}
	if len(c.RedirectURIs) == 0 {
		return errors.New("at least one redirect_uri is required")
	}
	// Public clients cannot hold a secret — they are unable to keep one confidential.
	if c.IsPublic && c.ClientSecretHash != "" {
		return errors.New("public client must not have a client_secret")
	}
	// A public client uses the authorization_code flow on behalf of a user.
	// Machine-to-machine (client_credentials) requires a confidential client.
	if c.IsPublic && c.ServiceAccountID != nil {
		return errors.New("public client cannot be linked to a service account")
	}

	method := c.EffectiveAuthMethod()

	// Validate auth method value — via the SAME function the update path
	// calls, not a second spelling of the map lookup (THE-MIRROR).
	if c.TokenEndpointAuthMethod != "" {
		if err := ValidateClientAuthMethod(c.TokenEndpointAuthMethod); err != nil {
			return err
		}
	}

	// Consistency checks between method and IsPublic.
	switch method {
	case "none":
		if !c.IsPublic {
			return fmt.Errorf("%w: token_endpoint_auth_method 'none' is only valid for public clients", ErrInvalidRequest)
		}
	case "client_secret_basic", "client_secret_post":
		if c.IsPublic {
			return fmt.Errorf("%w: token_endpoint_auth_method %q is not valid for public clients", ErrInvalidRequest, method)
		}
	case "private_key_jwt":
		if c.IsPublic {
			return fmt.Errorf("%w: token_endpoint_auth_method 'private_key_jwt' requires a confidential client", ErrInvalidRequest)
		}
		// Exactly one key source must be configured.
		hasURI := strings.TrimSpace(c.JWKSUri) != ""
		hasInline := strings.TrimSpace(c.JWKS) != ""
		if !hasURI && !hasInline {
			return fmt.Errorf("%w: private_key_jwt client requires jwks_uri or jwks", ErrInvalidRequest)
		}
		if hasURI && hasInline {
			return fmt.Errorf("%w: private_key_jwt client must specify jwks_uri or jwks, not both", ErrInvalidRequest)
		}
		if hasURI {
			u, err := url.Parse(c.JWKSUri)
			if err != nil || u.Scheme != "https" {
				return fmt.Errorf("%w: jwks_uri must be a valid HTTPS URL", ErrInvalidRequest)
			}
		}
	}

	// JWKS fields must be absent for non-private_key_jwt clients.
	if method != "private_key_jwt" {
		if c.JWKSUri != "" || c.JWKS != "" {
			return fmt.Errorf("%w: jwks_uri and jwks are only valid for private_key_jwt clients", ErrInvalidRequest)
		}
	}

	// Validate signing alg if explicitly set — same function as update.
	if c.TokenEndpointAuthSigningAlg != "" {
		if err := ValidateClientSigningAlg(c.TokenEndpointAuthSigningAlg); err != nil {
			return err
		}
	}

	return nil
}

// IsRedirectURIAllowed checks if the provided URI is in the allowed list
func (c *Client) IsRedirectURIAllowed(uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}
