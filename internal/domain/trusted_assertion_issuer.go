package domain

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AcceptableAssertionAlgorithms enumerates the JWS signing algorithms
// permitted for a TrustedAssertionIssuer per ARCHITECTURAL_GUIDELINES.md §7
// (Tokens MUST use EdDSA, ES256, or RS256 — no others).
// and §7.
var AcceptableAssertionAlgorithms = map[string]struct{}{
	"EdDSA": {},
	"ES256": {},
	"RS256": {},
}

// DefaultAssertionSubjectClaim is the JWT claim used to derive
// users.external_id when no explicit mapping is configured.
const DefaultAssertionSubjectClaim = "sub"

// TrustedAssertionIssuer represents an external IdP whose signed
// JWT assertions Identuum will accept as proof of user identity at
// the token-exchange endpoint. Trust is always scoped to
// (organization_id, issuer).
type TrustedAssertionIssuer struct {
	CreatedAt            time.Time
	UpdatedAt            time.Time
	Name                 string
	Issuer               string
	JWKSURL              string
	SubjectClaimMapping  string
	AcceptableAudiences  []string
	AcceptableAlgorithms []string
	ID                   uuid.UUID
	OrganizationID       uuid.UUID
	Enabled              bool

	// Optional OIDC discovery fields (migration 0053). When both are
	// non-nil + non-empty, ConsentFederationService can issue a 302
	// redirect with prompt=none to OIDCAuthorizeEndpoint?client_id=
	// OIDCClientID&... instead of returning the JSON envelope for
	// manual handoff. nil/empty means "OIDC redirect not configured".
	OIDCAuthorizeEndpoint *string
	OIDCClientID          *string

	// Optional OIDC client-secret column (migration 0054 — Rev 9
	// full code-exchange callback). Stored AES-GCM encrypted via
	// internal/crypto.CryptoService. Required when the IdP is
	// registered as a confidential client (the typical Okta/Auth0/
	// Azure AD setup); omitted for public-client registrations
	// where PKCE alone authenticates the redirect callback.
	//
	// NEVER expose the plaintext on the wire. The handler envelope
	// returns only `oidc_client_secret_set` (boolean) — admins see
	// whether a secret is configured but cannot read it back. Plaintext
	// arrives only via POST/PATCH from the admin's browser.
	OIDCClientSecretEncrypted *string
}

// Validate enforces invariants that must hold for any persisted row.
// Per the security pipeline (§3) this runs at the service layer before
// repository writes. It does NOT perform any I/O.
func (t *TrustedAssertionIssuer) Validate() error {
	if t == nil {
		return errors.New("trusted_assertion_issuer: nil receiver")
	}
	if strings.TrimSpace(t.Name) == "" {
		return errors.New("trusted_assertion_issuer: name is required")
	}
	if err := validateIssuerURL(t.Issuer); err != nil {
		return err
	}
	if err := validateJWKSURL(t.JWKSURL); err != nil {
		return err
	}
	if len(t.AcceptableAudiences) == 0 {
		return errors.New("trusted_assertion_issuer: acceptable_audiences must contain at least one entry")
	}
	for _, aud := range t.AcceptableAudiences {
		if strings.TrimSpace(aud) == "" {
			return errors.New("trusted_assertion_issuer: acceptable_audiences contains an empty entry")
		}
	}
	if len(t.AcceptableAlgorithms) == 0 {
		return errors.New("trusted_assertion_issuer: acceptable_algorithms must contain at least one entry")
	}
	for _, alg := range t.AcceptableAlgorithms {
		if _, ok := AcceptableAssertionAlgorithms[alg]; !ok {
			return errors.New("trusted_assertion_issuer: acceptable_algorithms contains unsupported algorithm: " + alg)
		}
	}
	if strings.TrimSpace(t.SubjectClaimMapping) == "" {
		return errors.New("trusted_assertion_issuer: subject_claim_mapping is required")
	}
	return nil
}

// validateIssuerURL enforces that the issuer is a well-formed absolute URL
// with an http or https scheme. This is the value that will be matched
// against the `iss` claim of incoming assertions.
func validateIssuerURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("trusted_assertion_issuer: issuer is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("trusted_assertion_issuer: issuer is not a valid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("trusted_assertion_issuer: issuer must be an http or https URL")
	}
	if parsed.Host == "" {
		return errors.New("trusted_assertion_issuer: issuer must include a host")
	}
	return nil
}

// validateJWKSURL enforces that the JWKS endpoint is HTTPS. Plain HTTP is
// refused because the JWKS document is the trust anchor for assertion
// signature verification — fetching it over an unauthenticated channel
// would let any on-path attacker mint accepted assertions.
func validateJWKSURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("trusted_assertion_issuer: jwks_url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("trusted_assertion_issuer: jwks_url is not a valid URL")
	}
	if parsed.Scheme != "https" {
		return errors.New("trusted_assertion_issuer: jwks_url must be an https URL")
	}
	if parsed.Host == "" {
		return errors.New("trusted_assertion_issuer: jwks_url must include a host")
	}
	return nil
}
