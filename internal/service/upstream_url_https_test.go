package service

import (
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// An upstream federation URL (OIDC issuer, JWKS URI) is accepted only when it
// is absolute with an https scheme (http solely under an explicit plain-HTTP
// opt-in) and a non-empty host — the scheme/host gate every fetch path passes
// before a request leaves the server. Asserts the guards' returned error for
// the SSRF-shaped inputs a fetch must never reach.
// RULE: UPSTREAM-URL-HTTPS-1
func TestUpstreamURLGuards_HTTPSAndHostRequired(t *testing.T) {
	// The OIDC provider-config issuer guard (org_admin-supplied issuer).
	badIssuers := []string{
		"",                       // empty
		"not-a-url",              // no scheme/host
		"http://idp.example.com", // plaintext http rejected (no dev opt-out here)
		"https://",               // scheme but no host
		"ftp://idp.example.com",  // non-http(s) scheme
		"file:///etc/passwd",     // file scheme — classic SSRF/LFI vector
	}
	for _, raw := range badIssuers {
		if err := validateIssuerURL(raw); err == nil {
			t.Errorf("issuer %q must be refused (absolute-https-host required), got nil", raw)
		}
	}
	if err := validateIssuerURL("https://idp.example.com/realms/x"); err != nil {
		t.Errorf("a well-formed https issuer must be accepted, got %v", err)
	}

	// validateOIDCInput wraps the same issuer guard behind the required-field
	// checks — a bad issuer must still be rejected end-to-end.
	base := OIDCProviderInput{
		Type:           domain.IDPTypeOIDC,
		OrganizationID: uuid.New(),
		Name:           "corp",
		ClientID:       "cid",
	}
	badInput := base
	badInput.IssuerURL = "http://idp.example.com"
	if err := validateOIDCInput(badInput); err == nil {
		t.Errorf("validateOIDCInput must reject a plaintext-http issuer, got nil")
	}
	okInput := base
	okInput.IssuerURL = "https://idp.example.com"
	if err := validateOIDCInput(okInput); err != nil {
		t.Errorf("validateOIDCInput must accept a well-formed https issuer, got %v", err)
	}

	// The client-JWKS fetcher's URL pre-check (allowPlainHTTP defaults false).
	fetcher := NewClientJWKSFetcherService(ClientJWKSFetcherOptions{})
	for _, raw := range []string{"", "relative/path", "http://jwks.example.com/keys", "https://", "ws://jwks.example.com"} {
		if err := fetcher.validateJWKSURI(raw); err == nil {
			t.Errorf("jwks_uri %q must be refused before fetch, got nil", raw)
		}
	}
	if err := fetcher.validateJWKSURI("https://jwks.example.com/keys"); err != nil {
		t.Errorf("a well-formed https jwks_uri must pass the pre-check, got %v", err)
	}
}
