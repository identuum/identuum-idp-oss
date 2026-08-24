package domain

import "testing"

// TestTrustedAssertionURLGuards_Direct pins BOTH domain-side upstream-URL guards
// with DIRECT calls so each has an exact coverage edge under an armed rule:
// validateIssuerURL accepts only an http or https URL with a non-empty host,
// and validateJWKSURL accepts only an https URL with a non-empty host; empty,
// unparseable, non-http(s)/https, and host-less values are refused before
// either becomes a trust anchor for assertion signature verification.
// RULE: TRUSTED-ISSUER-URL-1
func TestTrustedAssertionURLGuards_Direct(t *testing.T) {
	// Issuer guard: http OR https, with a non-empty host.
	if err := validateIssuerURL("https://idp.example.com/realms/x"); err != nil {
		t.Errorf("a well-formed https issuer must be accepted, got %v", err)
	}
	if err := validateIssuerURL("http://idp.example.com"); err != nil {
		t.Errorf("an http issuer must be accepted by the issuer guard, got %v", err)
	}
	for _, bad := range []string{
		"",                      // empty
		"not-a-url",             // no scheme/host
		"ftp://idp.example.com", // non-http(s) scheme with a host
		"file:///etc/passwd",    // file scheme, host-less
		"https://",              // scheme but no host
	} {
		if err := validateIssuerURL(bad); err == nil {
			t.Errorf("issuer %q must be refused (http/https + host required), got nil", bad)
		}
	}

	// JWKS guard: https ONLY, with a non-empty host.
	if err := validateJWKSURL("https://idp.example.com/jwks"); err != nil {
		t.Errorf("a well-formed https jwks_url must be accepted, got %v", err)
	}
	for _, bad := range []string{
		"",                            // empty
		"not-a-url",                   // no scheme/host
		"http://idp.example.com/jwks", // plaintext http rejected (https-only)
		"ftp://idp.example.com",       // non-https scheme
		"https://",                    // scheme but no host
	} {
		if err := validateJWKSURL(bad); err == nil {
			t.Errorf("jwks_url %q must be refused (https + host required), got nil", bad)
		}
	}
}
