package domain

import "testing"

// TestValidateIssuerURL_Direct gives the domain-side issuer guard an exact
// coverage edge with a DIRECT call: an issuer is accepted only when it is an
// http or https URL with a non-empty host; empty, unparseable, non-http(s), and
// host-less values are refused. This is the domain twin of the service-side
// upstream-URL guard pinned by UPSTREAM-URL-HTTPS-1.
func TestValidateIssuerURL_Direct(t *testing.T) {
	if err := validateIssuerURL("https://idp.example.com/realms/x"); err != nil {
		t.Errorf("a well-formed https issuer must be accepted, got %v", err)
	}
	// http is permitted for the issuer (the guard accepts http OR https).
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
}

// TestValidateJWKSURL_Direct gives the domain-side jwks_url guard an exact
// coverage edge with a DIRECT call: unlike the issuer guard it is https-ONLY,
// and still requires a non-empty host. Domain twin of UPSTREAM-URL-HTTPS-1.
func TestValidateJWKSURL_Direct(t *testing.T) {
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
