package domain

import (
	"errors"
	"testing"
)

// A redirect_uri is refused at registration when its scheme is a dangerous
// script/data scheme (javascript, data, vbscript, file) or is not a
// well-formed RFC 3986 scheme — so a dangerous scheme can never land in a
// client's allowlist, where the authorize-time exact match would then honor
// it. Asserts the validator's returned error.
// RULE: REDIRECT-URI-SCHEME-1
func TestValidateRedirectURIs_RejectsDangerousSchemes(t *testing.T) {
	for _, bad := range []string{
		"javascript:alert(1)",
		"JavaScript:alert(1)", // case-insensitive denylist
		"data:text/html,<script>x</script>",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"1abc://x",   // scheme must start with ALPHA (RFC 3986 §3.1)
		"has space:", // invalid scheme characters
	} {
		if err := ValidateRedirectURIs([]string{bad}); err == nil {
			t.Errorf("redirect_uri %q must be refused at registration, got nil", bad)
		} else if !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("redirect_uri %q must fail with ErrInvalidRequest, got %v", bad, err)
		}
	}
	// Legitimate schemes (https, http-localhost, RFC 8252 custom) are accepted.
	for _, ok := range []string{
		"https://app.example.com/cb",
		"http://localhost:8080/cb",
		"com.example.app:/callback",
	} {
		if err := ValidateRedirectURIs([]string{ok}); err != nil {
			t.Errorf("legitimate redirect_uri %q must be accepted, got %v", ok, err)
		}
	}
}
