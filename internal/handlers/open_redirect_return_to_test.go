package handlers

import "testing"

// A user-supplied return target is honored only as a same-site relative path:
// any absolute, protocol-relative (//host), scheme/host-bearing, or
// CR/LF-bearing value is refused (collapsed away) so the login flow cannot be
// turned into an open redirect. Asserts the sanitizer's returned value — what
// the serving path would actually redirect to.
// RULE: OPEN-REDIRECT-RELATIVE-1
func TestValidateReturnTo_RelativeOnly(t *testing.T) {
	// Honored: a same-site relative path is returned verbatim.
	for _, ok := range []string{"/", "/dashboard", "/a/b?c=d"} {
		if got := validateReturnTo(ok); got != ok {
			t.Errorf("same-site path %q must be honored, got %q", ok, got)
		}
	}
	// Refused: everything that could leave the origin collapses to "".
	for _, evil := range []string{
		"https://evil.example.com",  // absolute
		"//evil.example.com",        // protocol-relative
		"http://evil.example.com/x", // absolute http
		"/\r\nSet-Cookie: x=y",      // CR/LF header injection
		"javascript:alert(1)",       // scheme, not a path
		"evil.example.com",          // no leading slash
	} {
		if got := validateReturnTo(evil); got != "" {
			t.Errorf("off-origin return target %q must be refused, got %q", evil, got)
		}
	}
}
