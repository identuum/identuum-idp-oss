package service

import "testing"

// TestSanitizeReturnURL_RelativeOnly gives the service-side return-URL sanitizer
// an exact coverage edge with a DIRECT call: only a same-site relative path is
// honored verbatim, while an absolute URL, a protocol-relative URL, a backslash-
// bearing value, or an empty string collapses to the default. This is the
// service-side twin of the handler guard OPEN-REDIRECT-RELATIVE-1 pins in the
// handlers package; this rule pins the service function itself.
// RULE: RETURN-URL-SANITIZE-1
func TestSanitizeReturnURL_RelativeOnly(t *testing.T) {
	if got := sanitizeReturnURL("/dashboard"); got != "/dashboard" {
		t.Errorf("a same-site relative path must be honored verbatim, got %q", got)
	}
	for _, evil := range []string{
		"https://evil.example.com", // absolute — open redirect
		"//evil.example.com",       // protocol-relative — open redirect
		"/\\evil.example.com",      // backslash-bearing
		"http://x",                 // absolute
		"",                         // empty
	} {
		if got := sanitizeReturnURL(evil); got != defaultReturnURL {
			t.Errorf("return target %q must collapse to %q, got %q", evil, defaultReturnURL, got)
		}
	}
}
