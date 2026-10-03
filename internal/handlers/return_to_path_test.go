package handlers

import "testing"

// A browser normalises a backslash to a slash and drops tab and newline
// characters in a URL, so a return target that looks like a local path to a
// prefix check can still name another host. The sanitizer accepts only a
// value that stays a local path after that normalisation.
func TestValidateReturnTo_RefusesBackslashAndControlCharacters(t *testing.T) {
	for _, bad := range []string{
		`/\example.com`,
		`/\\example.com`,
		"/\t/example.com",
		"/\x00/example.com",
		`\/example.com`,
		"/%5Cexample.com/../x\\",
	} {
		if got := validateReturnTo(bad); got != "" {
			t.Errorf("return target %q must be refused, got %q", bad, got)
		}
	}
	for _, ok := range []string{"/", "/dashboard", "/a/b?c=d", "/api/v1/oauth/authorize?client_id=x&state=y"} {
		if got := validateReturnTo(ok); got != ok {
			t.Errorf("local path %q must be honored, got %q", ok, got)
		}
	}
}
