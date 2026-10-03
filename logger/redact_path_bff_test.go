package logger

import "testing"

// The console reaches the API through /bff/..., so a one-time token in an
// invite or activation path is redacted there too.
func TestRedactPath_BFFPrefixedTokenRoutes(t *testing.T) {
	for in, want := range map[string]string{
		"/bff/api/v1/auth/invite/abc123":                 "/bff/api/v1/auth/invite/:token",
		"/bff/api/v1/auth/organizations/activate/def456": "/bff/api/v1/auth/organizations/activate/:token",
		"/api/v1/auth/invite/abc123":                     "/api/v1/auth/invite/:token",
		"/bff/api/v1/users":                              "/bff/api/v1/users",
	} {
		if got := RedactPath(in); got != want {
			t.Errorf("RedactPath(%q) = %q, want %q", in, got, want)
		}
	}
}
