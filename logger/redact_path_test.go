package logger

import "testing"

func TestRedactPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/api/v1/auth/invite/abc123", "/api/v1/auth/invite/:token"},
		{"/api/v1/auth/organizations/activate/abc123", "/api/v1/auth/organizations/activate/:token"},
		{"/api/v1/auth/invite/abc123/", "/api/v1/auth/invite/:token"},
		{"/api/v1/auth//invite/abc123", "/api/v1/auth/invite/:token"},
		{"/api/v1/auth/invite/abc/extra", "/api/v1/auth/invite/:token"},
		// Untouched: the redeem POST (token in the body), the re-issue route
		// (a user id), and everything else.
		{"/api/v1/auth/invite", "/api/v1/auth/invite"},
		{"/api/v1/auth/invite/", "/api/v1/auth/invite/"},
		{"/api/v1/auth/organizations/activate", "/api/v1/auth/organizations/activate"},
		{"/api/v1/users/0198b2d0-0000-7000-8000-0000000000bb/invite", "/api/v1/users/0198b2d0-0000-7000-8000-0000000000bb/invite"},
		{"/health", "/health"},
		{"", ""},
	}
	for _, c := range cases {
		if got := RedactPath(c.in); got != c.want {
			t.Errorf("RedactPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
