// webauthn_ui_origin_test.go — focused tests for the WebAuthn UI
// public base URL resolver. These tests do not touch os.Getenv,
// they drive the resolver through an injected getenv hook.

package runtime

import (
	"testing"
)

// TestResolveUIPublicBaseURLForWebAuthn_OperatorOverrideWins pins
// rule 1 of the precedence contract: when the env var is set, its
// value (trimmed) is returned verbatim regardless of the IDP base
// URL shape. Production deployments rely on this so the localhost
// default never silently overrides an operator-configured origin.
func TestResolveUIPublicBaseURLForWebAuthn_OperatorOverrideWins(t *testing.T) {
	cases := []struct {
		name       string
		env        string
		idpBaseURL string
		want       string
	}{
		{
			name:       "https production override against https IDP",
			env:        "https://ui.example.com",
			idpBaseURL: "https://auth.example.com",
			want:       "https://ui.example.com",
		},
		{
			name:       "override trims trailing slash",
			env:        "https://ui.example.com/",
			idpBaseURL: "https://auth.example.com",
			want:       "https://ui.example.com",
		},
		{
			name:       "override trims trailing slashes (multiple)",
			env:        "https://ui.example.com///",
			idpBaseURL: "https://auth.example.com",
			want:       "https://ui.example.com",
		},
		{
			name:       "override beats localhost default",
			env:        "https://ui.example.com",
			idpBaseURL: "http://localhost:7113",
			want:       "https://ui.example.com",
		},
		{
			name:       "override trims surrounding whitespace",
			env:        "  https://ui.example.com  ",
			idpBaseURL: "https://auth.example.com",
			want:       "https://ui.example.com",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			getenv := func(k string) string {
				if k == envUIPublicBaseURL {
					return c.env
				}
				return ""
			}
			got := resolveUIPublicBaseURLForWebAuthn(getenv, c.idpBaseURL)
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestResolveUIPublicBaseURLForWebAuthn_LocalDevDefault pins rule 2:
// when the env var is unset AND the IDP base URL is a localhost-
// style origin, the conservative split-runtime default kicks in so
// the WebAuthn service accepts ceremonies originating from the
// identuum-ui port (7104).
func TestResolveUIPublicBaseURLForWebAuthn_LocalDevDefault(t *testing.T) {
	cases := []struct {
		name       string
		env        string
		idpBaseURL string
		want       string
	}{
		{
			name:       "localhost IDP origin (with port)",
			env:        "",
			idpBaseURL: "http://localhost:7113",
			want:       "http://localhost:7104",
		},
		{
			name:       "localhost IDP origin (no port, https)",
			env:        "",
			idpBaseURL: "https://localhost",
			want:       "http://localhost:7104",
		},
		{
			name:       "127.0.0.1 IDP origin",
			env:        "",
			idpBaseURL: "http://127.0.0.1:7113",
			want:       "http://localhost:7104",
		},
		{
			name:       "whitespace-only env still triggers default",
			env:        "   ",
			idpBaseURL: "http://localhost:7113",
			want:       "http://localhost:7104",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			getenv := func(k string) string {
				if k == envUIPublicBaseURL {
					return c.env
				}
				return ""
			}
			got := resolveUIPublicBaseURLForWebAuthn(getenv, c.idpBaseURL)
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestResolveUIPublicBaseURLForWebAuthn_ProductionDefaultEmpty pins
// rule 3: when the env var is unset AND the IDP base URL is NOT a
// localhost-style origin, the resolver returns the empty string so
// the WebAuthn service does NOT silently widen RPOrigins. This is
// the conservative production posture — operator must opt in.
func TestResolveUIPublicBaseURLForWebAuthn_ProductionDefaultEmpty(t *testing.T) {
	cases := []struct {
		name       string
		idpBaseURL string
	}{
		{"public host with subdomain", "https://auth.example.com"},
		{"public host with port", "https://auth.example.com:8443"},
		{"loopback alias name (NOT loopback for our purposes)", "http://lvh.me:7113"},
		{"empty IDP base URL", ""},
		{"malformed IDP base URL", "::::"},
		{"non-http scheme rejected", "ftp://localhost:7104"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			getenv := func(k string) string { return "" }
			got := resolveUIPublicBaseURLForWebAuthn(getenv, c.idpBaseURL)
			if got != "" {
				t.Fatalf("got %q, want empty string", got)
			}
		})
	}
}

// TestResolveUIPublicBaseURLForWebAuthn_NilGetenv ensures the
// resolver does not panic when a nil getenv is supplied; it falls
// straight through to the localhost default branch.
func TestResolveUIPublicBaseURLForWebAuthn_NilGetenv(t *testing.T) {
	got := resolveUIPublicBaseURLForWebAuthn(nil, "http://localhost:7113")
	if got != localDevUIPublicBaseURLDefault {
		t.Fatalf("got %q, want %q", got, localDevUIPublicBaseURLDefault)
	}
	got = resolveUIPublicBaseURLForWebAuthn(nil, "https://auth.example.com")
	if got != "" {
		t.Fatalf("got %q, want empty string", got)
	}
}

// TestIsLocalhostBaseURL pins the host classifier the resolver
// delegates to. The classifier is deliberately strict — only the
// two documented loopback names trip it.
func TestIsLocalhostBaseURL(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"localhost http", "http://localhost", true},
		{"localhost http with port", "http://localhost:7113", true},
		{"localhost https", "https://localhost", true},
		{"127.0.0.1 http", "http://127.0.0.1", true},
		{"127.0.0.1 http with port", "http://127.0.0.1:7113", true},
		{"::1 IPv6 loopback not classified", "http://[::1]:7113", false},
		{"lvh.me not classified", "http://lvh.me:7113", false},
		{"public host", "https://auth.example.com", false},
		{"empty string", "", false},
		{"malformed", "::::", false},
		{"non-http scheme", "ftp://localhost", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isLocalhostBaseURL(c.raw)
			if got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}
