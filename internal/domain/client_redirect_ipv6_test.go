package domain

import (
	"errors"
	"testing"
)

// D-020 / RFC 8252 §7.3: a native app's IPv6 loopback redirect
// (http://[::1]:<port>/…) is accepted at registration and matched at
// /authorize exactly like the IPv4 loopback one. Both are exact matches:
// neither gets a wildcard port.
func TestRedirectURIs_IPv6LoopbackLikeIPv4(t *testing.T) {
	v4 := "http://127.0.0.1:53682/callback"
	v6 := "http://[::1]:53682/callback"
	if err := ValidateRedirectURIs([]string{v4, v6}); err != nil {
		t.Fatalf("ValidateRedirectURIs refused a loopback redirect: %v", err)
	}
	c := &Client{RedirectURIs: []string{v4, v6}}
	for _, uri := range []string{v4, v6} {
		if !c.IsRedirectURIAllowed(uri) {
			t.Errorf("registered loopback redirect %q not allowed", uri)
		}
	}
	for _, uri := range []string{"http://127.0.0.1:1/callback", "http://[::1]:1/callback", "http://[::2]:53682/callback"} {
		if c.IsRedirectURIAllowed(uri) {
			t.Errorf("unregistered redirect %q allowed", uri)
		}
	}
	if err := ValidateRedirectURIs([]string{"javascript://[::1]/x"}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("a dangerous scheme on an IPv6 host was accepted: %v", err)
	}
}
