package handlers

import (
	"net/http/httptest"
	"testing"
)

// The Secure flag on the IdP's cookies follows the CONFIGURED issuer, not only
// the request's Host header: with an https issuer a request that merely claims
// Host: localhost (a proxy that does not rewrite it, a crafted request) must not
// receive a cookie a browser would also send over plain http.
func TestCookieSecure_FollowsTheConfiguredIssuer(t *testing.T) {
	local := httptest.NewRequest("GET", "http://localhost:7113/x", nil)
	local.Host = "localhost:7113"
	public := httptest.NewRequest("GET", "https://idp.example.test/x", nil)
	public.Host = "idp.example.test"

	t.Cleanup(func() { SetCookieIssuer("") })

	SetCookieIssuer("")
	if cookieSecureForRequest(local) {
		t.Error("no issuer configured, loopback host: the local-dev exception must hold")
	}
	if !cookieSecureForRequest(public) {
		t.Error("a public host is always Secure")
	}

	SetCookieIssuer("http://127.0.0.1:7113")
	if cookieSecureForRequest(local) {
		t.Error("a loopback http issuer keeps the local-dev exception")
	}

	SetCookieIssuer("https://idp.example.test")
	if !cookieSecureForRequest(local) {
		t.Error("an https issuer: a request claiming Host localhost must still get Secure cookies")
	}
	if !cookieSecureForRequest(public) {
		t.Error("an https issuer: a public host is Secure")
	}
}
