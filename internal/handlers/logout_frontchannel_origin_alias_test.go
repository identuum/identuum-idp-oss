package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// FRONTCHANNEL-SANDBOX-ORIGIN-1 (OSS-FIXES-REVIEW-2026-10-10 R1): a receiver
// whose address is another spelling of the OP's own origin is the OP's origin
// to the browser. A zero-padded default port, an IDNA host written in Unicode
// or in punycode, and an IPv6 literal written long or short all name the same
// origin; with allow-scripts and allow-same-origin together, such a receiver
// could read the page that frames it and remove its own sandbox. Each alias
// gets allow-scripts alone, on the helper and on both surfaces that frame a
// receiver. A spelling the OP cannot canonicalize with certainty — every
// internationalized host among them — is treated the same way. ASCII origins
// that really differ still get both, so a cross-origin receiver keeps its own
// storage.

// RULE: FRONTCHANNEL-SANDBOX-ORIGIN-1
func TestFrontchannelFrameSandbox_BrowserEquivalentOriginsAreTheOPsOrigin(t *testing.T) {
	for _, tc := range []struct {
		src, issuer, want string
	}{
		// Zero-padded ports: the browser reads the number.
		{"https://idp.test:0443/rp/fc", "https://idp.test", sandboxSameOrigin},
		{"https://idp.test:000443/rp/fc", "https://idp.test", sandboxSameOrigin},
		{"https://idp.test/rp/fc", "https://idp.test:0443", sandboxSameOrigin},
		{"http://idp.test:080/rp/fc", "http://idp.test", sandboxSameOrigin},
		{"https://idp.test:08443/rp/fc", "https://idp.test:8443", sandboxSameOrigin},
		// IDNA: Unicode, punycode and case are one host. An internationalized
		// host is not canonicalized here (no IDNA mapper may be imported), so
		// it is never judged different from the OP, alias or not.
		{"https://xn--bcher-kva.example/rp/fc", "https://bücher.example", sandboxSameOrigin},
		{"https://xn--bcher-kva.example/rp/fc", "https://idp.test", sandboxSameOrigin},
		{"https://idp.test/rp/fc", "https://bücher.example", sandboxSameOrigin},
		{"https://bücher.example/rp/fc", "https://xn--bcher-kva.example", sandboxSameOrigin},
		{"https://BÜCHER.example/rp/fc", "https://bücher.example", sandboxSameOrigin},
		{"https://XN--BCHER-KVA.example:0443/rp/fc", "https://bücher.example", sandboxSameOrigin},
		// IPv6 literals: long, short and upper-case forms are one address.
		{"https://[2001:0db8:0000:0000:0000:0000:0000:0001]/rp/fc", "https://[2001:db8::1]", sandboxSameOrigin},
		{"https://[2001:DB8::1]:443/rp/fc", "https://[2001:db8::1]", sandboxSameOrigin},
		{"https://[2001:db8:0:0::1]:0443/rp/fc", "https://[2001:db8::1]", sandboxSameOrigin},
		// Spellings the OP does not canonicalize: never granted both.
		{"http://127.1:8080/rp/fc", "http://127.0.0.1:8080", sandboxSameOrigin},
		{"http://0x7f.0.0.1:8080/rp/fc", "http://127.0.0.1:8080", sandboxSameOrigin},
		{"http://2130706433:8080/rp/fc", "http://127.0.0.1:8080", sandboxSameOrigin},
		{"https://idp.test./rp/fc", "https://idp.test", sandboxSameOrigin},
		{"https://user@idp.test/rp/fc", "https://idp.test", sandboxSameOrigin},
		{"https://idp.test:99999/rp/fc", "https://idp.test", sandboxSameOrigin},
		{"ftp://other.example/rp/fc", "https://idp.test", sandboxSameOrigin},
		// Controls: origins that really differ keep allow-same-origin.
		{"https://books.example/rp/fc", "https://idp.test", sandboxCrossOrigin},
		{"https://IDP.example:8443/rp/fc", "https://idp.test", sandboxCrossOrigin},
		{"https://idp.test:8443/rp/fc", "https://idp.test:0443", sandboxCrossOrigin},
		{"https://[2001:db8::2]/rp/fc", "https://[2001:db8::1]", sandboxCrossOrigin},
		{"https://[::ffff:127.0.0.1]/rp/fc", "https://127.0.0.1", sandboxCrossOrigin},
		{"http://127.0.0.2:8080/rp/fc", "http://127.0.0.1:8080", sandboxCrossOrigin},
		{"http://idp.test:0443/rp/fc", "https://idp.test", sandboxCrossOrigin},
	} {
		if got := frontchannelFrameSandbox(tc.src, tc.issuer); got != tc.want {
			t.Errorf("frontchannelFrameSandbox(%q, %q) = %q, want %q", tc.src, tc.issuer, got, tc.want)
		}
	}
}

// aliasCases are receivers registered under another spelling of the OP's own
// origin, each with the issuer it is an alias of. On the end_session fan-out
// an unrelated ASCII receiver beside it gets allow-scripts alone too: a fan-out
// with any receiver on the OP's origin runs every frame scripts-only
// (OSS-REVIEW-FIXES-3, review OSS-PKCE-REVIEW-2026-10-10 R3).
var aliasCases = []struct{ name, issuer, uri string }{
	{"zero-padded default port", "https://idp.test", "https://idp.test:0443/rp/fc"},
	{"IDNA punycode alias", "https://bücher.example", "https://xn--bcher-kva.example/rp/fc"},
	{"IPv6 long form", "https://[2001:db8::1]", "https://[2001:0db8:0:0:0:0:0:1]/rp/fc"},
}

func TestEndSession_AReceiverOnAnAliasOfTheOPsOriginGetsScriptsAlone(t *testing.T) {
	for _, tc := range aliasCases {
		w := fcWorldWith(t, tc.issuer, clientsByClientID{
			"fc-alias": {ClientID: "fc-alias", FrontchannelLogoutURI: tc.uri},
			"fc-other": {ClientID: "fc-other", FrontchannelLogoutURI: "https://other.example/fc"},
		}, []string{"fc-alias", "fc-other"})
		rec := w.logout("/api/v1/oidc/logout")
		got := sandboxOf(t, rec.Body.String())
		if len(got) != 2 || got[tc.uri] != sandboxSameOrigin || got["https://other.example/fc"] != sandboxSameOrigin {
			t.Errorf("%s: frame sandboxes = %v; want the alias receiver and the other at %q", tc.name, got, sandboxSameOrigin)
		}
		assertNoParentControl(t, rec.Body.String(), rec.Header().Get("Content-Security-Policy"))
	}
}

func TestFrontchannelLogout_AReceiverOnAnAliasOfTheOPsOriginGetsScriptsAlone(t *testing.T) {
	for _, tc := range aliasCases {
		r := newFrontchannelEngineWithClient(t, &domain.Client{ClientID: "cli-1", FrontchannelLogoutURI: tc.uri}, tc.issuer)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout?client_id=cli-1", nil))
		got := sandboxOf(t, w.Body.String())
		if len(got) != 1 || got[tc.uri] != sandboxSameOrigin {
			t.Errorf("%s: frame sandboxes = %v; want %q", tc.name, got, sandboxSameOrigin)
		}
	}
}
