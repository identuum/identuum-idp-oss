package handlers

import (
	"net/http"
	"strings"
	"testing"
)

// R3 (review OSS-PKCE-REVIEW-2026-10-10, OSS-REVIEW-FIXES-3, judge ruling
// (a)): the end_session page admits every receiver's origin in ONE frame-src,
// and a frame's sandbox does not change when its document navigates. A
// receiver positively off the issuer's origin got allow-scripts with
// allow-same-origin; when the same page also admitted the issuer's origin (a
// receiver there) it could redirect its own frame to that receiver, which then
// ran as the issuer's origin with both permissions. Such a mixed fan-out —
// any receiver on the issuer's origin, or any whose origin cannot be told
// apart from the issuer's with certainty — now runs EVERY frame with
// allow-scripts alone. A fan-out whose receivers are all positively off the
// issuer's origin keeps both permissions
// (TestEndSession_FramesLetACrossOriginReceiverRunItsScript).
//
// RULE: FRONTCHANNEL-FANOUT-MIXED-1
func TestEndSession_AMixedFanoutRunsEveryReceiverScriptsOnly(t *testing.T) {
	const issuer = "https://idp.test"
	const offIssuer = "https://other.example/fc"
	for _, tc := range []struct {
		name, uri, frameSrc string
	}{
		{"a receiver on the issuer's origin", "https://idp.test/rp/fc", "https://idp.test"},
		{"a receiver on the issuer's origin under another spelling", "https://IDP.test:0443/rp/fc", "https://IDP.test:0443"},
		{"a receiver on a punycode host", "https://xn--bcher-kva.example/fc", "https://xn--bcher-kva.example"},
		{"a receiver whose host is a frame-src wildcard", "https://*.idp.test/fc", "https://*.idp.test"},
	} {
		for _, order := range [][]string{{"fc-off", "fc-mixed"}, {"fc-mixed", "fc-off"}} {
			w := fcWorldWith(t, issuer, clientsByClientID{
				"fc-off":   {ClientID: "fc-off", FrontchannelLogoutURI: offIssuer},
				"fc-mixed": {ClientID: "fc-mixed", FrontchannelLogoutURI: tc.uri},
			}, order)
			rec := w.logout("/api/v1/oidc/logout")
			if rec.Code != http.StatusOK {
				t.Fatalf("%s %v: end_session = %d; want the page carrying the frames", tc.name, order, rec.Code)
			}
			csp := rec.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, "frame-src ") || !strings.Contains(csp, "https://other.example") || !strings.Contains(csp, tc.frameSrc) {
				t.Errorf("%s %v: CSP %q; want a frame-src admitting both receivers", tc.name, order, csp)
			}
			got := sandboxOf(t, rec.Body.String())
			if len(got) != 2 {
				t.Fatalf("%s %v: frames = %v; want both receivers framed", tc.name, order, got)
			}
			for src, sandbox := range got {
				if sandbox != sandboxSameOrigin {
					t.Errorf("%s %v: frame %s sandbox = %q; want %q on every frame of a mixed fan-out", tc.name, order, src, sandbox, sandboxSameOrigin)
				}
			}
			assertNoParentControl(t, rec.Body.String(), csp)
		}
	}
}

// The page-wide sandbox helper: one restricting receiver anywhere in the
// fan-out restricts every frame; only a fan-out of receivers all positively
// off the issuer's origin keeps allow-same-origin.
func TestFrontchannelFanoutSandbox(t *testing.T) {
	const issuer = "https://idp.test"
	for _, tc := range []struct {
		srcs []string
		want string
	}{
		{[]string{"https://a.example/fc", "https://b.example/fc"}, sandboxCrossOrigin},
		{[]string{"https://a.example/fc", "https://idp.test:8443/fc"}, sandboxCrossOrigin},
		{[]string{"https://a.example/fc", "https://idp.test/rp/fc"}, sandboxSameOrigin},
		{[]string{"https://idp.test/rp/fc", "https://a.example/fc"}, sandboxSameOrigin},
		{[]string{"https://a.example/fc", "https://bücher.example/fc"}, sandboxSameOrigin},
		{[]string{"https://a.example/fc", "https://*.idp.test/fc"}, sandboxSameOrigin},
		{[]string{"https://a.example/fc", "https://a_b.example/fc"}, sandboxSameOrigin},
	} {
		if got := frontchannelFanoutSandbox(tc.srcs, issuer); got != tc.want {
			t.Errorf("frontchannelFanoutSandbox(%q) = %q, want %q", tc.srcs, got, tc.want)
		}
	}
	if got := frontchannelFanoutSandbox([]string{"https://a.example/fc"}, ""); got != sandboxSameOrigin {
		t.Errorf("without an issuer = %q, want %q", got, sandboxSameOrigin)
	}
}
