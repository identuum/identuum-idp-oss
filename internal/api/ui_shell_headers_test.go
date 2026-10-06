package api

import (
	"testing"
)

// UI-SEC-HEADERS (review UI-XSS-REVIEW-2026-10-06, M1 and M2): every response
// that serves the console shell carries a script policy and no-referrer, on
// the whole engine (the global security-header middleware included). The
// account-link pages (/claim, /invite, /reset-link) carry a one-time
// credential in their URL; no-referrer keeps it out of every Referer header.
// The literal values are pinned here, not read from the constants.

const wantShellCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; " +
	"connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

func TestUI_ShellCarriesScriptPolicyAndNoReferrer(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	for _, p := range []string{"/", "/index.html", "/login", "/claim?token=opaque", "/invite?token=opaque", "/reset-link?token=opaque", "/site-admin/organizations", "/org-admin/settings"} {
		rec := uiGet(e, p)
		if rec.Code != 200 {
			t.Fatalf("%s: status %d, want the shell (200)", p, rec.Code)
		}
		h := rec.Header()
		if got := h.Get("Content-Security-Policy"); got != wantShellCSP {
			t.Errorf("%s: Content-Security-Policy = %q, want %q", p, got, wantShellCSP)
		}
		if got := h.Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s: Referrer-Policy = %q, want no-referrer", p, got)
		}
		// The global headers stay as they are.
		if h.Get("Strict-Transport-Security") != "max-age=63072000; includeSubDomains" || h.Get("X-Frame-Options") != "DENY" || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: a global security header changed: HSTS %q, XFO %q, nosniff %q", p,
				h.Get("Strict-Transport-Security"), h.Get("X-Frame-Options"), h.Get("X-Content-Type-Options"))
		}
		if h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: shell Cache-Control = %q, want no-store", p, h.Get("Cache-Control"))
		}
	}
}

func TestUI_APIResponsesKeepTheGlobalHeaders(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	rec := uiGet(e, "/api/v1/probe")
	if rec.Code != 200 {
		t.Fatalf("probe status %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Errorf("API Content-Security-Policy = %q, want today's frame-ancestors 'none'", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Errorf("API Referrer-Policy = %q, want today's strict-origin-when-cross-origin", got)
	}
}
