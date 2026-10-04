package handlers

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The passkey step-up page is the one server-rendered page that runs a script.
// Its policy allows exactly that script, by a per-response nonce, and nothing
// else: no inline script without the nonce, no other origin, no framing.
func TestPasskeyStepUpPage_AllowsOnlyItsOwnScriptByNonce(t *testing.T) {
	render := func() (csp, body string) {
		rec := httptest.NewRecorder()
		renderPasskeyStepUpPage(rec, `{"challenge":"c"}`, "ceremony-1", "/back", "")
		return rec.Header().Get("Content-Security-Policy"), rec.Body.String()
	}
	csp, body := render()

	m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]{16,})'`).FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("CSP = %q; want script-src limited to a nonce of at least 16 characters", csp)
	}
	if !strings.Contains(body, `<script nonce="`+m[1]+`">`) {
		t.Errorf("the page's script does not carry the nonce the policy allows")
	}
	for _, want := range []string{"default-src 'none'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "'unsafe-inline'") && strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Errorf("CSP %q allows any inline script", csp)
	}

	// A fresh nonce for every response.
	csp2, _ := render()
	if csp == csp2 {
		t.Error("two responses carried the same nonce")
	}
}
