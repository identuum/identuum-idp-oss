package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The OAuth authorize endpoint issues a code redirect only to a redirect_uri
// that byte-exact-matches one registered for the client; an unregistered or
// prefix-extended redirect_uri is refused with a direct 400 and NEVER
// receives a redirect (so the endpoint cannot be turned into an open
// redirector). Driven through the routed HandleAuthorize (the public path);
// the assertions are the HTTP status and Location the caller actually gets.
// RULE: AUTHORIZE-REDIRECT-EXACT-1
func TestAuthorize_RedirectURIExactMatchOrDirect400(t *testing.T) {
	client := preApprovedClient() // registered: https://app.example.com/cb
	r := authorizeEngine(t, client, authorizePrincipal())

	base := map[string]string{
		"client_id":             "cli-1",
		"response_type":         "code",
		"scope":                 "openid",
		"state":                 "xyz",
		"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
	}
	with := func(uri string) string {
		m := map[string]string{"redirect_uri": uri}
		for k, v := range base {
			m[k] = v
		}
		return authorizeURL(m)
	}

	// Registered exact → 302 whose Location points at the registered URI.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, with("https://app.example.com/cb"), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("PREMISE FAILED: registered redirect_uri must get a 302, got %d body=%q", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "https://app.example.com/cb") {
		t.Fatalf("PREMISE FAILED: 302 Location must be the registered redirect_uri, got %q", loc)
	}

	// Each attacker-shaped redirect_uri must be a DIRECT 400 with NO Location.
	for _, evil := range []string{
		"https://evil.example.com/cb",           // unregistered host
		"https://app.example.com/cb/../../evil", // path traversal off the registered prefix
		"https://app.example.com/cb.evil.com",   // suffix extension
		"https://app.example.com/cb?x=1",        // query-extended
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, with(evil), nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("unregistered redirect_uri %q must be a direct 400, got %d body=%q", evil, w.Code, w.Body.String())
		}
		if loc := w.Header().Get("Location"); loc != "" {
			t.Errorf("unregistered redirect_uri %q must NOT receive a redirect, got Location=%q", evil, loc)
		}
	}
}
