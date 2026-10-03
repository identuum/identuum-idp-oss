package safehttp

import (
	"net/http"
	"testing"
)

func redirectReq(t *testing.T, method, target string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The outbound client follows a redirect only for a GET, only to https on the
// same host, and at most three times. A POST (token exchange, back-channel
// logout) follows none, so its body is never sent to a second URL.
func TestSafeClient_RedirectPolicy(t *testing.T) {
	c := NewSafeClient()
	if c.CheckRedirect == nil {
		t.Fatal("the safe client must carry a redirect policy")
	}
	get := redirectReq(t, http.MethodGet, "https://idp.example/.well-known/openid-configuration")
	post := redirectReq(t, http.MethodPost, "https://idp.example/token")

	if err := c.CheckRedirect(redirectReq(t, http.MethodGet, "https://idp.example/other"), []*http.Request{get}); err != nil {
		t.Errorf("GET https same-host redirect must be followed, got %v", err)
	}
	for name, tc := range map[string]struct {
		next *http.Request
		via  []*http.Request
	}{
		"https to http":     {redirectReq(t, http.MethodGet, "http://idp.example/x"), []*http.Request{get}},
		"other host":        {redirectReq(t, http.MethodGet, "https://other.example/x"), []*http.Request{get}},
		"after POST":        {redirectReq(t, http.MethodPost, "https://idp.example/x"), []*http.Request{post}},
		"POST turned GET":   {redirectReq(t, http.MethodGet, "https://idp.example/x"), []*http.Request{post}},
		"fourth redirect":   {redirectReq(t, http.MethodGet, "https://idp.example/x"), []*http.Request{get, get, get}},
		"userinfo in URL":   {redirectReq(t, http.MethodGet, "https://u:p@idp.example/x"), []*http.Request{get}},
		"different port":    {redirectReq(t, http.MethodGet, "https://idp.example:8443/x"), []*http.Request{get}},
	} {
		if err := c.CheckRedirect(tc.next, tc.via); err == nil {
			t.Errorf("%s: redirect must be refused", name)
		}
	}
}
