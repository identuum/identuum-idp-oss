package domain

import "testing"

// A registered redirect URI has no fragment (RFC 6749 §3.1.2) and no
// userinfo; an http(s) URI names a host; plain http is accepted only on a
// loopback host. Private-use native-app schemes stay accepted (RFC 8252).
func TestValidateRedirectURIs_FragmentHostAndPlainHTTP(t *testing.T) {
	for _, ok := range []string{
		"https://app.example.com/cb",
		"http://127.0.0.1:9999/callback",
		"http://localhost:3000/cb",
		"http://[::1]:8080/cb",
		"com.example.app:/oauth2redirect",
	} {
		if err := ValidateRedirectURIs([]string{ok}); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"https://app.example.com/cb#frag",
		"http://app.example.com/cb",
		"https://user:pw@app.example.com/cb",
		"https:///cb",
		"http://10.0.0.5/cb",
	} {
		if err := ValidateRedirectURIs([]string{bad}); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}
