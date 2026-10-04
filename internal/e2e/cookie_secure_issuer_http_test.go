//go:build integration

package e2e

import (
	"net/http"
	"testing"
)

// The Secure flag follows the configured issuer. The sign-in page sets a CSRF
// cookie; reached over plain http on a loopback address, it is Secure when the
// issuer is https and is not when the issuer is the local http one.
func TestE2E_OSS_CookieSecureFollowsTheConfiguredIssuer(t *testing.T) {
	secureOf := func(env map[string]string) (bool, int) {
		w := startInviteEngine(t, env)
		res, err := http.Get(w.base + "/api/v1/auth/browser-login")
		if err != nil {
			t.Fatalf("GET browser-login: %v", err)
		}
		defer res.Body.Close()
		cookies := res.Cookies()
		if len(cookies) == 0 {
			t.Fatalf("the sign-in page set no cookie (status %d)", res.StatusCode)
		}
		for _, c := range cookies {
			if !c.Secure {
				return false, len(cookies)
			}
		}
		return true, len(cookies)
	}

	base := map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"}
	if secure, n := secureOf(base); secure {
		t.Errorf("local http issuer, loopback host: %d cookie(s) all Secure; want the local-development exception", n)
	}
	https := map[string]string{"UI": inviteUIBase, "ISSUER": "https://idp.invite.test", "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"}
	if secure, n := secureOf(https); !secure {
		t.Errorf("https issuer: %d cookie(s), at least one not Secure; want every cookie Secure", n)
	}
}
