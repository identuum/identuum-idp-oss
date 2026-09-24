package handlers

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
)

// Owner decision D3 (Plan C; ruled for v0.6.0): the refresh_token cookie is
// scoped to the browser boundary's session routes, Path=/bff/session/, so
// the browser sends it only to /bff/session/refresh and /bff/session/logout
// — never with every page or API request. The access_token cookie stays at
// Path=/. Judged with a real cookie jar, the way a browser matches paths.
func TestD3_RefreshCookieReachesOnlyTheBFFSessionRoutes(t *testing.T) {
	cookies := captureCookies(t, "localhost:7113", func(c *gin.Context) {
		setAuthCookies(c, "token-A", "refresh-B", true)
	})
	jar, _ := cookiejar.New(nil)
	origin, _ := url.Parse("http://localhost:7113/bff/api/v1/auth/login")
	jar.SetCookies(origin, cookies)
	sent := func(path string) map[string]bool {
		u, _ := url.Parse("http://localhost:7113" + path)
		out := map[string]bool{}
		for _, c := range jar.Cookies(u) {
			out[c.Name] = true
		}
		return out
	}
	for _, p := range []string{"/bff/session/refresh", "/bff/session/logout"} {
		if !sent(p)["refresh_token"] {
			t.Errorf("the browser does not send refresh_token to %s", p)
		}
	}
	for _, p := range []string{"/", "/site-admin", "/bff/api/v1/validate", "/api/v1/auth/login", "/api/v1/auth/logout"} {
		if sent(p)["refresh_token"] {
			t.Errorf("the browser sends refresh_token to %s; D3 scopes it to /bff/session/", p)
		}
	}
	for _, p := range []string{"/", "/bff/api/v1/validate"} {
		if !sent(p)["access_token"] {
			t.Errorf("access_token no longer reaches %s", p)
		}
	}
}

// Clearing expires the refresh cookie at BOTH paths: the scoped one, and the
// Path=/ cookie every earlier release set, which a browser that signed in
// before the upgrade still holds.
func TestD3_ClearExpiresTheScopedAndTheLegacyRootRefreshCookie(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	origin, _ := url.Parse("http://localhost:7113/")
	jar.SetCookies(origin, []*http.Cookie{
		{Name: "refresh_token", Value: "legacy", Path: "/", MaxAge: 600, HttpOnly: true},
		{Name: "refresh_token", Value: "scoped", Path: "/bff/session/", MaxAge: 600, HttpOnly: true},
		{Name: "access_token", Value: "access", Path: "/", MaxAge: 600, HttpOnly: true},
	})
	cleared := captureCookies(t, "localhost:7113", func(c *gin.Context) { clearAuthCookies(c) })
	jar.SetCookies(origin, cleared)
	for _, p := range []string{"/bff/session/refresh", "/bff/session/logout", "/", "/site-admin"} {
		u, _ := url.Parse("http://localhost:7113" + p)
		for _, c := range jar.Cookies(u) {
			t.Errorf("after clearAuthCookies the browser still sends %s (to %s)", c.Name, p)
		}
	}
}
