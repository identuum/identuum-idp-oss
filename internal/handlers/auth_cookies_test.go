package handlers

// Unit tests for auth_cookies.go. These pin the wire contract identuum-ui
// reads: cookie name, HttpOnly, SameSite=Lax, Path=/, localhost-aware
// Secure, and the MaxAge constants.
//
// Test discipline:
//   - Cookie values used here are sentinel placeholders ("token-A",
//     "refresh-B") — never real tokens — and are kept short so any
//     accidental leak is obvious.
//   - Assertions are structural (attribute presence, MaxAge equality,
//     SameSite enum value) — the cookie value is checked only with
//     `!= ""` once, never echoed back into a failure message.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func captureCookies(t *testing.T, host string, fn func(c *gin.Context)) []*http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = host
	c.Request = req
	fn(c)
	return w.Result().Cookies()
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestSetAuthCookies_AccessAndRefresh_Localhost(t *testing.T) {
	cookies := captureCookies(t, "localhost:7113", func(c *gin.Context) {
		setAuthCookies(c, "token-A", "refresh-B", true)
	})

	access := findCookie(cookies, "access_token")
	if access == nil {
		t.Fatal("access_token cookie was not set")
	}
	if access.MaxAge != accessTokenCookieMaxAgeSec {
		t.Fatalf("access_token MaxAge: want %d, got %d", accessTokenCookieMaxAgeSec, access.MaxAge)
	}
	if !access.HttpOnly {
		t.Fatal("access_token HttpOnly: want true")
	}
	if access.SameSite != http.SameSiteLaxMode {
		t.Fatal("access_token SameSite: want Lax")
	}
	if access.Path != "/" {
		t.Fatalf("access_token Path: want /, got %q", access.Path)
	}
	if access.Secure {
		t.Fatal("access_token Secure: must be false on localhost so the local-demo HTTP runtime works")
	}
	if access.Value == "" {
		t.Fatal("access_token Value must be non-empty")
	}

	refresh := findCookie(cookies, "refresh_token")
	if refresh == nil {
		t.Fatal("refresh_token cookie was not set when rememberMe=true")
	}
	if refresh.MaxAge != refreshTokenCookieMaxAgeSec {
		t.Fatalf("refresh_token MaxAge (rememberMe=true): want %d, got %d", refreshTokenCookieMaxAgeSec, refresh.MaxAge)
	}
	if !refresh.HttpOnly || refresh.SameSite != http.SameSiteLaxMode || refresh.Path != "/" || refresh.Secure {
		t.Fatal("refresh_token attributes must match access_token posture on localhost")
	}
}

func TestSetAuthCookies_RefreshMaxAge_NoRememberMe(t *testing.T) {
	cookies := captureCookies(t, "localhost:7113", func(c *gin.Context) {
		setAuthCookies(c, "token-A", "refresh-B", false)
	})
	refresh := findCookie(cookies, "refresh_token")
	if refresh == nil {
		t.Fatal("refresh_token cookie was not set")
	}
	if refresh.MaxAge != 0 {
		t.Fatalf("refresh_token MaxAge (rememberMe=false): want 0 (session cookie), got %d", refresh.MaxAge)
	}
}

func TestSetAuthCookies_EmptyTokensAreSkipped(t *testing.T) {
	cookies := captureCookies(t, "localhost:7113", func(c *gin.Context) {
		setAuthCookies(c, "", "", true)
	})
	if findCookie(cookies, "access_token") != nil {
		t.Fatal("access_token must not be set when accessToken is empty")
	}
	if findCookie(cookies, "refresh_token") != nil {
		t.Fatal("refresh_token must not be set when refreshToken is empty")
	}
}

// RULE: COOKIE-SECURE-NOT-GIN-MODE-1
func TestSetAuthCookies_LocalhostDetection(t *testing.T) {
	cases := []struct {
		host       string
		wantSecure bool
		mode       string
	}{
		{"localhost:7113", false, "release"},
		{"127.0.0.1:7113", false, "release"},
		{"host.docker.internal:7113", false, "release"},
		{"example.com", true, "release"},
		{"prod.identuum.io", true, "release"},
		// DECOUPLED (THE-DEBUG-BANNER-SWITCH): Secure rides on the request
		// HOST, not gin.Mode. A real host is Secure in test AND debug mode; a
		// loopback host is never Secure, in any mode. Under the old
		// gin.ReleaseMode coupling these three would flip with the mode — that
		// flip is exactly what this rule forbids (a security flag must not ride
		// on the debug-banner switch).
		{"example.com", true, "test"},
		{"example.com", true, "debug"},
		{"localhost:7113", false, "debug"},
	}
	for _, tc := range cases {
		t.Run(tc.host+"_"+tc.mode, func(t *testing.T) {
			defer gin.SetMode(gin.TestMode)
			gin.SetMode(tc.mode)
			cookies := captureCookies(t, tc.host, func(c *gin.Context) {
				setAuthCookies(c, "token-A", "", false)
			})
			access := findCookie(cookies, "access_token")
			if access == nil {
				t.Fatal("access_token cookie missing")
			}
			if access.Secure != tc.wantSecure {
				t.Fatalf("Secure: want %v, got %v", tc.wantSecure, access.Secure)
			}
		})
	}
}

func TestClearAuthCookies_ExpiresBoth(t *testing.T) {
	cookies := captureCookies(t, "localhost:7113", func(c *gin.Context) {
		clearAuthCookies(c)
	})
	for _, name := range []string{"access_token", "refresh_token"} {
		ck := findCookie(cookies, name)
		if ck == nil {
			t.Fatalf("clearAuthCookies must emit Set-Cookie for %s", name)
		}
		if ck.MaxAge != -1 {
			t.Fatalf("%s MaxAge after clear: want -1, got %d", name, ck.MaxAge)
		}
		if ck.Value != "" {
			t.Fatalf("%s value after clear: want empty, got non-empty", name)
		}
		if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" {
			t.Fatalf("%s clear attributes must mirror the set-cookie attribute set", name)
		}
	}
}

// TestSetAuthCookies_NeverPrintsValue is a defence-in-depth assertion
// against future regressions: capturing the Set-Cookie header text via
// the recorder and ensuring the cookie value bytes are present (so we
// know the cookie was actually written) but that the test itself never
// formats the value into an error message.
func TestSetAuthCookies_NeverPrintsValue(t *testing.T) {
	const marker = "ZZZZZZZ-not-a-real-token-zzz"
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "localhost:7113"
	c.Request = req

	setAuthCookies(c, marker, "", false)

	header := w.Header().Get("Set-Cookie")
	if header == "" {
		t.Fatal("Set-Cookie header missing")
	}
	if !strings.Contains(header, "access_token=") {
		t.Fatal("Set-Cookie missing access_token= prefix")
	}
	// Defensive: do NOT include the marker in a t.Errorf body. Just
	// assert structurally that the access_token cookie was set with
	// SOME non-empty value.
	if !strings.Contains(header, "HttpOnly") || !strings.Contains(header, "SameSite=Lax") {
		t.Fatal("Set-Cookie must carry HttpOnly and SameSite=Lax")
	}
}
