package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// THE-UI-THAT-GO-CAN-SERVE (Plan B): proofs for the static export serving and
// the narrow BFF in ui.go. Every test drives the WHOLE engine (NewOSSEngine),
// so the global middleware — BearerPrincipal included — is the real one; only
// the token verifier is a stub, and the probe routes stand in for resource
// handlers whose services are not wired in a minimal engine.

// uiStubVerifier maps token → principal; anything else is refused the way the
// real verifier refuses (an error), which BearerPrincipal turns into 401
// token_invalid.
type uiStubVerifier struct{ principals map[string]*domain.Principal }

func (v uiStubVerifier) VerifyBearerToken(_ context.Context, token string) (*domain.Principal, error) {
	if p, ok := v.principals[token]; ok {
		return p, nil
	}
	return nil, errors.New("stub: unknown token")
}

// uiExportDir writes a minimal export: a shell, one hashed asset, and a file
// OUTSIDE the export root that must never be reachable.
func uiExportDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "ui")
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	must := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must(filepath.Join(dir, "index.html"), "<!doctype html><title>shell</title>")
	must(filepath.Join(dir, "assets", "app-abc123.js"), "console.log('app')")
	must(filepath.Join(dir, ".hidden"), "hidden")
	must(filepath.Join(root, "secret.txt"), "outside the export root")
	return dir
}

func uiPrincipal(email string) *domain.Principal {
	return &domain.Principal{Email: email, Role: domain.UserRole("org_user"), UserID: uuid.New(), SessionID: uuid.New()}
}

// uiEngine builds the real engine with the UI mounted and registers the probe
// routes the BFF proofs dispatch to. The probes run behind the same global
// middleware as every resource route.
func uiEngine(t *testing.T, dir string, allowed ...string) *gin.Engine {
	t.Helper()
	verifier := uiStubVerifier{principals: map[string]*domain.Principal{
		"good":  uiPrincipal("alice@example.test"),
		"other": uiPrincipal("bob@example.test"),
	}}
	e := NewOSSEngine(OSSRouterDeps{UIStaticDir: dir, TokenVerifier: verifier, CORSAllowedOrigins: allowed})
	echo := func(c *gin.Context) {
		who := "anonymous"
		if p, ok := mw.PrincipalFromContext(c); ok {
			who = p.Email
		}
		c.JSON(http.StatusOK, gin.H{
			"who":           who,
			"cookie_header": c.GetHeader("Cookie") != "",
			"authorization": c.GetHeader("Authorization") != "",
			"method":        c.Request.Method,
			"query":         c.Request.URL.RawQuery,
		})
	}
	e.GET("/api/v1/probe", echo)
	e.POST("/api/v1/probe", echo)
	e.GET("/api/v1/guarded", mw.RequireAuthenticated(), echo)
	e.GET("/api/v1/handler401", func(c *gin.Context) {
		who := "anonymous"
		if p, ok := mw.PrincipalFromContext(c); ok {
			who = p.Email
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "reason": "handler_says_so", "who": who})
	})
	e.POST("/api/v1/setcookie", func(c *gin.Context) {
		c.Header("Set-Cookie", "probe=1; Path=/; HttpOnly")
		c.Status(http.StatusNoContent)
	})
	// A login-shaped route: mints the browser cookies AND echoes the tokens in
	// the JSON body, as HandleLocalLogin does (auth_sessions.go:428-447).
	e.POST("/api/v1/auth/probe-login", func(c *gin.Context) {
		c.Writer.Header().Add("Set-Cookie", "access_token=minted; Path=/; HttpOnly; SameSite=Lax")
		c.Writer.Header().Add("Set-Cookie", "refresh_token=minted-r; Path=/; HttpOnly; SameSite=Lax")
		c.JSON(http.StatusOK, gin.H{
			"user_id": "u1", "session_id": "s1", "role": "org_user", "email": "alice@example.test",
			"access_token": "minted", "refresh_token": "minted-r", "token_type": "Bearer", "expires_in": 900,
		})
	})
	return e
}

func TestUI_BFF_RedactsBodyTokensWhenTheCookieCarriesThem(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	rec := uiPost(e, "/bff/api/v1/auth/probe-login", withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue))
	if rec.Code != http.StatusOK {
		t.Fatalf("login through the boundary: %d %q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, leaked := range []string{`"access_token"`, `"refresh_token"`, `minted`} {
		if strings.Contains(body, leaked) {
			t.Fatalf("a token reached page script through the boundary: body %q contains %q", body, leaked)
		}
	}
	for _, kept := range []string{`"role":"org_user"`, `"session_id":"s1"`, `"email":"alice@example.test"`} {
		if !strings.Contains(body, kept) {
			t.Fatalf("redaction removed more than the tokens: body %q lacks %q", body, kept)
		}
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 2 {
		t.Fatalf("the cookies must still reach the browser: Set-Cookie = %v", got)
	}
	// The direct route is untouched: a non-browser API client still gets the
	// body tokens it always did.
	rec = uiPost(e, "/api/v1/auth/probe-login")
	if !strings.Contains(rec.Body.String(), `"access_token":"minted"`) {
		t.Fatalf("the direct route must be unchanged: %q", rec.Body.String())
	}
}

func uiGet(e http.Handler, target string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, m := range mutate {
		m(req)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func uiPost(e http.Handler, target string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{"x":1}`))
	req.Header.Set("Content-Type", "application/json")
	for _, m := range mutate {
		m(req)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func withCookie(v string) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "access_token", Value: v}) }
}

func withHeader(k, v string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(k, v) }
}

// ---------------------------------------------------------------- default

func TestUI_NotMountedByDefault(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	for _, target := range []string{"/", "/login", "/bff/api/v1/probe"} {
		rec := uiGet(e, target)
		if rec.Code != http.StatusNotFound || strings.TrimSpace(rec.Body.String()) != uiGinNotFoundBody {
			t.Fatalf("%s without UIStaticDir: got %d %q, want gin's plain 404", target, rec.Code, rec.Body.String())
		}
	}
}

func TestUI_MissingShellRecordsFatalFault(t *testing.T) {
	report := lifecycle.NewStartupReport()
	NewOSSEngine(OSSRouterDeps{UIStaticDir: filepath.Join(t.TempDir(), "absent"), StartupReport: report})
	if !report.HasFatal() {
		t.Fatal("a UIStaticDir with no index.html must record a fatal fault (P-018), not serve an empty UI")
	}
}

// ---------------------------------------------------------------- static

func TestUI_ServesShellAndAssets(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))

	rec := uiGet(e, "/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "shell") {
		t.Fatalf("GET /: %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != uiShellCacheControl {
		t.Fatalf("shell Cache-Control = %q, want %q", got, uiShellCacheControl)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("shell Content-Type = %q", ct)
	}

	rec = uiGet(e, "/assets/app-abc123.js")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "console.log") {
		t.Fatalf("asset: %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != uiAssetCacheControl {
		t.Fatalf("asset Cache-Control = %q, want %q", got, uiAssetCacheControl)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("asset Content-Type = %q", ct)
	}
	// Security headers come from the global chain and reach static responses.
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("static response lost the global security headers: X-Content-Type-Options = %q", got)
	}
}

func TestUI_SPAFallbackOnlyForShellPaths(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	for _, target := range []string{"/login", "/org-admin/users/0f1e2d3c-0000-4000-8000-000000000001", "/org-admin/users/other-id"} {
		rec := uiGet(e, target)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "shell") {
			t.Fatalf("%s: %d %q, want the shell", target, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Cache-Control"); got != uiShellCacheControl {
			t.Fatalf("%s: shell fallback Cache-Control = %q", target, got)
		}
	}
	// A missing ASSET path is a 404, never the shell: a script URL must not
	// come back as HTML.
	rec := uiGet(e, "/assets/missing-9f9f9f.js")
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "shell") {
		t.Fatalf("missing asset: %d %q, want 404 without the shell", rec.Code, rec.Body.String())
	}
}

func TestUI_ReservedSurfaceNeverBecomesTheShell(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	for _, target := range []string{"/api/v1/does-not-exist", "/api/nope", "/.well-known/nope", "/system/nope", "/bff", "/bff/nope", "/health/extra"} {
		rec := uiGet(e, target)
		if strings.Contains(rec.Body.String(), "shell") {
			t.Fatalf("%s: the shell leaked onto the API surface: %d %q", target, rec.Code, rec.Body.String())
		}
	}
	// Unknown API paths keep gin's plain 404 exactly as before the UI existed.
	rec := uiGet(e, "/api/v1/does-not-exist")
	if rec.Code != http.StatusNotFound || strings.TrimSpace(rec.Body.String()) != uiGinNotFoundBody {
		t.Fatalf("unknown API path: %d %q", rec.Code, rec.Body.String())
	}
	// The probes themselves still answer: the NoRoute fallback is a fallback.
	if rec := uiGet(e, "/health"); rec.Code != http.StatusOK {
		t.Fatalf("/health under the UI mount: %d", rec.Code)
	}
}

func TestUI_StaticRefusesTraversalDotfilesAndUnsafeMethods(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	for _, target := range []string{"/../secret.txt", "/%2e%2e/secret.txt", "/assets/../../secret.txt", "/.hidden", "/assets/%2e%2e/%2e%2e/secret.txt"} {
		rec := uiGet(e, target)
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "outside") || strings.Contains(rec.Body.String(), "hidden") {
			t.Fatalf("%s: %d %q — must be a plain 404", target, rec.Code, rec.Body.String())
		}
	}
	rec := uiPost(e, "/login")
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "shell") {
		t.Fatalf("POST /login: %d %q, want a plain 404", rec.Code, rec.Body.String())
	}
	if rec := uiGet(e, "/assets/app-abc123.js", func(r *http.Request) { r.Method = http.MethodHead }); rec.Code != http.StatusOK {
		t.Fatalf("HEAD asset: %d", rec.Code)
	}
}

// ---------------------------------------------------------------- BFF: lift

func TestUI_BFF_LiftsCookieAndNeverForwardsIt(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	rec := uiGet(e, "/bff/api/v1/probe?x=1", withCookie("good"), bffProof)
	if rec.Code != http.StatusOK {
		t.Fatalf("lifted GET: %d %q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"who":"alice@example.test"`, `"cookie_header":false`, `"authorization":true`, `"query":"x=1"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("lifted GET body %q lacks %q", body, want)
		}
	}
}

func TestUI_BFF_ExplicitBearerBeatsCookie(t *testing.T) {
	// Conflicting identities: cookie says alice, the Authorization header says
	// bob. The header wins and the cookie is never consulted.
	e := uiEngine(t, uiExportDir(t))
	rec := uiGet(e, "/bff/api/v1/probe", withCookie("good"), withHeader("Authorization", "Bearer other"), bffProof)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"who":"bob@example.test"`) {
		t.Fatalf("precedence: %d %q, want bob", rec.Code, rec.Body.String())
	}
	// A bad explicit Bearer beside a good cookie is refused, not rescued by
	// the cookie: the middleware's verdict on the header stands.
	rec = uiGet(e, "/bff/api/v1/probe", withCookie("good"), withHeader("Authorization", "Bearer bogus"), bffProof)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad header beside good cookie: %d %q, want 401", rec.Code, rec.Body.String())
	}
}

func TestUI_BFF_NoCredentialIsAnonymous(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	rec := uiGet(e, "/bff/api/v1/probe", bffProof)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"who":"anonymous"`) {
		t.Fatalf("no credential: %d %q", rec.Code, rec.Body.String())
	}
	rec = uiGet(e, "/bff/api/v1/guarded", bffProof)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"reason":"no_credential"`) {
		t.Fatalf("guarded without credential: %d %q, want 401 no_credential", rec.Code, rec.Body.String())
	}
}

// ------------------------------------------------------ BFF: stale cookie

func TestUI_BFF_StaleCookieRetriesOnceAnonymously(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	// The middleware's own refusal shape, measured rather than assumed: this
	// is what the retry keys on.
	rec := uiGet(e, "/api/v1/probe", withHeader("Authorization", "Bearer stale"))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"reason":"token_invalid"`) {
		t.Fatalf("direct stale bearer: %d %q, want the middleware's 401 token_invalid", rec.Code, rec.Body.String())
	}
	// Through the BFF a stale COOKIE is retried anonymously, so a public
	// endpoint still answers (THE-STALE-COOKIE)...
	rec = uiGet(e, "/bff/api/v1/probe", withCookie("stale"), bffProof)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"who":"anonymous"`) {
		t.Fatalf("stale cookie on a public route: %d %q, want 200 anonymous", rec.Code, rec.Body.String())
	}
	// ...and a guarded endpoint refuses with no_credential, not token_invalid.
	rec = uiGet(e, "/bff/api/v1/guarded", withCookie("stale"), bffProof)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"reason":"no_credential"`) {
		t.Fatalf("stale cookie on a guarded route: %d %q, want 401 no_credential", rec.Code, rec.Body.String())
	}
}

func TestUI_BFF_HandlerRefusalIsNeverRetried(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	rec := uiGet(e, "/bff/api/v1/handler401", withCookie("good"), bffProof)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"reason":"handler_says_so"`) || !strings.Contains(rec.Body.String(), `"who":"alice@example.test"`) {
		t.Fatalf("handler 401 with a good cookie: %d %q — must pass through unchanged, with the principal the handler saw", rec.Code, rec.Body.String())
	}
}

// ------------------------------------------------------------- BFF: CSRF

func TestUI_BFF_UnsafeMethodRequiresRequestHeader_WithCredentials(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	// The cookie IS attached: the refusal is the server's, not the browser's
	// SameSite rules withholding the credential.
	rec := uiPost(e, "/bff/api/v1/probe", withCookie("good"))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"csrf_failed"`) || !strings.Contains(rec.Body.String(), `"missing_request_header"`) {
		t.Fatalf("POST without the request header, cookie attached: %d %q, want 403 csrf_failed", rec.Code, rec.Body.String())
	}
	rec = uiPost(e, "/bff/api/v1/probe", withCookie("good"), withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"who":"alice@example.test"`) || !strings.Contains(rec.Body.String(), `"method":"POST"`) {
		t.Fatalf("POST with the request header: %d %q, want 200 as alice", rec.Code, rec.Body.String())
	}
	// Owner decision D1 (2026-09-23) reverses the old "a safe method needs no
	// header": a GET without it is refused too, with the cookie attached.
	if rec := uiGet(e, "/bff/api/v1/probe", withCookie("good")); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"missing_request_header"`) {
		t.Fatalf("GET without the header: %d %q, want 403 csrf_failed", rec.Code, rec.Body.String())
	}
}

func TestUI_BFF_OriginMustBeThisHostOrAllowlisted(t *testing.T) {
	const allowed = "https://console.example.test"
	e := uiEngine(t, uiExportDir(t), allowed)
	hdr := withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue)
	cases := []struct {
		origin string
		code   int
	}{
		{"http://example.com", http.StatusOK}, // httptest's request Host
		{allowed, http.StatusOK},              // exact allowlist entry
		{"https://evil.example", http.StatusForbidden},
		{"https://sub.example.com", http.StatusForbidden}, // a subdomain is not this host
		{"null", http.StatusForbidden},
	}
	for _, tc := range cases {
		rec := uiPost(e, "/bff/api/v1/probe", withCookie("good"), hdr, withHeader("Origin", tc.origin))
		if rec.Code != tc.code {
			t.Fatalf("Origin %q: %d %q, want %d", tc.origin, rec.Code, rec.Body.String(), tc.code)
		}
		if tc.code == http.StatusForbidden && !strings.Contains(rec.Body.String(), `"origin_not_permitted"`) {
			t.Fatalf("Origin %q: refusal must name the origin: %q", tc.origin, rec.Body.String())
		}
	}
}

// -------------------------------------------------- BFF: destinations

func TestUI_BFF_OnlyAPIv1IsReachable(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	for _, target := range []string{"/bff/health", "/bff/api/setup/status", "/bff/.well-known/openid-configuration", "/bff/bff/api/v1/probe", "/bff/api/v2/x", "/bff/system/info"} {
		rec := uiGet(e, target, withCookie("good"))
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"bff_destination_refused"`) {
			t.Fatalf("%s: %d %q, want 404 bff_destination_refused", target, rec.Code, rec.Body.String())
		}
	}
}

func TestUI_BFF_PassesResponseHeadersThrough(t *testing.T) {
	e := uiEngine(t, uiExportDir(t))
	rec := uiPost(e, "/bff/api/v1/setcookie", withCookie("good"), withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("setcookie: %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 1 || !strings.HasPrefix(got[0], "probe=1") {
		t.Fatalf("Set-Cookie through the BFF = %v", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("security headers on a BFF response: %q", got)
	}
}

// ---------------------------------------------------------- BFF: logout

// uiLogoutEngine registers a stand-in for /api/v1/auth/logout (the real
// route needs a session service the minimal engine does not wire) that
// answers `status` and, on 204, clears the cookies exactly as HandleLogout
// does through the same exported helper.
func uiLogoutEngine(t *testing.T, status int) (*gin.Engine, *int) {
	t.Helper()
	e := uiEngine(t, uiExportDir(t))
	seen := 0
	e.POST("/api/v1/auth/logout", func(c *gin.Context) {
		seen++
		if c.GetHeader("Authorization") == "" {
			t.Errorf("the boundary must lift the cookie into a Bearer for the logout it proxies")
		}
		if c.GetHeader("Cookie") != "" {
			t.Errorf("the boundary must not forward the browser's Cookie header")
		}
		if status == http.StatusNoContent {
			handlers.ClearAuthCookies(c)
		}
		c.Status(status)
	})
	return e, &seen
}

func TestUI_BFF_LogoutRevokedPassesGoCookieClearThrough(t *testing.T) {
	e, seen := uiLogoutEngine(t, http.StatusNoContent)
	rec := uiPost(e, uiBFFLogoutPath, withCookie("good"), withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue))
	if rec.Code != http.StatusNoContent || *seen != 1 {
		t.Fatalf("logout through the boundary: %d %q (upstream seen %d)", rec.Code, rec.Body.String(), *seen)
	}
	cleared := 0
	for _, sc := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(sc, "access_token=;") || strings.HasPrefix(sc, "refresh_token=;") {
			cleared++
		}
	}
	if cleared != 2 {
		t.Fatalf("revoked logout must clear both cookies through the boundary; Set-Cookie = %v", rec.Header().Values("Set-Cookie"))
	}
}

func TestUI_BFF_LogoutDuringOutageIsLocalOnlyAndSaysSo(t *testing.T) {
	e, seen := uiLogoutEngine(t, http.StatusServiceUnavailable)
	rec := uiPost(e, uiBFFLogoutPath, withCookie("good"), withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue))
	if rec.Code != http.StatusOK || *seen != 1 {
		t.Fatalf("logout during an upstream 503: %d %q, want 200 local_only", rec.Code, rec.Body.String())
	}
	for _, want := range []string{`"logout":"local_only"`, `"upstream_status":503`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("local-only logout body %q lacks %q", rec.Body.String(), want)
		}
	}
	cleared := 0
	for _, sc := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(sc, "access_token=;") || strings.HasPrefix(sc, "refresh_token=;") {
			cleared++
		}
	}
	if cleared != 2 {
		t.Fatalf("local-only logout must still clear both cookies; Set-Cookie = %v", rec.Header().Values("Set-Cookie"))
	}
}

func TestUI_BFF_LogoutRequiresRequestHeader_WithCredentials(t *testing.T) {
	e, seen := uiLogoutEngine(t, http.StatusNoContent)
	rec := uiPost(e, uiBFFLogoutPath, withCookie("good"))
	if rec.Code != http.StatusForbidden || *seen != 0 || !strings.Contains(rec.Body.String(), `"csrf_failed"`) {
		t.Fatalf("cross-site-shaped logout with the cookie attached: %d %q (upstream seen %d), want 403 and no upstream call", rec.Code, rec.Body.String(), *seen)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("a refused logout must not touch the cookies: %v", got)
	}
}

// THE-UI-THAT-GO-CAN-SERVE outage proof (measured live 2026-09-22 with the
// store paused): HandleLogout swallows store errors and answers 204 only
// once every store call has given up, so an unbounded dispatch hangs the
// browser's sign-out for as long as the store hangs — and then reports a
// revocation that never happened. The boundary bounds the upstream and
// reports the timeout as local-only.
func TestUI_BFF_LogoutBoundsTheUpstreamAndReportsTimeoutAsLocalOnly(t *testing.T) {
	prev := uiLogoutUpstreamTimeout
	uiLogoutUpstreamTimeout = 200 * time.Millisecond
	t.Cleanup(func() { uiLogoutUpstreamTimeout = prev })

	e := uiEngine(t, uiExportDir(t))
	released := make(chan struct{})
	e.POST("/api/v1/auth/logout", func(c *gin.Context) {
		<-c.Request.Context().Done() // the store never answers; the handler gives up with the context
		handlers.ClearAuthCookies(c)
		c.Status(http.StatusNoContent)
		close(released)
	})
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		answered <- uiPost(e, uiBFFLogoutPath, withCookie("good"), withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue))
	}()
	var rec *httptest.ResponseRecorder
	select {
	case rec = <-answered:
	case <-time.After(2 * time.Second):
		t.Fatalf("logout hung against a hanging upstream; the boundary must answer within its bound")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("logout against a hanging upstream: %d %q, want 200 local_only", rec.Code, rec.Body.String())
	}
	for _, want := range []string{`"logout":"local_only"`, `"upstream":"timeout"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("local-only logout body %q lacks %q", rec.Body.String(), want)
		}
	}
	cleared := 0
	for _, sc := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(sc, "access_token=;") || strings.HasPrefix(sc, "refresh_token=;") {
			cleared++
		}
	}
	if cleared != 2 {
		t.Fatalf("local-only logout must still clear both cookies; Set-Cookie = %v", rec.Header().Values("Set-Cookie"))
	}
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatalf("the abandoned upstream must be released by the bound's cancel, not left hanging")
	}
}
