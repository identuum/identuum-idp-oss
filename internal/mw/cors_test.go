package mw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// newCORSRouter builds a minimal gin engine with the CORS middleware for
// the given allowlist and a single GET/PUT test route.
func newCORSRouter(allowedOrigins []string) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(CORS(allowedOrigins))
	r.GET("/x", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	r.PUT("/x", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	return r
}

// (c) DEFAULT / deny-by-default: with an EMPTY allowlist, a cross-origin
// request receives NO Access-Control-Allow-Origin (the browser blocks the
// response), and same-origin / no-Origin traffic is completely unaffected.
func TestCORS_EmptyAllowlist_DeniesCrossOrigin(t *testing.T) {
	for _, allow := range [][]string{nil, {}} {
		r := newCORSRouter(allow)

		// Cross-origin request: an Origin header is present.
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Origin", "https://app.example.com")
		r.ServeHTTP(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("empty allowlist: Access-Control-Allow-Origin = %q, want empty (deny)", got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Errorf("empty allowlist: Access-Control-Allow-Credentials = %q, want empty", got)
		}
		// The underlying handler still runs (same-origin semantics): a
		// non-preflight request is NOT short-circuited.
		if rec.Code != http.StatusOK {
			t.Errorf("empty allowlist: status = %d, want 200 (handler still runs)", rec.Code)
		}
	}
}

// (c) No Origin header (same-origin or non-browser client): the middleware
// must emit no CORS headers and pass through untouched.
func TestCORS_NoOriginHeader_PassThrough(t *testing.T) {
	r := newCORSRouter([]string{"https://app.example.com"})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil)) // no Origin

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("no Origin: Access-Control-Allow-Origin = %q, want empty", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("no Origin: status = %d, want 200", rec.Code)
	}
}

// (d) Allowlisted origin: the EXACT origin is echoed, credentials are
// allowed, Vary: Origin is set, and a preflight short-circuits with 204
// carrying the allow-methods/headers.
func TestCORS_AllowlistedOrigin_EchoedWithCredentials(t *testing.T) {
	const origin = "https://app.example.com"
	r := newCORSRouter([]string{origin})

	// Simple (non-preflight) request.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", origin)
	r.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q (exact echo)", got, origin)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want \"true\"", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want \"Origin\"", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("simple request: status = %d, want 200", rec.Code)
	}

	// Preflight request: OPTIONS + Access-Control-Request-Method.
	pre := httptest.NewRecorder()
	preReq := httptest.NewRequest(http.MethodOptions, "/x", nil)
	preReq.Header.Set("Origin", origin)
	preReq.Header.Set("Access-Control-Request-Method", "PUT")
	r.ServeHTTP(pre, preReq)

	if pre.Code != http.StatusNoContent {
		t.Errorf("preflight: status = %d, want 204", pre.Code)
	}
	if got := pre.Header().Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("preflight: Access-Control-Allow-Origin = %q, want %q", got, origin)
	}
	if got := pre.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("preflight: Access-Control-Allow-Credentials = %q, want \"true\"", got)
	}
	if got := pre.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("preflight: Access-Control-Allow-Methods is empty, want method list")
	}
	if got := pre.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("preflight: Access-Control-Allow-Headers is empty, want header list")
	}
	if got := pre.Header().Get("Access-Control-Max-Age"); got == "" {
		t.Error("preflight: Access-Control-Max-Age is empty, want max-age")
	}
}

// (e) Non-allowlisted origins — including substring and suffix near-matches
// of an allowlisted origin — are REJECTED. This proves EXACT-string matching
// (a suffix/substring match would be an origin-bypass vulnerability).
func TestCORS_NonAllowlistedOrigin_Rejected(t *testing.T) {
	const allowed = "https://app.example.com"
	r := newCORSRouter([]string{allowed})

	// Each of these is a classic origin-bypass probe against the allowed
	// origin. NONE may be granted CORS access.
	rejected := []string{
		"https://evil.com",                    // unrelated
		"https://app.example.com.evil.com",    // suffix-append attack
		"https://evilapp.example.com",         // prefix attack
		"https://app.example.com.attacker.io", // domain-append attack
		"http://app.example.com",              // scheme mismatch
		"https://app.example.com:8443",        // port mismatch
		"https://app.example.co",              // truncation
		"https://sub.app.example.com",         // extra subdomain
	}
	for _, origin := range rejected {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Origin", origin)
		r.ServeHTTP(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin %q: Access-Control-Allow-Origin = %q, want empty (must be rejected — exact match only)", origin, got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Errorf("origin %q: Access-Control-Allow-Credentials = %q, want empty", origin, got)
		}
	}

	// A disallowed PREFLIGHT is answered with a bare 204 and no allow
	// headers — still no CORS access granted.
	pre := httptest.NewRecorder()
	preReq := httptest.NewRequest(http.MethodOptions, "/x", nil)
	preReq.Header.Set("Origin", "https://app.example.com.evil.com")
	preReq.Header.Set("Access-Control-Request-Method", "PUT")
	r.ServeHTTP(pre, preReq)
	if pre.Code != http.StatusNoContent {
		t.Errorf("disallowed preflight: status = %d, want 204", pre.Code)
	}
	if got := pre.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("disallowed preflight: Access-Control-Allow-Origin = %q, want empty", got)
	}
	if got := pre.Header().Get("Access-Control-Allow-Methods"); got != "" {
		t.Errorf("disallowed preflight: Access-Control-Allow-Methods = %q, want empty", got)
	}
}

// (f) The middleware NEVER emits "*" as the allowed origin, and NEVER emits
// "*" together with credentials (the Fetch spec forbids that combination). A
// literal "*" in the allowlist is ignored; a matching request still echoes
// the specific origin, never a wildcard.
func TestCORS_NeverWildcardWithCredentials(t *testing.T) {
	// A literal "*" entry must NOT turn the middleware into allow-all.
	r := newCORSRouter([]string{"*"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://anything.example.com")
	r.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("literal \"*\" allowlist: Access-Control-Allow-Origin = %q, want empty (\"*\" is ignored, not allow-all)", got)
	}

	// With a real allowlist, the echoed origin is the specific request
	// origin — never "*" — so "*" + credentials can never co-occur.
	const origin = "https://app.example.com"
	r2 := newCORSRouter([]string{origin})
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.Header.Set("Origin", origin)
	r2.ServeHTTP(rec2, req2)

	acao := rec2.Header().Get("Access-Control-Allow-Origin")
	acac := rec2.Header().Get("Access-Control-Allow-Credentials")
	if acao == "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, must never be \"*\"", acao)
	}
	if acao == "*" && acac == "true" {
		t.Error("emitted \"*\" together with credentials — forbidden by the Fetch spec")
	}
	if acao != origin {
		t.Errorf("Access-Control-Allow-Origin = %q, want the specific origin %q", acao, origin)
	}
}
