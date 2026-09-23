package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// THE-UI-THAT-GO-CAN-SERVE (Plan B, 2026-09-22): the OSS binary can serve a
// static UI export and expose ONE narrow browser boundary, the BFF, so that a
// browser holding only the HttpOnly `access_token` cookie can reach the
// bearer-only resource APIs without the token ever being readable by page
// script. Both are OPT-IN: nothing here mounts unless UIStaticDir is set, so a
// binary configured as before behaves as before (no default changes).
//
// What the BFF reproduces from identuum-ui's Next proxy
// (src/app/api/idp/[...path]/route.ts), and why each rule exists:
//
//   - the cookie-to-Bearer LIFT, only when the browser sent no Authorization
//     header — an explicit Bearer always wins, so an M2M caller or a page
//     that carries its own token is never overridden by a cookie;
//   - the browser's Cookie header is NEVER forwarded: the resource APIs are
//     bearer-only and the only cookie-reading JSON routes (validate, logout)
//     are reached directly, not through here;
//   - THE-STALE-COOKIE: when the lift was ours and the middleware refused the
//     lifted token (token_invalid / token_revoked / session_not_live), the
//     request is retried ONCE anonymously, so a dead cookie cannot 401 a
//     public endpoint and lock a user out of signing back in. A handler's own
//     401 (any other reason, or a body that is not the middleware's) is never
//     retried;
//   - permitted destinations: only `/api/v1/...`. The setup routes, probes,
//     discovery and the BFF itself are not reachable through the lift.
//
// What the BFF adds that the Next proxy never had, by the settled ruling that
// every browser mutation authorized through a lift needs CSRF protection:
// unsafe methods must carry `X-Requested-With: identuum-ui` (a header no
// cross-site form can set and no non-allowlisted origin can send through
// CORS), and an `Origin` header, when present, must be this host or a
// CORS-allowlisted origin. The check runs BEFORE the lift, so a cookie-bearing
// cross-site POST is refused with the credential attached — the browser's
// SameSite rules are a second wall, not the first.
//
// Static serving is a gin NoRoute fallback with a fixed reservation list: the
// API, discovery, probe and BFF prefixes keep gin's plain 404, an asset path
// that does not exist is 404 (never the shell), dot-segments are refused, and
// only GET/HEAD are served. The app shell is served with Cache-Control:
// no-store; hashed assets under /assets/ are immutable.

const (
	uiBFFPrefix               = "/bff"
	uiBFFPermittedPrefix      = "/api/v1/"
	uiBFFRequiredHeader       = "X-Requested-With"
	uiBFFRequiredHeaderValue  = "identuum-ui"
	uiAccessTokenCookie       = "access_token"
	uiShellFile               = "index.html"
	uiAssetsPrefix            = "assets/"
	uiShellCacheControl       = "no-store"
	uiAssetCacheControl       = "public, max-age=31536000, immutable"
	uiGinNotFoundBody         = "404 page not found"
	uiBFFMiddlewareErrorField = "unauthorized"
)

// uiReservedPrefixes never fall through to the app shell: an unknown path
// under them is an API 404, exactly as before the UI existed.
var uiReservedPrefixes = []string{"/api/", "/.well-known/", "/system/", "/health/", "/livez/", "/metrics/", uiBFFPrefix + "/"}

// uiReservedPaths are exact paths that are never the shell.
var uiReservedPaths = map[string]struct{}{"/health": {}, "/livez": {}, "/metrics": {}, uiBFFPrefix: {}}

// uiStaleCookieReasons are the bearer middleware's own refusals of a token it
// was handed (internal/mw/auth_verdict.go). Only these mean "the cookie we
// lifted is dead"; a handler's 401 carries a different reason or none.
var uiStaleCookieReasons = map[string]struct{}{
	mw.ReasonTokenInvalid:   {},
	mw.ReasonTokenRevoked:   {},
	mw.ReasonSessionNotLive: {},
}

// mountUI mounts the static export and the BFF when UIStaticDir is set. The
// router must be the engine itself (NoRoute and in-process dispatch need it);
// a composed sub-router records a fatal fault rather than silently serving
// nothing, per P-018.
func mountUI(router gin.IRouter, resolved OSSRouterDeps) {
	if resolved.UIStaticDir == "" {
		return
	}
	engine, ok := router.(*gin.Engine)
	if !ok {
		if resolved.StartupReport != nil {
			resolved.StartupReport.Fatal("mountUI", "IDENTUUM_IDP_UI_DIR is set but the UI can only be mounted on the root engine")
		}
		return
	}
	fsys := uiExportFS(resolved.UIStaticDir)
	if info, err := fs.Stat(fsys, uiShellFile); err != nil || info.IsDir() {
		if resolved.StartupReport != nil {
			resolved.StartupReport.Fatal("mountUI", "IDENTUUM_IDP_UI_DIR has no index.html; refusing to serve an empty UI")
		}
		return
	}
	engine.NoRoute(uiStaticHandler(fsys, uiRouteSegments(engine)))
	// ONE catch-all: gin refuses a static sibling beside a `*target`
	// wildcard, so the boundary's own logout is dispatched inside it.
	engine.Any(uiBFFPrefix+"/*target", uiBFFHandler(engine, resolved))
}

// uiExportFS confines every open, including symlink resolution, to the export.
// OpenInRoot closes its temporary root handle; returned files own their handles.
type uiExportFS string

func (root uiExportFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, fs.ErrInvalid
	}
	return os.OpenInRoot(string(root), name)
}

// uiBFFLogoutPath is the boundary's own logout: it proxies the cookie-derived
// revocation and, when the upstream cannot answer, still clears the browser's
// cookies and SAYS so. A page script cannot expire an HttpOnly cookie, and the
// Next proxy did exactly this (identuum-ui src/app/api/auth/logout/route.ts:
// 37-99); without it an outage would leave a user who pressed "sign out"
// still carrying a live cookie.
const uiBFFLogoutPath = uiBFFPrefix + uiBFFLogoutTarget

// uiBFFLogoutTarget is the wildcard value that selects the logout branch.
const uiBFFLogoutTarget = "/session/logout"

// uiLogoutTarget is the canonical JSON logout route the boundary proxies.
const uiLogoutTarget = "/api/v1/auth/logout"

// uiLogoutUpstreamTimeout bounds the proxied revocation even when a store
// takes too long to answer. An immediate failure is reported by HandleLogout;
// a missing answer is reported by the boundary. Variable for the timeout proof.
var uiLogoutUpstreamTimeout = 5 * time.Second

func uiBFFLogout(c *gin.Context, engine *gin.Engine, resolved OSSRouterDeps) {
	if c.Request.Method != http.MethodPost {
		c.JSON(http.StatusNotFound, gin.H{"error": "bff_destination_refused"})
		return
	}
	if uiRefuseWithoutBrowserProof(c, resolved.CORSAllowedOrigins) {
		return
	}
	bearer := c.GetHeader("Authorization")
	var body []byte
	if bearer == "" {
		if tok, err := c.Cookie(uiAccessTokenCookie); err == nil && tok != "" {
			bearer = "Bearer " + tok
		}
		if refresh, err := c.Cookie("refresh_token"); err == nil && refresh != "" {
			body, _ = json.Marshal(map[string]string{"refresh_token": refresh})
		}
	}
	started := time.Now()
	rec, answered := uiDispatchBounded(engine, c, uiLogoutTarget, body, bearer, uiLogoutUpstreamTimeout)
	if answered && c.GetHeader("Authorization") == "" && bearer != "" && uiMiddlewareRefusedLiftedToken(rec) {
		// An expired or revoked lifted access cookie must not prevent the
		// logout handler from checking the remaining refresh proof. Preserve
		// the original total deadline and never retry an explicit Bearer.
		rec, answered = uiDispatchBounded(engine, c, uiLogoutTarget, body, "", uiLogoutUpstreamTimeout-time.Since(started))
	}
	if !answered {
		// No answer within the bound is not confirmed revocation.
		handlers.ClearAuthCookies(c)
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{"logout": "local_only", "upstream": "timeout"})
		return
	}
	if rec.Code >= http.StatusInternalServerError || rec.Header().Get(handlers.LogoutUnconfirmedHeader) != "" {
		// Upstream could not revoke. Clear locally, and never call it a
		// revocation: the body names the outcome so the page can show it.
		handlers.ClearAuthCookies(c)
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{"logout": "local_only", "upstream_status": rec.Code})
		return
	}
	uiCopyResponse(c, rec)
}

// uiDispatchBounded runs uiDispatch under a deadline. The upstream runs on
// its own goroutine with a recorder nobody else touches: when the bound
// fires the recorder is abandoned unread and the cancelled context releases
// the handler on its own schedule. An answer that arrives after the context
// is done is treated as no answer: the caller no longer has a confirmed result.
func uiDispatchBounded(engine *gin.Engine, c *gin.Context, target string, body []byte, authorization string, bound time.Duration) (*httptest.ResponseRecorder, bool) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), bound)
	defer cancel()
	// Gin may recycle c as soon as this function times out. The worker owns
	// an immutable request snapshot, including a cloned header map.
	snapshot := c.Copy()
	snapshot.Request = c.Request.Clone(ctx)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- uiDispatchCtx(ctx, engine, snapshot, target, body, authorization) }()
	select {
	case rec := <-done:
		if ctx.Err() != nil {
			return nil, false
		}
		return rec, true
	case <-ctx.Done():
		return nil, false
	}
}

// uiReserved reports whether p belongs to the API/probe surface and must
// never resolve to a UI file or the shell.
func uiReserved(p string) bool {
	if _, exact := uiReservedPaths[p]; exact {
		return true
	}
	for _, prefix := range uiReservedPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// uiRouteSegments returns, computed once on first use (every route is
// registered by then, including any added after mountUI), whether a request
// path's first segment is the first segment of a route the engine carries.
// Such a path belongs to the API or operational surface: a wrong method or
// an unknown sibling there is the engine's plain 404, never the app shell.
// Parameter and wildcard first segments reserve nothing.
func uiRouteSegments(engine *gin.Engine) func(string) bool {
	var once sync.Once
	var segments map[string]struct{}
	first := func(p string) string {
		s, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
		return s
	}
	return func(p string) bool {
		once.Do(func() {
			segments = map[string]struct{}{}
			for _, r := range engine.Routes() {
				if s := first(r.Path); s != "" && !strings.HasPrefix(s, ":") && !strings.HasPrefix(s, "*") {
					segments[s] = struct{}{}
				}
			}
		})
		s := first(p)
		if s == "" {
			return false
		}
		_, ok := segments[s]
		return ok
	}
}

// uiCanonicalTarget reports whether a boundary target is exactly its own
// cleaned form under /api/v1/ — no dot segments, no doubled or trailing
// slash, no escape or backslash — so the boundary forwards only to the API
// path it names and never lets the engine's own resolution decide.
func uiCanonicalTarget(target string) bool {
	if !strings.HasPrefix(target, uiBFFPermittedPrefix) || strings.ContainsAny(target, "%\\") {
		return false
	}
	return path.Clean(target) == target
}

// uiHasDotSegment refuses hidden files and any traversal-looking segment
// before the path is ever cleaned or opened.
func uiHasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if strings.HasPrefix(seg, ".") && seg != "" {
			return true
		}
	}
	return false
}

func uiStaticHandler(fsys fs.FS, routeSegment func(string) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqPath := c.Request.URL.Path
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.String(http.StatusNotFound, uiGinNotFoundBody)
			return
		}
		if uiReserved(reqPath) || routeSegment(reqPath) || uiHasDotSegment(reqPath) {
			c.String(http.StatusNotFound, uiGinNotFoundBody)
			return
		}
		rel := strings.TrimPrefix(path.Clean("/"+reqPath), "/")
		if rel == "" {
			rel = uiShellFile
		}
		if info, err := fs.Stat(fsys, rel); err == nil && !info.IsDir() {
			cache := uiShellCacheControl
			if strings.HasPrefix(rel, uiAssetsPrefix) {
				cache = uiAssetCacheControl
			}
			uiServeFile(c, fsys, rel, cache)
			return
		}
		// An asset that does not exist is a 404, never the shell: a script or
		// stylesheet URL must not come back as HTML.
		if path.Ext(rel) != "" {
			c.String(http.StatusNotFound, uiGinNotFoundBody)
			return
		}
		uiServeFile(c, fsys, uiShellFile, uiShellCacheControl)
	}
}

// uiServeFile serves one file with the given Cache-Control. It uses
// http.ServeContent (content type by extension, HEAD, ranges) rather than
// http.ServeFileFS, whose index.html redirect would rewrite the shell URL.
func uiServeFile(c *gin.Context, fsys fs.FS, name, cache string) {
	f, err := fsys.Open(name)
	if err != nil {
		c.String(http.StatusNotFound, uiGinNotFoundBody)
		return
	}
	defer f.Close()
	var modTime time.Time
	if info, statErr := f.Stat(); statErr == nil {
		modTime = info.ModTime()
	}
	seeker, ok := f.(io.ReadSeeker)
	if !ok {
		b, readErr := io.ReadAll(f)
		if readErr != nil {
			c.String(http.StatusNotFound, uiGinNotFoundBody)
			return
		}
		seeker = bytes.NewReader(b)
	}
	c.Header("Cache-Control", cache)
	http.ServeContent(c.Writer, c.Request, name, modTime, seeker)
}

// uiBFFHandler is the narrow browser boundary. See the file comment.
func uiBFFHandler(engine *gin.Engine, resolved OSSRouterDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		target := c.Param("target")
		if target == "/session/refresh" {
			c.Header("Cache-Control", "no-store")
			if c.Request.Method != http.MethodPost {
				c.JSON(http.StatusNotFound, gin.H{"error": "bff_destination_refused"})
				return
			}
			// Same-origin only: the refresh answers with nothing but cookies,
			// so no allowlisted cross-origin page has a use for it.
			if uiRefuseWithoutBrowserProof(c, nil) {
				return
			}
			if c.GetHeader("Authorization") != "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "browser_refresh_requires_cookie"})
				return
			}
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()
			c.Request = c.Request.WithContext(ctx)
			handlers.HandleBrowserSessionRefresh(handlers.AuthSessionsHandlerDeps{
				UserSession: resolved.UserSessionService,
				UserToken:   resolved.UserToken,
				UserLookup:  resolved.UserLookup,
				Audit:       resolved.Audit,
			})(c)
			return
		}
		if target == uiBFFLogoutTarget {
			uiBFFLogout(c, engine, resolved)
			return
		}
		if !uiCanonicalTarget(target) {
			c.JSON(http.StatusNotFound, gin.H{"error": "bff_destination_refused"})
			return
		}
		// Owner decision D1: every method, safe ones included.
		if uiRefuseWithoutBrowserProof(c, resolved.CORSAllowedOrigins) {
			return
		}
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		lifted := false
		bearer := c.GetHeader("Authorization")
		if bearer == "" {
			if tok, cookieErr := c.Cookie(uiAccessTokenCookie); cookieErr == nil && tok != "" {
				bearer = "Bearer " + tok
				lifted = true
			}
		}
		rec := uiDispatch(engine, c, target, body, bearer)
		if lifted && uiMiddlewareRefusedLiftedToken(rec) {
			rec = uiDispatch(engine, c, target, body, "")
		}
		uiRedactBodyTokens(rec)
		uiCopyResponse(c, rec)
	}
}

// uiBodyTokenFields are the JSON members the login family echoes beside the
// cookies it mints (HandleLocalLogin, auth_sessions.go:428-447). A browser
// that receives the cookie needs none of them, and page script must never
// see a token, so the boundary removes them when — and only when — the same
// response set the browser's auth cookie. Direct API clients are untouched.
var uiBodyTokenFields = []string{"access_token", "refresh_token", "token_type", "expires_in"}

func uiRedactBodyTokens(rec *httptest.ResponseRecorder) {
	minted := false
	for _, sc := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(sc, uiAccessTokenCookie+"=") || strings.HasPrefix(sc, "refresh_token=") {
			minted = true
			break
		}
	}
	if !minted || rec.Body.Len() == 0 {
		return
	}
	// Authentication material must never reach page script merely because
	// an upstream response cannot be decoded. Withhold the cookies too: a
	// refused browser response must not silently establish a new session.
	refuse := func() {
		rec.Code = http.StatusBadGateway
		for key := range rec.Header() {
			rec.Header().Del(key)
		}
		rec.Header().Set("Content-Type", "application/json")
		rec.Header().Set("Cache-Control", "no-store")
		rec.Body.Reset()
		rec.Body.WriteString(`{"error":"bff_auth_response_refused"}`)
	}
	mediaType, _, _ := strings.Cut(rec.Header().Get("Content-Type"), ";")
	if !strings.EqualFold(strings.TrimSpace(mediaType), "application/json") {
		refuse()
		return
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &obj); err != nil || obj == nil {
		refuse()
		return
	}
	changed := false
	for _, k := range uiBodyTokenFields {
		if _, ok := obj[k]; ok {
			delete(obj, k)
			changed = true
		}
	}
	if !changed {
		return
	}
	out, err := json.Marshal(obj)
	if err != nil {
		refuse()
		return
	}
	rec.Body.Reset()
	rec.Body.Write(out)
	rec.Header().Set("Content-Length", "")
	rec.Header().Del("Content-Length")
}

// uiRefuseWithoutBrowserProof is the boundary's CSRF proof, required on EVERY
// /bff request, safe methods included (owner decision D1, 2026-09-23): a
// cross-site top-level GET would otherwise carry the Lax access cookie and
// the boundary would lift it. The proof is three checks, all before any
// credential is lifted: the X-Requested-With header (no form, link or
// navigation can set it, and a non-allowlisted origin cannot send it through
// CORS); an Origin, when present, that is this host or an exact allowlist
// entry; and Fetch Metadata, when present, that says same-origin — or, for a
// cross-origin request, carries an allowlisted Origin. It writes 403
// csrf_failed and reports true when it refused.
func uiRefuseWithoutBrowserProof(c *gin.Context, allowed []string) bool {
	refuse := func(reason string) bool {
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusForbidden, gin.H{"error": "csrf_failed", "reason": reason})
		return true
	}
	if c.GetHeader(uiBFFRequiredHeader) != uiBFFRequiredHeaderValue {
		return refuse("missing_request_header")
	}
	origin := c.GetHeader("Origin")
	if origin != "" && !uiOriginPermitted(c.Request, origin, allowed) {
		return refuse("origin_not_permitted")
	}
	switch site := c.GetHeader("Sec-Fetch-Site"); site {
	case "", "same-origin":
	default:
		// same-site, cross-site, none: only an explicitly permitted Origin
		// (checked above) may make a request that is not same-origin.
		if origin == "" {
			return refuse("fetch_site_not_permitted")
		}
	}
	return false
}

func uiUnsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// uiOriginPermitted: same host as the request, or an exact CORS allowlist
// entry. Anything else — including a subdomain — is refused.
func uiOriginPermitted(request *http.Request, origin string, allowed []string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(origin, "#") {
		return false
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	if u.Scheme == scheme && strings.EqualFold(u.Host, request.Host) {
		return true
	}
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}

// uiDispatch runs the target route in-process through the whole engine
// (every global middleware, BearerPrincipal included) and returns the
// recorded response. The browser's Cookie header is dropped; the caller
// decides the Authorization header.
func uiDispatch(engine *gin.Engine, c *gin.Context, target string, body []byte, authorization string) *httptest.ResponseRecorder {
	return uiDispatchCtx(c.Request.Context(), engine, c, target, body, authorization)
}

// uiDispatchCtx is uiDispatch with an explicit context, so a caller can
// bound the inner request without touching the browser's own request.
func uiDispatchCtx(ctx context.Context, engine *gin.Engine, c *gin.Context, target string, body []byte, authorization string) *httptest.ResponseRecorder {
	inner, err := http.NewRequestWithContext(ctx, c.Request.Method, target, bytes.NewReader(body))
	if err != nil {
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusBadRequest)
		return rec
	}
	inner.URL.RawQuery = c.Request.URL.RawQuery
	inner.Host = c.Request.Host
	inner.RemoteAddr = c.Request.RemoteAddr
	for k, vs := range c.Request.Header {
		if strings.EqualFold(k, "Cookie") || strings.EqualFold(k, "Authorization") {
			continue
		}
		inner.Header[k] = append([]string(nil), vs...)
	}
	if authorization != "" {
		inner.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, inner)
	return rec
}

// uiMiddlewareRefusedLiftedToken is true only for the bearer middleware's own
// refusal shapes; a handler's 401 never triggers the anonymous retry.
func uiMiddlewareRefusedLiftedToken(rec *httptest.ResponseRecorder) bool {
	if rec.Code != http.StatusUnauthorized {
		return false
	}
	var v struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || v.Error != uiBFFMiddlewareErrorField {
		return false
	}
	_, stale := uiStaleCookieReasons[v.Reason]
	return stale
}

func uiCopyResponse(c *gin.Context, rec *httptest.ResponseRecorder) {
	h := c.Writer.Header()
	for k, vs := range rec.Header() {
		h.Del(k)
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	// Cookie-authenticated browser responses must never inherit a public
	// cache policy from the internally dispatched API response.
	h.Set("Cache-Control", "no-store")
	c.Status(rec.Code)
	_, _ = c.Writer.Write(rec.Body.Bytes())
}
