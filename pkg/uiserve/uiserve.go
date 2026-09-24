// Package uiserve serves the identuum-ui static export and its one browser
// boundary from a gin engine, so that a single binary answers the UI and the
// API on one origin (owner decision 2026-09-24: one binary per edition, no UI
// container, no Node at runtime). identuum-idp-oss mounts it; an edition that
// imports identuum-idp-oss mounts it the same way with its own UI files.
//
// The caller supplies:
//
//   - the UI as an fs.FS (Options.UI) — an embedded export, or DirFS for a
//     developer override; Select applies the precedence the binaries use;
//   - its edition routes, registered on the engine before or after Mount
//     (the static fallback reserves the first segment of every route the
//     engine carries, computed on first use);
//   - the /bff forward rules (Options.ForwardPrefixes) and the hooks the
//     boundary cannot know: the refresh handler, the cookie clear, the
//     logout route and the bearer middleware's stale-token reasons.
//
// What the boundary does, and why each rule exists:
//
//   - the cookie-to-Bearer LIFT, only when the browser sent no Authorization
//     header — an explicit Bearer always wins, so an M2M caller or a page
//     that carries its own token is never overridden by a cookie;
//   - the browser's Cookie header is NEVER forwarded;
//   - THE-STALE-COOKIE: when the lift was ours and the bearer middleware
//     refused the lifted token (one of Options.StaleTokenReasons), the
//     request is retried ONCE anonymously, so a dead cookie cannot 401 a
//     public endpoint. A handler's own 401 is never retried;
//   - permitted destinations: only canonical paths under a forward prefix;
//   - every /bff request, safe methods included (owner decision D1,
//     2026-09-23), carries `X-Requested-With: identuum-ui`, an Origin (when
//     present) that is this host or an allowlisted origin, and Fetch
//     Metadata (when present) that says same-origin — all checked BEFORE the
//     lift, so a cookie-bearing cross-site request is refused with the
//     credential attached;
//   - the login family's body tokens are removed when the same response set
//     the auth cookie, so page script never sees a token;
//   - logout is bounded and, when the upstream cannot confirm revocation,
//     still clears the cookies and SAYS local_only.
//
// Static serving is a gin NoRoute fallback: the API, discovery, probe and BFF
// prefixes keep gin's plain 404, an asset path that does not exist is 404
// (never the shell), dot-segments are refused, and only GET/HEAD are served.
// The app shell is served with Cache-Control: no-store; hashed assets under
// /assets/ are immutable.
package uiserve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
)

const (
	// RequestHeader and RequestHeaderValue are the browser proof every /bff
	// request carries.
	RequestHeader      = "X-Requested-With"
	RequestHeaderValue = "identuum-ui"
	// BFFPrefix is the boundary's mount point.
	BFFPrefix = "/bff"
	// LogoutPath and RefreshPath are the boundary's own session routes.
	LogoutPath  = BFFPrefix + logoutTarget
	RefreshPath = BFFPrefix + refreshTarget
	// ShellCacheControl is the app shell's cache policy; AssetCacheControl is
	// the hashed assets'.
	ShellCacheControl = "no-store"
	AssetCacheControl = "public, max-age=31536000, immutable"
	// NotFoundBody is gin's plain 404 body, which the fallback keeps.
	NotFoundBody = "404 page not found"

	// DefaultLogoutTimeout bounds the proxied revocation when
	// LogoutOptions.Timeout is zero.
	DefaultLogoutTimeout = 5 * time.Second

	logoutTarget          = "/session/logout"
	refreshTarget         = "/session/refresh"
	refreshTimeout        = 5 * time.Second
	accessTokenCookie     = "access_token"
	refreshTokenCookie    = "refresh_token"
	shellFile             = "index.html"
	assetsPrefix          = "assets/"
	middlewareErrorField  = "unauthorized"
	defaultForwardPrefix  = "/api/v1/"
	statusPath            = "/api/status"
	runtimeConfigPath     = "/api/runtime-config"
	destinationRefusedErr = "bff_destination_refused"
)

// reservedPrefixes never fall through to the app shell: an unknown path
// under them is an API 404, exactly as before the UI existed.
var reservedPrefixes = []string{"/api/", "/.well-known/", "/system/", "/health/", "/livez/", "/metrics/", BFFPrefix + "/"}

// reservedPaths are exact paths that are never the shell.
var reservedPaths = map[string]struct{}{"/health": {}, "/livez": {}, "/metrics": {}, BFFPrefix: {}}

// bodyTokenFields are the JSON members the login family echoes beside the
// cookies it mints. A browser that receives the cookie needs none of them.
var bodyTokenFields = []string{"access_token", "refresh_token", "token_type", "expires_in"}

// Options configures Mount.
type Options struct {
	// UI is the static export, rooted at its index.html. Required.
	UI fs.FS
	// Source names the UI in errors (for example "the embedded UI export").
	Source string
	// AllowedOrigins are the exact cross-origin Origins the boundary accepts
	// besides this host (the CORS allowlist).
	AllowedOrigins []string
	// ForwardPrefixes are the path prefixes the boundary forwards to; empty
	// means "/api/v1/". Each ends in "/".
	ForwardPrefixes []string
	// StaleTokenReasons are the bearer middleware's own refusal reasons for
	// a token it was handed (the body {"error":"unauthorized","reason":R}).
	// Only these trigger the anonymous retry of a lifted cookie.
	StaleTokenReasons []string
	// Refresh answers POST /bff/session/refresh once the boundary has checked
	// the browser proof (same-origin only) and the absence of an explicit
	// Bearer; nil refuses the route.
	Refresh gin.HandlerFunc
	// Logout configures POST /bff/session/logout.
	Logout LogoutOptions
	// Status is the /api/status answer.
	Status Status
	// PublicBaseURL is /api/runtime-config's idp.public_base_url.
	PublicBaseURL string
}

// LogoutOptions configures the boundary's logout.
type LogoutOptions struct {
	// Target is the JSON logout route the boundary proxies to.
	Target string
	// Timeout bounds the proxied revocation; zero means DefaultLogoutTimeout.
	Timeout time.Duration
	// ClearCookies expires the browser's auth cookies on a local-only logout.
	ClearCookies func(*gin.Context)
	// UnconfirmedHeader, when set on the upstream answer, means the upstream
	// could not confirm the revocation.
	UnconfirmedHeader string
}

// Status is the edition's /api/status answer for the IdP.
type Status struct {
	// Product is idp.product, for example "identuum-idp-oss".
	Product string
	// Healthy is idp.healthy; nil reports healthy.
	Healthy func() bool
	// Extra are further idp members (for example
	// brute_force_protection_disabled); nil adds none.
	Extra func() map[string]any
}

// Select picks the UI a binary serves. Precedence: a UI directory (the
// developer override) wins; otherwise the embedded export; otherwise nothing
// (nil). The second value names the source for errors.
func Select(dir, dirName string, embedded fs.FS) (fs.FS, string) {
	if dir != "" {
		return DirFS(dir), dirName
	}
	if embedded != nil {
		return embedded, "the embedded UI export"
	}
	return nil, ""
}

// DirFS serves a UI directory with every open, including symlink resolution,
// confined to it.
func DirFS(dir string) fs.FS { return dirFS(dir) }

type dirFS string

func (root dirFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, fs.ErrInvalid
	}
	return os.OpenInRoot(string(root), name)
}

// Mount mounts the UI routes on engine: GET /api/status and GET
// /api/runtime-config, the static fallback (NoRoute), and the /bff boundary.
// It refuses a UI without an index.html rather than serve an empty UI.
func Mount(engine *gin.Engine, o Options) error {
	if o.UI == nil {
		return errors.New("uiserve: no UI to mount")
	}
	if info, err := fs.Stat(o.UI, shellFile); err != nil || info.IsDir() {
		return fmt.Errorf("%s has no index.html; refusing to serve an empty UI", o.Source)
	}
	if len(o.ForwardPrefixes) == 0 {
		o.ForwardPrefixes = []string{defaultForwardPrefix}
	}
	if o.Logout.Timeout == 0 {
		o.Logout.Timeout = DefaultLogoutTimeout
	}
	b := &boundary{engine: engine, o: o, stale: map[string]struct{}{}}
	for _, r := range o.StaleTokenReasons {
		b.stale[r] = struct{}{}
	}
	// Registered before the fallback computes its route segments, so /api
	// stays reserved either way.
	engine.GET(statusPath, statusHandler(o.Status))
	engine.GET(runtimeConfigPath, runtimeConfigHandler(o.PublicBaseURL))
	engine.NoRoute(staticHandler(o.UI, routeSegments(engine)))
	// ONE catch-all: gin refuses a static sibling beside a `*target`
	// wildcard, so the boundary's own session routes are dispatched inside it.
	engine.Any(BFFPrefix+"/*target", b.handle)
	return nil
}

func statusHandler(s Status) gin.HandlerFunc {
	return func(c *gin.Context) {
		healthy := s.Healthy == nil || s.Healthy()
		idp := gin.H{"enabled": true, "healthy": healthy, "product": s.Product}
		if s.Extra != nil {
			for k, v := range s.Extra() {
				idp[k] = v
			}
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{
			"idp": idp,
			"ag":  gin.H{"enabled": false, "healthy": nil, "product": "identuum-ag"},
		})
	}
}

// runtimeConfigHandler answers with the public configuration only (never an
// internal base URL). The UI is served by this binary, so its origin is the
// request's own.
func runtimeConfigHandler(publicBaseURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{
			"configured": true,
			"ui_origin":  scheme + "://" + c.Request.Host,
			"idp":        gin.H{"enabled": true, "public_base_url": publicBaseURL},
			"ag":         gin.H{"enabled": false, "public_base_url": ""},
		})
	}
}

func reserved(p string) bool {
	if _, exact := reservedPaths[p]; exact {
		return true
	}
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// routeSegments returns, computed once on first use (every route is
// registered by then, including any added after Mount), whether a request
// path's first segment is the first segment of a route the engine carries.
// Parameter and wildcard first segments reserve nothing.
func routeSegments(engine *gin.Engine) func(string) bool {
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

// hasDotSegment refuses hidden files and any traversal-looking segment
// before the path is ever cleaned or opened.
func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if strings.HasPrefix(seg, ".") && seg != "" {
			return true
		}
	}
	return false
}

func staticHandler(fsys fs.FS, routeSegment func(string) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqPath := c.Request.URL.Path
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.String(http.StatusNotFound, NotFoundBody)
			return
		}
		if reserved(reqPath) || routeSegment(reqPath) || hasDotSegment(reqPath) {
			c.String(http.StatusNotFound, NotFoundBody)
			return
		}
		rel := strings.TrimPrefix(path.Clean("/"+reqPath), "/")
		if rel == "" {
			rel = shellFile
		}
		if info, err := fs.Stat(fsys, rel); err == nil && !info.IsDir() {
			cache := ShellCacheControl
			if strings.HasPrefix(rel, assetsPrefix) {
				cache = AssetCacheControl
			}
			serveFile(c, fsys, rel, cache)
			return
		}
		// An asset that does not exist is a 404, never the shell.
		if path.Ext(rel) != "" {
			c.String(http.StatusNotFound, NotFoundBody)
			return
		}
		serveFile(c, fsys, shellFile, ShellCacheControl)
	}
}

// serveFile uses http.ServeContent (content type by extension, HEAD, ranges)
// rather than http.ServeFileFS, whose index.html redirect would rewrite the
// shell URL.
func serveFile(c *gin.Context, fsys fs.FS, name, cache string) {
	f, err := fsys.Open(name)
	if err != nil {
		c.String(http.StatusNotFound, NotFoundBody)
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
			c.String(http.StatusNotFound, NotFoundBody)
			return
		}
		seeker = bytes.NewReader(b)
	}
	c.Header("Cache-Control", cache)
	http.ServeContent(c.Writer, c.Request, name, modTime, seeker)
}

type boundary struct {
	engine *gin.Engine
	o      Options
	stale  map[string]struct{}
}

func (b *boundary) handle(c *gin.Context) {
	target := c.Param("target")
	if target == refreshTarget {
		b.refresh(c)
		return
	}
	if target == logoutTarget {
		b.logout(c)
		return
	}
	if !b.canonicalTarget(target) {
		c.JSON(http.StatusNotFound, gin.H{"error": destinationRefusedErr})
		return
	}
	// Owner decision D1: every method, safe ones included.
	if refuseWithoutBrowserProof(c, b.o.AllowedOrigins) {
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
		if tok, cookieErr := c.Cookie(accessTokenCookie); cookieErr == nil && tok != "" {
			bearer = "Bearer " + tok
			lifted = true
		}
	}
	rec := dispatch(c.Request.Context(), b.engine, c, target, body, bearer)
	if lifted && b.middlewareRefusedLiftedToken(rec) {
		rec = dispatch(c.Request.Context(), b.engine, c, target, body, "")
	}
	redactBodyTokens(rec)
	copyResponse(c, rec)
}

func (b *boundary) refresh(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if c.Request.Method != http.MethodPost || b.o.Refresh == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": destinationRefusedErr})
		return
	}
	// Same-origin only: the refresh answers with nothing but cookies, so no
	// allowlisted cross-origin page has a use for it.
	if refuseWithoutBrowserProof(c, nil) {
		return
	}
	if c.GetHeader("Authorization") != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "browser_refresh_requires_cookie"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), refreshTimeout)
	defer cancel()
	c.Request = c.Request.WithContext(ctx)
	b.o.Refresh(c)
}

// canonicalTarget reports whether a boundary target is exactly its own
// cleaned form under a forward prefix — no dot segments, no doubled or
// trailing slash, no escape or backslash — so the boundary forwards only to
// the path it names and never lets the engine's own resolution decide.
func (b *boundary) canonicalTarget(target string) bool {
	if strings.ContainsAny(target, "%\\") || path.Clean(target) != target {
		return false
	}
	for _, prefix := range b.o.ForwardPrefixes {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}

// logout proxies the cookie-derived revocation and, when the upstream cannot
// answer, still clears the browser's cookies and SAYS so: a page script
// cannot expire an HttpOnly cookie.
func (b *boundary) logout(c *gin.Context) {
	lo := b.o.Logout
	if c.Request.Method != http.MethodPost || lo.Target == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": destinationRefusedErr})
		return
	}
	if refuseWithoutBrowserProof(c, b.o.AllowedOrigins) {
		return
	}
	bearer := c.GetHeader("Authorization")
	var body []byte
	if bearer == "" {
		if tok, err := c.Cookie(accessTokenCookie); err == nil && tok != "" {
			bearer = "Bearer " + tok
		}
		if refresh, err := c.Cookie(refreshTokenCookie); err == nil && refresh != "" {
			body, _ = json.Marshal(map[string]string{"refresh_token": refresh})
		}
	}
	started := time.Now()
	rec, answered := dispatchBounded(b.engine, c, lo.Target, body, bearer, lo.Timeout)
	if answered && c.GetHeader("Authorization") == "" && bearer != "" && b.middlewareRefusedLiftedToken(rec) {
		// An expired or revoked lifted access cookie must not prevent the
		// logout handler from checking the remaining refresh proof. Preserve
		// the original total deadline and never retry an explicit Bearer.
		rec, answered = dispatchBounded(b.engine, c, lo.Target, body, "", lo.Timeout-time.Since(started))
	}
	clear := func() {
		if lo.ClearCookies != nil {
			lo.ClearCookies(c)
		}
		c.Header("Cache-Control", "no-store")
	}
	if !answered {
		// No answer within the bound is not confirmed revocation.
		clear()
		c.JSON(http.StatusOK, gin.H{"logout": "local_only", "upstream": "timeout"})
		return
	}
	if rec.Code >= http.StatusInternalServerError || (lo.UnconfirmedHeader != "" && rec.Header().Get(lo.UnconfirmedHeader) != "") {
		// Upstream could not revoke. Clear locally, and never call it a
		// revocation: the body names the outcome so the page can show it.
		clear()
		c.JSON(http.StatusOK, gin.H{"logout": "local_only", "upstream_status": rec.Code})
		return
	}
	copyResponse(c, rec)
}

// dispatchBounded runs dispatch under a deadline. The upstream runs on its
// own goroutine with a recorder nobody else touches: when the bound fires the
// recorder is abandoned unread and the cancelled context releases the
// handler on its own schedule. An answer that arrives after the context is
// done is treated as no answer.
func dispatchBounded(engine *gin.Engine, c *gin.Context, target string, body []byte, authorization string, bound time.Duration) (*httptest.ResponseRecorder, bool) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), bound)
	defer cancel()
	// Gin may recycle c as soon as this function times out. The worker owns
	// an immutable request snapshot, including a cloned header map.
	snapshot := c.Copy()
	snapshot.Request = c.Request.Clone(ctx)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- dispatch(ctx, engine, snapshot, target, body, authorization) }()
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

// dispatch runs the target route in-process through the whole engine (every
// global middleware included) and returns the recorded response. The
// browser's Cookie header is dropped; the caller decides the Authorization
// header.
func dispatch(ctx context.Context, engine *gin.Engine, c *gin.Context, target string, body []byte, authorization string) *httptest.ResponseRecorder {
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

// middlewareRefusedLiftedToken is true only for the bearer middleware's own
// refusal shapes; a handler's 401 never triggers the anonymous retry.
func (b *boundary) middlewareRefusedLiftedToken(rec *httptest.ResponseRecorder) bool {
	if rec.Code != http.StatusUnauthorized {
		return false
	}
	var v struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || v.Error != middlewareErrorField {
		return false
	}
	_, stale := b.stale[v.Reason]
	return stale
}

// refuseWithoutBrowserProof is the boundary's CSRF proof. It writes 403
// csrf_failed and reports true when it refused.
func refuseWithoutBrowserProof(c *gin.Context, allowed []string) bool {
	refuse := func(reason string) bool {
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusForbidden, gin.H{"error": "csrf_failed", "reason": reason})
		return true
	}
	if c.GetHeader(RequestHeader) != RequestHeaderValue {
		return refuse("missing_request_header")
	}
	origin := c.GetHeader("Origin")
	if origin != "" && !originPermitted(c.Request, origin, allowed) {
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

// originPermitted: same host as the request, or an exact allowlist entry.
// Anything else — including a subdomain — is refused.
func originPermitted(request *http.Request, origin string, allowed []string) bool {
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

// redactBodyTokens removes the body tokens when — and only when — the same
// response set the browser's auth cookie; a response it cannot redact is
// refused, cookies included.
func redactBodyTokens(rec *httptest.ResponseRecorder) {
	minted := false
	for _, sc := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(sc, accessTokenCookie+"=") || strings.HasPrefix(sc, refreshTokenCookie+"=") {
			minted = true
			break
		}
	}
	if !minted || rec.Body.Len() == 0 {
		return
	}
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
	for _, k := range bodyTokenFields {
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
	rec.Header().Del("Content-Length")
}

func copyResponse(c *gin.Context, rec *httptest.ResponseRecorder) {
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
