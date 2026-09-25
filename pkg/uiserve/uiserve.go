// Package uiserve serves the identuum-ui static export and its one browser
// boundary as a standard-library http.Handler, so that a single binary
// answers the UI and the API on one origin (owner decision 2026-09-24: one
// binary per edition, no UI container, no Node at runtime). It imports the
// standard library only: identuum-idp-oss mounts it on gin, identuum-idp-ce
// on net/http's ServeMux, both with the same UI files.
//
// The caller builds a Handler with New(Options) and routes to it:
//
//   - GET /api/status and GET /api/runtime-config — the UI's two platform
//     routes, answered from Options;
//   - /bff/... — the browser boundary, which dispatches into Options.API,
//     the caller's own API handler, in-process;
//   - every other path its own router does not claim — the static
//     fallback, which serves the export and the app shell.
//
// The caller supplies the UI as an fs.FS (DirFS, or an embedded export;
// Select applies the precedence the binaries use), the API handler, which
// paths belong to its API (Options.Reserved), which paths the boundary
// forwards to, how a browser credential reaches the API (a cookie lifted
// into a Bearer header, or cookies forwarded unchanged), and the hooks only
// it knows: the session refresh, the cookie clear and the logout route.
//
// What the boundary does, and why each rule exists:
//
//   - every /bff request, safe methods included (owner decision D1,
//     2026-09-23), carries `X-Requested-With: identuum-ui`, an Origin (when
//     present) that is this host or an allowlisted origin, and Fetch
//     Metadata (when present) that says same-origin — all checked BEFORE any
//     credential is used, so a cookie-bearing cross-site request is refused
//     with the credential attached;
//   - the browser's Cookie header is NEVER forwarded as sent: only the
//     cookies named in Options.ForwardCookies pass through, and the
//     Options.AccessCookie is lifted into `Authorization: Bearer` only when
//     the browser sent no Authorization header (an explicit Bearer wins);
//   - THE-STALE-COOKIE: when the lift was ours and the API refused the
//     lifted token with one of Options.StaleTokenReasons, the request is
//     retried ONCE anonymously, so a dead cookie cannot 401 a public
//     endpoint. Any other 401 is never retried;
//   - permitted destinations: only canonical paths under a forward prefix;
//   - with Options.AllowedMethods, a method the API does not serve at the
//     destination is answered 405 with Allow before the browser proof, and
//     never forwarded;
//   - a response that sets a credential cookie has the login family's body
//     tokens removed, so page script never sees a token; one that cannot be
//     redacted is refused, cookies included;
//   - logout is bounded and, when the upstream cannot confirm revocation,
//     still clears the cookies and SAYS local_only.
//
// Static serving refuses the API, discovery, probe and BFF prefixes and
// whatever Options.Reserved claims (a plain 404), an asset path that does
// not exist (404, never the shell), dot-segments, and every method but GET
// and HEAD. The app shell is served with Cache-Control: no-store; hashed
// assets under /assets/ are immutable.
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
	"time"
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
	// StatusPath and RuntimeConfigPath are the UI's two platform routes.
	StatusPath        = "/api/status"
	RuntimeConfigPath = "/api/runtime-config"
	// ShellCacheControl is the app shell's cache policy; AssetCacheControl is
	// the hashed assets'.
	ShellCacheControl = "no-store"
	AssetCacheControl = "public, max-age=31536000, immutable"
	// NotFoundBody is the plain 404 body the fallback answers with.
	NotFoundBody = "404 page not found"

	// DefaultLogoutTimeout bounds the proxied revocation when
	// LogoutOptions.Timeout is zero.
	DefaultLogoutTimeout = 5 * time.Second

	logoutTarget          = "/session/logout"
	refreshTarget         = "/session/refresh"
	refreshTimeout        = 5 * time.Second
	shellFile             = "index.html"
	assetsPrefix          = "assets/"
	middlewareErrorField  = "unauthorized"
	defaultForwardPrefix  = "/api/v1/"
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

// Options configures New.
type Options struct {
	// UI is the static export, rooted at its index.html. Required.
	UI fs.FS
	// Source names the UI in errors (for example "the embedded UI export").
	Source string
	// Edition names the binary's edition ("oss", "ce"); /api/status and
	// /api/runtime-config report it as "edition", so the one UI artifact
	// both editions embed can read it at runtime.
	Edition string
	// API is the caller's API handler, into which the boundary dispatches
	// every forwarded request in-process. Required.
	API http.Handler
	// Reserved reports whether a request path belongs to the caller's API or
	// operational surface, so the static fallback answers it with a plain
	// 404 and never the shell; nil reserves only the fixed prefixes.
	Reserved func(path string) bool
	// AllowedOrigins are the exact cross-origin Origins the boundary accepts
	// besides this host (the CORS allowlist).
	AllowedOrigins []string
	// ForwardPrefixes are the path prefixes the boundary forwards to; empty
	// means "/api/v1/". Each ends in "/".
	ForwardPrefixes []string
	// AllowedMethods, when set, reports the methods the API serves at a
	// forwarded target path for a request method it does not serve there
	// (the Allow list), and nil when it serves the method or the path is none
	// of its routes. The boundary then answers a wrong method 405 with that
	// Allow before the browser proof and without forwarding, and a wrong
	// method on its own session routes 405 with Allow: POST. Nil keeps every
	// answer as before: each method forwarded, the session routes' 404.
	AllowedMethods func(method, path string) []string
	// AccessCookie names the cookie lifted into `Authorization: Bearer` when
	// the browser sent no Authorization header; empty lifts nothing.
	AccessCookie string
	// RefreshCookie names the cookie sent as the logout's refresh proof
	// ({"refresh_token": value}); empty sends none.
	RefreshCookie string
	// ForwardCookies name the cookies passed to the API unchanged (a
	// cookie-session API); every other cookie is dropped.
	ForwardCookies []string
	// StaleTokenReasons are the API's own refusal reasons for a token it was
	// handed (the body {"error":"unauthorized","reason":R}). Only these
	// trigger the anonymous retry of a lifted cookie.
	StaleTokenReasons []string
	// Refresh answers POST /bff/session/refresh once the boundary has checked
	// the browser proof (same-origin only) and the absence of an explicit
	// Bearer; nil refuses the route.
	Refresh http.HandlerFunc
	// Logout configures POST /bff/session/logout.
	Logout LogoutOptions
	// Status is the /api/status answer.
	Status Status
	// PublicBaseURL is /api/runtime-config's idp.public_base_url.
	PublicBaseURL string
}

// LogoutOptions configures the boundary's logout.
type LogoutOptions struct {
	// Target is the JSON logout route the boundary proxies to; empty
	// refuses the route.
	Target string
	// Timeout bounds the proxied revocation; zero means DefaultLogoutTimeout.
	Timeout time.Duration
	// ClearCookies expires the browser's auth cookies on a local-only
	// logout; it writes headers only.
	ClearCookies http.HandlerFunc
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

// New builds the UI handler. It refuses a UI without an index.html rather
// than serve an empty UI, and a missing API handler.
func New(o Options) (http.Handler, error) {
	if o.UI == nil {
		return nil, errors.New("uiserve: no UI to serve")
	}
	if info, err := fs.Stat(o.UI, shellFile); err != nil || info.IsDir() {
		return nil, fmt.Errorf("%s has no index.html; refusing to serve an empty UI", o.Source)
	}
	if o.API == nil {
		return nil, errors.New("uiserve: no API handler for the boundary")
	}
	if len(o.ForwardPrefixes) == 0 {
		o.ForwardPrefixes = []string{defaultForwardPrefix}
	}
	if o.Logout.Timeout == 0 {
		o.Logout.Timeout = DefaultLogoutTimeout
	}
	h := &handler{o: o, stale: map[string]struct{}{}}
	for _, r := range o.StaleTokenReasons {
		h.stale[r] = struct{}{}
	}
	return h, nil
}

type handler struct {
	o     Options
	stale map[string]struct{}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == StatusPath && r.Method == http.MethodGet:
		h.status(w)
	case p == RuntimeConfigPath && r.Method == http.MethodGet:
		h.runtimeConfig(w, r)
	case strings.HasPrefix(p, BFFPrefix+"/"):
		h.boundary(w, r, strings.TrimPrefix(p, BFFPrefix))
	default:
		h.static(w, r)
	}
}

// writeJSON writes v as JSON with the status and Content-Type a gin c.JSON
// wrote before this package left gin, so no answer changes shape.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// writeMethodNotAllowed answers 405 with the Allow list, in the boundary's
// {"error": code} shape.
func writeMethodNotAllowed(w http.ResponseWriter, allow []string) {
	w.Header().Set("Allow", strings.Join(allow, ", "))
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
}

func writeNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, NotFoundBody)
}

// cookie returns a request cookie's value, query-unescaped as gin's
// c.Cookie returned it; "" when absent.
func cookie(r *http.Request, name string) string {
	if name == "" {
		return ""
	}
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	v, _ := url.QueryUnescape(c.Value)
	return v
}

// status answers the UI's /api/status: the edition, the IdP's own health
// and product, and AG as not part of this deployment.
func (h *handler) status(w http.ResponseWriter) {
	s := h.o.Status
	healthy := s.Healthy == nil || s.Healthy()
	idp := map[string]any{"enabled": true, "healthy": healthy, "product": s.Product}
	if s.Extra != nil {
		for k, v := range s.Extra() {
			idp[k] = v
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"edition": h.o.Edition,
		"idp":     idp,
		"ag":      map[string]any{"enabled": false, "healthy": nil, "product": "identuum-ag"},
	})
}

// runtimeConfig answers with the public configuration only (never an
// internal base URL). The UI is served by this binary, so its origin is the
// request's own.
func (h *handler) runtimeConfig(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": true,
		"edition":    h.o.Edition,
		"ui_origin":  scheme + "://" + r.Host,
		"idp":        map[string]any{"enabled": true, "public_base_url": h.o.PublicBaseURL},
		"ag":         map[string]any{"enabled": false, "public_base_url": ""},
	})
}

func (h *handler) reserved(p string) bool {
	if _, exact := reservedPaths[p]; exact {
		return true
	}
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return h.o.Reserved != nil && h.o.Reserved(p)
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

func (h *handler) static(w http.ResponseWriter, r *http.Request) {
	reqPath := r.URL.Path
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeNotFound(w)
		return
	}
	if h.reserved(reqPath) || hasDotSegment(reqPath) {
		writeNotFound(w)
		return
	}
	rel := strings.TrimPrefix(path.Clean("/"+reqPath), "/")
	if rel == "" {
		rel = shellFile
	}
	if info, err := fs.Stat(h.o.UI, rel); err == nil && !info.IsDir() {
		cache := ShellCacheControl
		if strings.HasPrefix(rel, assetsPrefix) {
			cache = AssetCacheControl
		}
		serveFile(w, r, h.o.UI, rel, cache)
		return
	}
	// An asset that does not exist is a 404, never the shell.
	if path.Ext(rel) != "" {
		writeNotFound(w)
		return
	}
	serveFile(w, r, h.o.UI, shellFile, ShellCacheControl)
}

// serveFile uses http.ServeContent (content type by extension, HEAD, ranges)
// rather than http.ServeFileFS, whose index.html redirect would rewrite the
// shell URL.
func serveFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, name, cache string) {
	f, err := fsys.Open(name)
	if err != nil {
		writeNotFound(w)
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
			writeNotFound(w)
			return
		}
		seeker = bytes.NewReader(b)
	}
	w.Header().Set("Cache-Control", cache)
	http.ServeContent(w, r, name, modTime, seeker)
}

func (h *handler) boundary(w http.ResponseWriter, r *http.Request, target string) {
	if target == refreshTarget {
		h.refresh(w, r)
		return
	}
	if target == logoutTarget {
		h.logout(w, r)
		return
	}
	if !h.canonicalTarget(target) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": destinationRefusedErr})
		return
	}
	// A method the API does not serve at the target is answered here, as the
	// API would answer it, and never forwarded.
	if h.o.AllowedMethods != nil {
		if allow := h.o.AllowedMethods(r.Method, target); len(allow) > 0 {
			writeMethodNotAllowed(w, allow)
			return
		}
	}
	// Owner decision D1: every method, safe ones included.
	if refuseWithoutBrowserProof(w, r, h.o.AllowedOrigins) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	lifted := false
	bearer := r.Header.Get("Authorization")
	if bearer == "" {
		if tok := cookie(r, h.o.AccessCookie); tok != "" {
			bearer = "Bearer " + tok
			lifted = true
		}
	}
	rec := h.dispatch(r.Context(), r, target, body, bearer)
	if lifted && h.middlewareRefusedLiftedToken(rec) {
		rec = h.dispatch(r.Context(), r, target, body, "")
	}
	h.redactBodyTokens(rec)
	copyResponse(w, rec)
}

func (h *handler) refresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost && h.o.Refresh != nil && h.o.AllowedMethods != nil {
		writeMethodNotAllowed(w, []string{http.MethodPost})
		return
	}
	if r.Method != http.MethodPost || h.o.Refresh == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": destinationRefusedErr})
		return
	}
	// Same-origin only: the refresh answers with nothing but cookies, so no
	// allowlisted cross-origin page has a use for it.
	if refuseWithoutBrowserProof(w, r, nil) {
		return
	}
	if r.Header.Get("Authorization") != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "browser_refresh_requires_cookie"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), refreshTimeout)
	defer cancel()
	h.o.Refresh(w, r.WithContext(ctx))
}

// canonicalTarget reports whether a boundary target is exactly its own
// cleaned form under a forward prefix — no dot segments, no doubled or
// trailing slash, no escape or backslash — so the boundary forwards only to
// the path it names and never lets the API's own resolution decide.
func (h *handler) canonicalTarget(target string) bool {
	if strings.ContainsAny(target, "%\\") || path.Clean(target) != target {
		return false
	}
	for _, prefix := range h.o.ForwardPrefixes {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}

// logout proxies the cookie-derived revocation and, when the upstream cannot
// answer, still clears the browser's cookies and SAYS so: a page script
// cannot expire an HttpOnly cookie.
func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	lo := h.o.Logout
	if r.Method != http.MethodPost && lo.Target != "" && h.o.AllowedMethods != nil {
		writeMethodNotAllowed(w, []string{http.MethodPost})
		return
	}
	if r.Method != http.MethodPost || lo.Target == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": destinationRefusedErr})
		return
	}
	if refuseWithoutBrowserProof(w, r, h.o.AllowedOrigins) {
		return
	}
	bearer := r.Header.Get("Authorization")
	var body []byte
	if bearer == "" {
		if tok := cookie(r, h.o.AccessCookie); tok != "" {
			bearer = "Bearer " + tok
		}
		if refresh := cookie(r, h.o.RefreshCookie); refresh != "" {
			body, _ = json.Marshal(map[string]string{"refresh_token": refresh})
		}
	}
	started := time.Now()
	rec, answered := h.dispatchBounded(r, lo.Target, body, bearer, lo.Timeout)
	if answered && r.Header.Get("Authorization") == "" && bearer != "" && h.middlewareRefusedLiftedToken(rec) {
		// An expired or revoked lifted access cookie must not prevent the
		// logout handler from checking the remaining refresh proof. Preserve
		// the original total deadline and never retry an explicit Bearer.
		rec, answered = h.dispatchBounded(r, lo.Target, body, "", lo.Timeout-time.Since(started))
	}
	clear := func() {
		if lo.ClearCookies != nil {
			lo.ClearCookies(w, r)
		}
		w.Header().Set("Cache-Control", "no-store")
	}
	if !answered {
		// No answer within the bound is not confirmed revocation.
		clear()
		writeJSON(w, http.StatusOK, map[string]any{"logout": "local_only", "upstream": "timeout"})
		return
	}
	if rec.Code >= http.StatusInternalServerError || (lo.UnconfirmedHeader != "" && rec.Header().Get(lo.UnconfirmedHeader) != "") {
		// Upstream could not revoke. Clear locally, and never call it a
		// revocation: the body names the outcome so the page can show it.
		clear()
		writeJSON(w, http.StatusOK, map[string]any{"logout": "local_only", "upstream_status": rec.Code})
		return
	}
	copyResponse(w, rec)
}

// dispatchBounded runs dispatch under a deadline. The upstream runs on its
// own goroutine with a recorder and a request clone nobody else touches:
// when the bound fires the recorder is abandoned unread and the cancelled
// context releases the handler on its own schedule. An answer that arrives
// after the context is done is treated as no answer.
func (h *handler) dispatchBounded(r *http.Request, target string, body []byte, authorization string, bound time.Duration) (*httptest.ResponseRecorder, bool) {
	ctx, cancel := context.WithTimeout(r.Context(), bound)
	defer cancel()
	snapshot := r.Clone(ctx)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- h.dispatch(ctx, snapshot, target, body, authorization) }()
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

// dispatch runs the target route in-process through the caller's API
// handler (every middleware it wraps included) and returns the recorded
// response. The browser's Cookie header is replaced by the forwarded cookies
// alone; the caller decides the Authorization header.
func (h *handler) dispatch(ctx context.Context, r *http.Request, target string, body []byte, authorization string) *httptest.ResponseRecorder {
	inner, err := http.NewRequestWithContext(ctx, r.Method, target, bytes.NewReader(body))
	if err != nil {
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusBadRequest)
		return rec
	}
	inner.URL.RawQuery = r.URL.RawQuery
	inner.Host = r.Host
	inner.RemoteAddr = r.RemoteAddr
	for k, vs := range r.Header {
		if strings.EqualFold(k, "Cookie") || strings.EqualFold(k, "Authorization") {
			continue
		}
		inner.Header[k] = append([]string(nil), vs...)
	}
	for _, name := range h.o.ForwardCookies {
		if c, cerr := r.Cookie(name); cerr == nil {
			inner.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	if authorization != "" {
		inner.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	h.o.API.ServeHTTP(rec, inner)
	return rec
}

// middlewareRefusedLiftedToken is true only for the API's own refusal shapes
// for a token it was handed; a handler's 401 never triggers the retry.
func (h *handler) middlewareRefusedLiftedToken(rec *httptest.ResponseRecorder) bool {
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
	_, stale := h.stale[v.Reason]
	return stale
}

// refuseWithoutBrowserProof is the boundary's CSRF proof. It writes 403
// csrf_failed and reports true when it refused.
func refuseWithoutBrowserProof(w http.ResponseWriter, r *http.Request, allowed []string) bool {
	refuse := func(reason string) bool {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "csrf_failed", "reason": reason})
		return true
	}
	if r.Header.Get(RequestHeader) != RequestHeaderValue {
		return refuse("missing_request_header")
	}
	origin := r.Header.Get("Origin")
	if origin != "" && !originPermitted(r, origin, allowed) {
		return refuse("origin_not_permitted")
	}
	switch site := r.Header.Get("Sec-Fetch-Site"); site {
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

// credentialCookie reports whether a Set-Cookie line sets one of the
// boundary's credential cookies.
func (h *handler) credentialCookie(setCookie string) bool {
	names := append([]string{h.o.AccessCookie, h.o.RefreshCookie}, h.o.ForwardCookies...)
	for _, n := range names {
		if n != "" && strings.HasPrefix(setCookie, n+"=") {
			return true
		}
	}
	return false
}

// redactBodyTokens removes the body tokens when — and only when — the same
// response set a credential cookie; a response it cannot redact is refused,
// cookies included.
func (h *handler) redactBodyTokens(rec *httptest.ResponseRecorder) {
	minted := false
	for _, sc := range rec.Header().Values("Set-Cookie") {
		if h.credentialCookie(sc) {
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

func copyResponse(w http.ResponseWriter, rec *httptest.ResponseRecorder) {
	hd := w.Header()
	for k, vs := range rec.Header() {
		hd.Del(k)
		for _, v := range vs {
			hd.Add(k, v)
		}
	}
	// Cookie-authenticated browser responses must never inherit a public
	// cache policy from the internally dispatched API response.
	hd.Set("Cache-Control", "no-store")
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}
