package api

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/pkg/uiserve"
)

// THE-UI-THAT-GO-CAN-SERVE (Plan B, 2026-09-22): the OSS binary serves the
// identuum-ui static export and its one browser boundary, /bff. The serving
// code is the public, standard-library package pkg/uiserve (PLAN-F-1,
// PLAN-F-2), so an edition importing this module mounts the same thing on
// its own router; this file is the OSS edition's wiring onto gin: which UI,
// the IdP's own hooks for the boundary, and the /api/status answer.

// uiLogoutUpstreamTimeout bounds the proxied revocation. Variable for the
// timeout proof.
var uiLogoutUpstreamTimeout = uiserve.DefaultLogoutTimeout

// uiLogoutTarget is the canonical JSON logout route the boundary proxies.
const uiLogoutTarget = "/api/v1/auth/logout"

// uiGinContextKey carries the gin context of the request the boundary is
// answering into the two hooks that are gin handlers (the browser refresh
// and the cookie clear), so they run on the context the engine built for
// the request — its writer, its keys, its client-IP policy — exactly as
// they did before the boundary left gin.
type uiGinContextKey struct{}

// mountUI mounts the UI when one is configured (uiserve.Select: the
// IDENTUUM_IDP_UI_DIR directory wins over the embedded export; neither
// mounts nothing). The router must be the engine itself (NoRoute and
// in-process dispatch need it); a composed sub-router or a UI without an
// index.html records a fatal fault rather than silently serving nothing,
// per P-018.
func mountUI(router gin.IRouter, resolved OSSRouterDeps) {
	fsys, source := uiserve.Select(resolved.UIStaticDir, "IDENTUUM_IDP_UI_DIR", resolved.UIEmbedded)
	if fsys == nil {
		return
	}
	engine, ok := router.(*gin.Engine)
	if !ok {
		if resolved.StartupReport != nil {
			resolved.StartupReport.Fatal("mountUI", source+" is set but the UI can only be mounted on the root engine")
		}
		return
	}
	report := resolved.StartupReport
	refresh := handlers.HandleBrowserSessionRefresh(handlers.AuthSessionsHandlerDeps{
		UserSession: resolved.UserSessionService,
		UserToken:   resolved.UserToken,
		UserLookup:  resolved.UserLookup,
		Audit:       resolved.Audit,
	})
	h, err := uiserve.New(uiserve.Options{
		UI:             fsys,
		Source:         source,
		API:            engine,
		Reserved:       uiRouteSegments(engine),
		AllowedOrigins: resolved.CORSAllowedOrigins,
		AccessCookie:   "access_token",
		RefreshCookie:  "refresh_token",
		// The bearer middleware's own refusals of a token it was handed
		// (internal/mw/auth_verdict.go): only these mean "the cookie we
		// lifted is dead".
		StaleTokenReasons: []string{mw.ReasonTokenInvalid, mw.ReasonTokenRevoked, mw.ReasonSessionNotLive},
		Refresh:           uiGinHook(refresh),
		Logout: uiserve.LogoutOptions{
			Target:            uiLogoutTarget,
			Timeout:           uiLogoutUpstreamTimeout,
			ClearCookies:      uiGinHook(handlers.ClearAuthCookies),
			UnconfirmedHeader: handlers.LogoutUnconfirmedHeader,
		},
		// The IdP is as healthy as its own /health says (serving unless a
		// fatal startup fault — P-018); AG is not part of this deployment.
		Status: uiserve.Status{
			Product: "identuum-idp-oss",
			Healthy: func() bool { return !report.HasFatal() },
			Extra: func() map[string]any {
				if resolved.BruteForceProtectionDisabled {
					return map[string]any{"brute_force_protection_disabled": true}
				}
				return nil
			},
		},
		PublicBaseURL: resolved.DiscoveryConfig.Issuer,
	})
	if err != nil {
		if report != nil {
			report.Fatal("mountUI", err.Error())
		}
		return
	}
	serve := func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request.WithContext(context.WithValue(c.Request.Context(), uiGinContextKey{}, c)))
	}
	// The same gin routes as before the package left gin, so gin's own
	// routing (methods, trailing slashes) decides what reaches the handler.
	engine.GET(uiserve.StatusPath, serve)
	engine.GET(uiserve.RuntimeConfigPath, serve)
	engine.NoRoute(serve)
	// ONE catch-all: gin refuses a static sibling beside a `*target`
	// wildcard, so the boundary's own session routes are dispatched inside it.
	engine.Any(uiserve.BFFPrefix+"/*target", serve)
}

// uiGinHook runs a gin handler as a boundary hook on the request's own gin
// context, with the request the boundary hands it (the refresh's bounded
// context). A request that did not come through the engine has no context
// to run on and is answered 503 rather than half-served.
func uiGinHook(fn gin.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := r.Context().Value(uiGinContextKey{}).(*gin.Context)
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		c.Request = r
		fn(c)
	}
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
