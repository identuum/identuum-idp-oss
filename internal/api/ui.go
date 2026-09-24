package api

import (
	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/pkg/uiserve"
)

// THE-UI-THAT-GO-CAN-SERVE (Plan B, 2026-09-22): the OSS binary serves the
// identuum-ui static export and its one browser boundary, /bff. The serving
// code is the public package pkg/uiserve (PLAN-F-1), so an edition importing
// this module mounts the same thing; this file is the OSS edition's wiring:
// which UI, the IdP's own hooks for the boundary, and the /api/status answer.

// uiLogoutUpstreamTimeout bounds the proxied revocation. Variable for the
// timeout proof.
var uiLogoutUpstreamTimeout = uiserve.DefaultLogoutTimeout

// uiLogoutTarget is the canonical JSON logout route the boundary proxies.
const uiLogoutTarget = "/api/v1/auth/logout"

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
	err := uiserve.Mount(engine, uiserve.Options{
		UI:             fsys,
		Source:         source,
		AllowedOrigins: resolved.CORSAllowedOrigins,
		// The bearer middleware's own refusals of a token it was handed
		// (internal/mw/auth_verdict.go): only these mean "the cookie we
		// lifted is dead".
		StaleTokenReasons: []string{mw.ReasonTokenInvalid, mw.ReasonTokenRevoked, mw.ReasonSessionNotLive},
		Refresh: handlers.HandleBrowserSessionRefresh(handlers.AuthSessionsHandlerDeps{
			UserSession: resolved.UserSessionService,
			UserToken:   resolved.UserToken,
			UserLookup:  resolved.UserLookup,
			Audit:       resolved.Audit,
		}),
		Logout: uiserve.LogoutOptions{
			Target:            uiLogoutTarget,
			Timeout:           uiLogoutUpstreamTimeout,
			ClearCookies:      handlers.ClearAuthCookies,
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
	if err != nil && report != nil {
		report.Fatal("mountUI", err.Error())
	}
}
