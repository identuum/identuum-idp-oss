// webauthn_ui_origin.go — resolver for the browser-facing UI public
// base URL fed into service.WebAuthnServiceConfig.UIPublicBaseURL.
//
// Why this exists. go-webauthn v0.15.0 compares the ceremony origin
// host EXACTLY against the configured RPOrigins. In local
// split-runtime development the OSS IDP serves on
// http://localhost:7113 while identuum-ui serves on
// http://localhost:7104, so a browser passkey ceremony originating
// from the UI port fails origin validation unless the UI origin is
// explicitly added to RPOrigins. Operator override is honoured
// first so production deployments (e.g. https://ui.example.com) are
// not pinned to a localhost default.
//
// Resolution rules — first match wins:
//
//  1. IDENTUUM_IDP_UI_PUBLIC_BASE_URL (operator override). Trimmed
//     of trailing slashes; structural validation happens later
//     inside the WebAuthn service constructor's
//     normalizeUIOriginForRPID helper (subdomain / exact-host match
//     against RP ID). A malformed override is forwarded as-is so the
//     service constructor can reject or silently drop it according
//     to its existing posture.
//  2. Local split-runtime fallback. When the override is empty AND
//     the IDP base URL parses as a localhost-style origin
//     (localhost or 127.0.0.1) — the only shape that matches the
//     documented dev split — default to http://localhost:7104
//     (identuum-ui's documented dev port).
//  3. Otherwise return the empty string. The WebAuthn service then
//     accepts ceremonies only from the IDP's own origin, which is
//     the conservative posture for production deployments where the
//     operator has not configured a UI origin.
//
// This file does NOT read .env files; it reads process env via the
// supplied getenv hook so unit tests can drive the resolver without
// touching os.Getenv.

package runtime

import (
	"net/url"
	"strings"
)

// envUIPublicBaseURL is the operator-facing env var name for the
// browser-facing UI public base URL. Mirrors the
// IDENTUUM_IDP_UI_PUBLIC_BASE_URL key the monolith uses so a single
// env var configures both code paths.
const envUIPublicBaseURL = "IDENTUUM_IDP_UI_PUBLIC_BASE_URL"

// localDevUIPublicBaseURLDefault is the conservative localhost
// default applied only when the IDP base URL itself is a
// localhost-style origin AND the operator has not set the env var.
// Production deployments where the IDP is hosted on a real domain
// MUST set the env var explicitly.
const localDevUIPublicBaseURLDefault = "http://localhost:7104"

// resolveUIPublicBaseURLForWebAuthn applies the precedence above
// and returns the value that should be assigned to
// service.WebAuthnServiceConfig.UIPublicBaseURL. The idpBaseURL
// argument is the IDP's own externally-facing origin (the same
// string that becomes WebAuthnServiceConfig.BaseURL).
func resolveUIPublicBaseURLForWebAuthn(getenv func(string) string, idpBaseURL string) string {
	if getenv != nil {
		if raw := strings.TrimSpace(getenv(envUIPublicBaseURL)); raw != "" {
			return strings.TrimRight(raw, "/")
		}
	}
	if isLocalhostBaseURL(idpBaseURL) {
		return localDevUIPublicBaseURLDefault
	}
	return ""
}

// isLocalhostBaseURL reports whether raw parses as an http/https URL
// whose hostname is one of the documented local-dev hosts. The
// hostname check is deliberately exact — anything that resolves to
// loopback over a non-localhost name (e.g. lvh.me) is treated as a
// real deployment so the localhost default does NOT kick in.
func isLocalhostBaseURL(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1"
}
