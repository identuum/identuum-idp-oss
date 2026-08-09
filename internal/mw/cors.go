package mw

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSOptions configures the CORS middleware.
//
// AllowedOrigins is an EXACT-match allowlist. It is deny-by-default:
// an empty allowlist means no cross-origin request is granted CORS
// access (same-origin requests are unaffected). A literal "*" entry is
// ignored — this middleware never emits a wildcard origin, and never
// emits "*" together with credentials (the Fetch spec forbids that
// combination and it would be an origin-confusion hole on an IdP).
type CORSOptions struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAgeSeconds  int
}

// DefaultCORSOptions returns sensible method/header defaults for the
// supplied (possibly empty) origin allowlist.
func DefaultCORSOptions(allowedOrigins []string) CORSOptions {
	return CORSOptions{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type", "Authorization", "X-Requested-With", "X-CSRF-Token"},
		MaxAgeSeconds:  600,
	}
}

// CORS returns deny-by-default CORS middleware for the given exact-match
// origin allowlist (empty => deny all cross-origin).
func CORS(allowedOrigins []string) gin.HandlerFunc {
	return CORSWithOptions(DefaultCORSOptions(allowedOrigins))
}

// CORSWithOptions returns the CORS middleware.
//
// Behaviour:
//   - No Origin header (same-origin or non-browser) → no CORS headers,
//     pass through. Same-origin and server-to-server traffic is
//     unaffected.
//   - Origin present + EXACTLY in the allowlist → echo that exact origin
//     in Access-Control-Allow-Origin, set Access-Control-Allow-Credentials:
//     true, and Vary: Origin. A preflight (OPTIONS + Access-Control-
//     Request-Method) additionally returns the allow-methods/headers/max-age
//     and short-circuits with 204.
//   - Origin present but NOT in the allowlist → emit NO Access-Control-
//     Allow-* headers (the browser blocks the response). A preflight from a
//     disallowed origin returns 204 with no allow headers (still no access).
//
// Origins are matched byte-for-byte against the allowlist — there is NO
// substring or suffix matching (a suffix match would be an origin-bypass
// bug, e.g. `https://app.example.com.evil.com`). The echoed value is
// always the specific request origin, never "*", so "*" + credentials can
// never occur.
//
// It only sets response headers / short-circuits preflight; it never
// touches auth, cookies, or the request body, and never panics/exits
// (P-018).
func CORSWithOptions(opts CORSOptions) gin.HandlerFunc {
	allow := make(map[string]struct{}, len(opts.AllowedOrigins))
	for _, o := range opts.AllowedOrigins {
		o = strings.TrimSpace(o)
		if o == "" || o == "*" { // never honor empty or a literal wildcard
			continue
		}
		allow[o] = struct{}{}
	}
	methods := strings.Join(opts.AllowedMethods, ", ")
	headers := strings.Join(opts.AllowedHeaders, ", ")
	maxAge := strconv.Itoa(opts.MaxAgeSeconds)

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		isPreflight := c.Request.Method == http.MethodOptions && c.GetHeader("Access-Control-Request-Method") != ""

		if origin == "" {
			// Same-origin / non-browser: no CORS negotiation.
			c.Next()
			return
		}

		_, ok := allow[origin] // EXACT match — no substring/suffix
		if !ok {
			// Disallowed origin: emit no Allow-* headers so the browser
			// blocks the response. Answer a disallowed preflight with a
			// bare 204 (no allow headers).
			if isPreflight {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
			return
		}

		// Allowlisted origin: echo the exact origin (never "*") + credentials.
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Vary", "Origin")

		if isPreflight {
			c.Header("Access-Control-Allow-Methods", methods)
			c.Header("Access-Control-Allow-Headers", headers)
			c.Header("Access-Control-Max-Age", maxAge)
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
