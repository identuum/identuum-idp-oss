package mw

import "github.com/gin-gonic/gin"

// SecurityHeadersOptions carries the response security-header values the
// SecurityHeaders middleware writes. Empty fields are skipped. Use
// DefaultSecurityHeadersOptions for the hardened defaults.
type SecurityHeadersOptions struct {
	// HSTS is the Strict-Transport-Security value. Browsers ignore HSTS
	// on plain-HTTP responses (per spec), so it is safe to set it
	// unconditionally, including for an app served over HTTP behind a
	// TLS-terminating proxy or for local HTTP development.
	HSTS string
	// XFrameOptions is the X-Frame-Options value (legacy clickjacking
	// control; the CSP frame-ancestors directive is the modern one and
	// both are set for defense in depth).
	XFrameOptions string
	// XContentTypeOptions is the X-Content-Type-Options value (nosniff).
	XContentTypeOptions string
	// ReferrerPolicy is the Referrer-Policy value.
	ReferrerPolicy string
	// ContentSecurityPolicy is the Content-Security-Policy value.
	//
	// This service serves BOTH JSON (the API) and HTML (the OAuth
	// consent form + browser-login page, which do NOT set their own CSP).
	// A blanket `default-src 'none'` would break those HTML forms, so the
	// default is scoped to `frame-ancestors 'none'` — the clickjacking
	// control, which restricts framing (safe for both HTML and JSON) and
	// does NOT restrict resource loading. An operator serving a JSON-only
	// surface can tighten this to `default-src 'none'; frame-ancestors 'none'`.
	ContentSecurityPolicy string
}

// DefaultSecurityHeadersOptions returns the hardened default header set.
//
// HSTS: 2 years + includeSubDomains. X-Frame-Options: DENY. Content-Type
// sniffing: nosniff. Referrer-Policy: strict-origin-when-cross-origin.
// CSP: frame-ancestors 'none' (see ContentSecurityPolicy note above for
// why not default-src 'none').
func DefaultSecurityHeadersOptions() SecurityHeadersOptions {
	return SecurityHeadersOptions{
		HSTS:                  "max-age=63072000; includeSubDomains",
		XFrameOptions:         "DENY",
		XContentTypeOptions:   "nosniff",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		ContentSecurityPolicy: "frame-ancestors 'none'",
	}
}

// SecurityHeaders returns middleware that writes the hardened default
// response security headers on every response.
func SecurityHeaders() gin.HandlerFunc {
	return SecurityHeadersWithOptions(DefaultSecurityHeadersOptions())
}

// SecurityHeadersWithOptions returns middleware that writes the supplied
// response security headers on every response.
//
// The headers are written BEFORE c.Next(), so they apply to every
// response — including early 503s (the NOT-SERVING guard) and 4xx auth
// rejections. A downstream handler that sets its own value for one of
// these headers (e.g. the frontchannel-logout page's page-specific CSP)
// overrides the default, because the handler runs after this middleware.
//
// It only writes headers and calls c.Next(); it never reads the body,
// touches cookies, alters status, or panics/exits (P-018).
func SecurityHeadersWithOptions(opts SecurityHeadersOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		if opts.HSTS != "" {
			c.Header("Strict-Transport-Security", opts.HSTS)
		}
		if opts.XFrameOptions != "" {
			c.Header("X-Frame-Options", opts.XFrameOptions)
		}
		if opts.XContentTypeOptions != "" {
			c.Header("X-Content-Type-Options", opts.XContentTypeOptions)
		}
		if opts.ReferrerPolicy != "" {
			c.Header("Referrer-Policy", opts.ReferrerPolicy)
		}
		if opts.ContentSecurityPolicy != "" {
			c.Header("Content-Security-Policy", opts.ContentSecurityPolicy)
		}
		c.Next()
	}
}
