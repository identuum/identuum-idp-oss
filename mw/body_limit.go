package mw

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxBodySize is the maximum allowed request body size (1 MB).
// This protects against memory exhaustion from oversized payloads.
// See ARCHITECTURAL_GUIDELINES.md §4: "Max body size 1MB".
const MaxBodySize = 1 << 20 // 1 MB

// RouteBodyLimits is a registry of per-route overrides for the global body
// limit, keyed by gin's matched route template (`c.FullPath()`, e.g.
// "/api/v1/organizations/:id/backups/restore-upload"). An entry larger than
// MaxBodySize widens the cap for that specific route only; a smaller value
// tightens it. Routes not present in the map fall back to MaxBodySize.
//
// This indirection exists because gin evaluates `r.Use()` middleware before
// route-level middleware, so a per-route wrapper applied inside the route
// handler chain cannot unwrap the global MaxBytesReader. Instead the global
// middleware reads the override at request time based on the matched route.
type RouteBodyLimits map[string]int64

// BodyLimitMiddleware wraps the request body with http.MaxBytesReader
// to enforce a maximum body size of MaxBodySize bytes (or a per-route
// override supplied via overrides).
//
// When a handler (or JSON decoder) reads past the limit, the reader
// returns *http.MaxBytesError and the underlying ResponseWriter emits a
// 413 Request Entity Too Large, preventing memory exhaustion regardless
// of the response status code the handler chooses.
func BodyLimitMiddleware(overrides ...RouteBodyLimits) gin.HandlerFunc {
	// Flatten the optional variadic into a single lookup map so the hot
	// path does not have to loop.
	effective := RouteBodyLimits{}
	for _, o := range overrides {
		for k, v := range o {
			effective[k] = v
		}
	}
	return func(c *gin.Context) {
		if c.Request.Body == nil {
			c.Next()
			return
		}
		limit := int64(MaxBodySize)
		if v, ok := effective[c.FullPath()]; ok && v > 0 {
			limit = v
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}
