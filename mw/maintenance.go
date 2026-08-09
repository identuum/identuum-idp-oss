package mw

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// UnconfiguredSystemBlocker returns a middleware that blocks
// all requests if the system is not configured.
func UnconfiguredSystemBlocker(isConfigured func() bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Allow health check to pass so orchestration/monitoring knows service is up
		if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/api/v1/health" {
			c.Next()
			return
		}

		// Also allow static assets/logo so the maintenance page (if we had one) could render?
		// or at least so the 503 doesn't look completely broken in browser network tab for favicon.
		// But strictly, block API.

		if !isConfigured() {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "System Not Configured",
				"message": "The functionality of this system is suspended until the Site Admin is configured. Please run 'identuum --setup'.",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
