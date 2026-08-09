package mw

import (
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/logger"
	"go.uber.org/zap"
)

// RecoveryMiddleware recovers from panics and logs the error
// This prevents the entire application from crashing on unhandled panics
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				stack := string(debug.Stack())
				logger.ErrorContext(c.Request.Context(), "Panic recovered in HTTP handler",
					zap.Any("panic", err),
					zap.String("stack", stack),
					zap.String("path", c.Request.URL.Path),
					zap.String("method", c.Request.Method),
					zap.String("ip", c.ClientIP()),
				)

				// Return generic error to client (don't expose stack trace)
				c.JSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"message": "Internal server error",
				})
				c.Abort()
			}
		}()
		c.Next()
	}
}
