package mw

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
	"github.com/identuum/identuum-idp-oss/logger"
)

const (
	RequestIDHeader     = "X-Request-ID"
	RequestIDKey        = domain.CtxKeyRequestID // Gin context key
	CorrelationIDHeader = "X-Correlation-ID"
	CorrelationIDKey    = domain.CtxKeyCorrelationID // Gin context key
)

// Pinger abstracts database connection/pool for readiness check
type Pinger interface {
	Ping(ctx context.Context) error
}

// DatabaseReadinessMiddleware checks if the database is ready before processing requests
// Returns 503 Service Unavailable if database is not ready
func DatabaseReadinessMiddleware(pool Pinger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip readiness check for health check endpoint itself (handled separately)
		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}

		if pool == nil || pool.Ping(c.Request.Context()) != nil {
			requestID := c.GetString(RequestIDKey)
			logger.Warning.WithFields(map[string]any{
				domain.CtxKeyRequestID: requestID,
				"path":                 c.Request.URL.Path,
			}).Print("Request rejected - database not ready")

			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":  "service_unavailable",
				"message": "Service is running in degraded mode (database unavailable)",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if request ID exists in header
		requestID := c.GetHeader(RequestIDHeader)
		if requestID == "" {
			id, err := uuidgen.NewV7String()
			if err != nil {
				// Request IDs are non-critical for persistence; log and use timestamp fallback.
				logger.Warning.Printf("Failed to generate request ID via uuidgen: %v — using timestamp fallback", err)
				id = fmt.Sprintf("%d", time.Now().UnixNano())
			}
			requestID = id
		} else {
			// Security (INFO-5): Sanitize client-supplied request IDs before logging/storing.
			// Prevents log injection via ANSI codes, newlines, script tags etc.
			requestID = sanitizeRequestID(requestID)
		}

		// Set request ID in header and context
		c.Header(RequestIDHeader, requestID)
		ctx := context.WithValue(c.Request.Context(), logger.RequestIDKey, requestID)
		c.Request = c.Request.WithContext(ctx)

		// Set request ID in Gin context for easy access
		c.Set(RequestIDKey, requestID)

		// Capture start time
		start := time.Now()

		path := c.Request.URL.Path
		// Only log API requests to reduce noise
		shouldLog := strings.HasPrefix(path, "/api")

		// Log request start
		if shouldLog {
			logger.Info.WithContext(
				ctx,
				"Request started",
				map[string]any{
					"method": c.Request.Method,
					"path":   path,
					"ip":     c.ClientIP(),
				},
			)
		}

		c.Next()

		// Calculate latency
		latency := time.Since(start)
		statusCode := c.Writer.Status()

		// Use colors for method and status code in development mode
		useColors := gin.Mode() != gin.ReleaseMode

		methodDisplay := c.Request.Method
		statusDisplay := fmt.Sprintf("%d", statusCode)

		if useColors {
			methodColor := logger.MethodColor(c.Request.Method)
			statusColor := logger.StatusCodeColor(statusCode)
			methodDisplay = methodColor + c.Request.Method + logger.Reset
			statusDisplay = statusColor + fmt.Sprintf("%d", statusCode) + logger.Reset
		}

		// Log request completion with colors
		if shouldLog {
			logFields := map[string]any{
				"status_code": statusCode,
				"path":        path,
				"latency_ms":  latency.Milliseconds(),
			}

			if useColors {
				logFields["status"] = statusDisplay
				logFields["method"] = methodDisplay
			} else {
				logFields["status"] = statusCode
				logFields["method"] = c.Request.Method
			}

			logger.Info.WithContext(
				ctx,
				"Request completed",
				logFields,
			)
		}
	}
}

// sanitizeRequestID strips any characters outside [a-zA-Z0-9-] from a client-supplied
// request ID and caps the result at 128 characters. This prevents log injection attacks
// via specially crafted X-Request-ID header values (ANSI codes, newlines, HTML/script tags).
func sanitizeRequestID(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if len(result) > 128 {
		result = result[:128]
	}
	return result
}

// CorrelationIDMiddleware reads the X-Correlation-ID request header, sanitizes it,
// and stores the value in the Gin context and request context under CtxKeyCorrelationID.
// When the header is absent the middleware is a no-op — downstream callers that read
// from context will get an empty string and leave correlation_id NULL on audit rows.
//
// Do NOT confuse this with X-Request-ID (which is always generated when missing).
// Correlation IDs are caller-supplied cross-service traces; they are never invented
// by the server.
func CorrelationIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.GetHeader(CorrelationIDHeader)
		if raw == "" {
			c.Next()
			return
		}
		sanitized := sanitizeCorrelationID(raw)
		if sanitized == "" {
			// Header was present but contained only stripped characters.
			c.Next()
			return
		}
		c.Set(CorrelationIDKey, sanitized)
		ctx := context.WithValue(c.Request.Context(), logger.CorrelationIDKey, sanitized)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// sanitizeCorrelationID strips control characters and limits length to 128 characters.
// Allows alphanumeric, '-', '_', and '.' which covers UUID, trace-id, and dotted
// namespace formats used by common distributed tracing systems. Newlines and all
// other control characters are stripped to prevent log injection.
func sanitizeCorrelationID(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if len(result) > 128 {
		result = result[:128]
	}
	return result
}
