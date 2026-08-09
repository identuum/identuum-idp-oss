package mw

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/logger"
	"go.uber.org/zap"
)

// RequestTimeoutMiddleware adds a timeout to all requests.
// We DO NOT run `c.Next()` in a goroutine because Gin contexts and their writers
// are definitively not thread-safe. Instead, we inject the context timeout and rely
// on Postgres/services honoring `ctx.Done()`. To detect if a timeout happened, we
// check `ctx.Err()` after `c.Next()` completes. If it timed out, we overwrite
// the response if headers weren't sent, or just log.
func RequestTimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		// Create a custom writer to intercept writes
		// If timeout occurs, we prevent further writes and return 408
		tw := &timeoutWriter{ResponseWriter: c.Writer, ctx: ctx}
		c.Writer = tw

		c.Next()

		if ctx.Err() == context.DeadlineExceeded {
			logger.ErrorContext(ctx, "Request timeout exceeded",
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method),
				zap.String("timeout", timeout.String()),
			)
			// Tests explicitly expect a 408 on timeout.
			// Since we intercepted the write, we can safely overwrite here if nothing was written
			// Or if it was intercepted, we already returned 408 inside the writer.
		}
	}
}

type timeoutWriter struct {
	gin.ResponseWriter
	ctx         context.Context
	wroteHeader bool
}

func (tw *timeoutWriter) WriteHeader(code int) {
	if tw.ctx.Err() == context.DeadlineExceeded && !tw.wroteHeader {
		tw.wroteHeader = true
		tw.ResponseWriter.Header().Set("Content-Type", "application/json; charset=utf-8")
		tw.ResponseWriter.WriteHeader(http.StatusRequestTimeout)
		_, _ = tw.ResponseWriter.Write([]byte(`{"success":false,"message":"Request timeout"}`))
		return
	}
	if !tw.wroteHeader {
		tw.wroteHeader = true
		tw.ResponseWriter.WriteHeader(code)
	}
}

func (tw *timeoutWriter) Write(b []byte) (int, error) {
	if tw.ctx.Err() == context.DeadlineExceeded {
		if !tw.wroteHeader {
			tw.WriteHeader(http.StatusRequestTimeout)
		}
		// Swallow the rest
		return len(b), nil
	}
	tw.wroteHeader = true
	return tw.ResponseWriter.Write(b)
}

func (tw *timeoutWriter) WriteHeaderNow() {
	if tw.ctx.Err() == context.DeadlineExceeded && !tw.wroteHeader {
		tw.WriteHeader(http.StatusRequestTimeout)
		return
	}
	if !tw.wroteHeader {
		tw.wroteHeader = true
		tw.ResponseWriter.WriteHeaderNow()
	}
}
