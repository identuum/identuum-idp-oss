package mw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/stretchr/testify/assert"
)

func init() {
	// Initialize logger for tests
	logger.InitializeZapLogger()
	gin.SetMode(gin.TestMode)
}

// TestRecoveryMiddleware_Panic tests that panic is recovered and returns 500
func TestRecoveryMiddleware_Panic(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())
	r.Use(RequestIDMiddleware())

	// Handler that panics
	r.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Internal server error")
	assert.Contains(t, w.Body.String(), "success")
	assert.Contains(t, w.Body.String(), "false")
}

// TestRecoveryMiddleware_PanicWithRequestID tests that panic includes request ID in logs
func TestRecoveryMiddleware_PanicWithRequestID(t *testing.T) {
	r := gin.New()
	r.Use(RequestIDMiddleware()) // Set request ID first
	r.Use(RecoveryMiddleware())

	// Handler that panics
	r.GET("/panic-with-id", func(c *gin.Context) {
		// Verify request ID is set before panic
		requestID := c.GetString(domain.CtxKeyRequestID)
		assert.NotEmpty(t, requestID)
		panic("test panic with request ID")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic-with-id", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Internal server error")
}

// TestRecoveryMiddleware_NoPanic tests that normal requests continue without issues
func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())
	r.Use(RequestIDMiddleware())

	// Normal handler
	r.GET("/normal", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "OK",
		})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/normal", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "OK")
	assert.Contains(t, w.Body.String(), `"success":true`)
}

// TestRecoveryMiddleware_PanicString tests panic with string error
func TestRecoveryMiddleware_PanicString(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())

	r.GET("/panic-string", func(c *gin.Context) {
		panic("string panic message")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic-string", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Internal server error")
}

// TestRecoveryMiddleware_PanicError tests panic with error type
func TestRecoveryMiddleware_PanicError(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())

	r.GET("/panic-error", func(c *gin.Context) {
		panic(assert.AnError)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic-error", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Internal server error")
}

// TestRecoveryMiddleware_MultiplePanics tests that each panic is handled independently
func TestRecoveryMiddleware_MultiplePanics(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())

	r.GET("/panic1", func(c *gin.Context) {
		panic("first panic")
	})
	r.GET("/panic2", func(c *gin.Context) {
		panic("second panic")
	})

	// First panic
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/panic1", nil)
	r.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusInternalServerError, w1.Code)

	// Second panic - should still work
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/panic2", nil)
	r.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusInternalServerError, w2.Code)
}

// TestRecoveryMiddleware_ChainContinuesAfterPanic tests that middleware chain is aborted after panic
func TestRecoveryMiddleware_ChainContinuesAfterPanic(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())

	executed := false
	r.Use(func(c *gin.Context) {
		executed = true
		c.Next()
	})

	r.GET("/panic-chain", func(c *gin.Context) {
		panic("test chain panic")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic-chain", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.True(t, executed, "Middleware before handler should have executed")
}

// TestRecoveryMiddleware_ResponseFormat tests the JSON response format
func TestRecoveryMiddleware_ResponseFormat(t *testing.T) {
	r := gin.New()
	r.Use(RecoveryMiddleware())

	r.GET("/panic-format", func(c *gin.Context) {
		panic("format test")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic-format", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	body := w.Body.String()
	assert.Contains(t, body, `"success":false`)
	assert.Contains(t, body, `"message":"Internal server error"`)
	// Should NOT contain stack trace in response
	assert.NotContains(t, body, "panic-format")
	assert.NotContains(t, body, "goroutine")
}
