package mw

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestBodyLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		method     string
		bodySize   int
		wantStatus int
	}{
		{
			name:       "body within limit",
			method:     http.MethodPost,
			bodySize:   1024, // 1 KB
			wantStatus: http.StatusOK,
		},
		{
			name:       "body exactly at limit",
			method:     http.MethodPost,
			bodySize:   MaxBodySize, // 1 MB
			wantStatus: http.StatusOK,
		},
		{
			name:       "body exceeds limit",
			method:     http.MethodPost,
			bodySize:   MaxBodySize + 1,
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:       "GET request no body",
			method:     http.MethodGet,
			bodySize:   0,
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(BodyLimitMiddleware())

			r.POST("/test", func(c *gin.Context) {
				// Drain the body to trigger MaxBytesReader if limit exceeded
				_, err := io.ReadAll(c.Request.Body)
				if err != nil {
					var maxBytesErr *http.MaxBytesError
					if errors.As(err, &maxBytesErr) {
						c.JSON(http.StatusRequestEntityTooLarge, gin.H{
							"success": false,
							"message": "Request body too large",
						})
						return
					}
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			r.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"success": true})
			})

			var req *http.Request
			if tt.bodySize > 0 {
				body := strings.NewReader(strings.Repeat("x", tt.bodySize))
				req = httptest.NewRequest(tt.method, "/test", body)
			} else {
				req = httptest.NewRequest(tt.method, "/test", nil)
			}
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

// TestBodyLimitMiddleware_RouteOverrideWidensLimit exercises the per-route
// override used by the org-backup restore-upload endpoint, which needs to
// accept multi-megabyte `.idbak` uploads while keeping the 1 MB cap on every
// other route.
func TestBodyLimitMiddleware_RouteOverrideWidensLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const overrideLimit = int64(2 * MaxBodySize) // 2 MB
	r := gin.New()
	r.Use(BodyLimitMiddleware(RouteBodyLimits{
		"/upload": overrideLimit,
	}))

	handler := func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{})
			return
		}
		c.JSON(http.StatusOK, gin.H{})
	}
	r.POST("/upload", handler)
	r.POST("/other", handler)

	// 1.5 MB on the overridden route → still ok (< 2 MB override).
	largeBody := strings.NewReader(strings.Repeat("x", int(1.5*MaxBodySize)))
	req := httptest.NewRequest(http.MethodPost, "/upload", largeBody)
	req.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code,
		"1.5 MB on /upload must pass under the 2 MB override")

	// Same 1.5 MB on a non-overridden route → 413.
	largeBody2 := strings.NewReader(strings.Repeat("x", int(1.5*MaxBodySize)))
	req2 := httptest.NewRequest(http.MethodPost, "/other", largeBody2)
	req2.Header.Set("Content-Type", "application/octet-stream")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w2.Code,
		"1.5 MB on /other must be capped at the global 1 MB")

	// Body exceeding even the override on the overridden route → 413.
	oversized := strings.NewReader(strings.Repeat("x", int(overrideLimit)+1))
	req3 := httptest.NewRequest(http.MethodPost, "/upload", oversized)
	req3.Header.Set("Content-Type", "application/octet-stream")
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w3.Code,
		"body above the per-route override must still 413")
}

func TestBodyLimitMiddleware_LargePayloadPreventsMemoryExhaustion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(BodyLimitMiddleware())

	var totalBytesRead int
	r.POST("/test", func(c *gin.Context) {
		buf := make([]byte, 4096)
		for {
			n, err := c.Request.Body.Read(buf)
			totalBytesRead += n
			if err != nil {
				break
			}
		}
		c.JSON(http.StatusOK, gin.H{"bytes_read": totalBytesRead})
	})

	// Send 10 MB — but the reader should stop at ~1 MB
	largeBody := strings.NewReader(strings.Repeat("x", 10*MaxBodySize))
	req := httptest.NewRequest(http.MethodPost, "/test", largeBody)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// MaxBytesReader allows reading up to limit+1 byte to detect overflow
	assert.LessOrEqual(t, totalBytesRead, MaxBodySize+1, "MaxBytesReader should prevent reading beyond the limit")
}
