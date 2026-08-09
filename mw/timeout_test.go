package mw

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRequestTimeoutMiddleware_NormalRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.Use(RequestTimeoutMiddleware(2 * time.Second))

	router.GET("/test", func(c *gin.Context) {
		// Fast request that completes immediately
		c.JSON(http.StatusOK, gin.H{"status": "success"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
}

func TestRequestTimeoutMiddleware_SlowRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Logger initialized by package

	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.Use(RequestTimeoutMiddleware(100 * time.Millisecond))

	router.GET("/slow", func(c *gin.Context) {
		// Slow request that exceeds timeout
		time.Sleep(200 * time.Millisecond)
		c.JSON(http.StatusOK, gin.H{"status": "completed"})
	})

	req := httptest.NewRequest(http.MethodGet, "/slow", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestTimeout, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, false, response["success"])
	assert.Equal(t, "Request timeout", response["message"])
}

func TestRequestTimeoutMiddleware_RequestAtBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Logger initialized by package

	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.Use(RequestTimeoutMiddleware(150 * time.Millisecond))

	router.GET("/boundary", func(c *gin.Context) {
		// Request that completes just before timeout
		time.Sleep(100 * time.Millisecond)
		c.JSON(http.StatusOK, gin.H{"status": "completed"})
	})

	req := httptest.NewRequest(http.MethodGet, "/boundary", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should complete successfully since 100ms < 150ms
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "completed", response["status"])
}

func TestRequestTimeoutMiddleware_NoRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Logger initialized by package

	router := gin.New()
	// Note: No RequestIDMiddleware - testing timeout without request ID
	router.Use(RequestTimeoutMiddleware(100 * time.Millisecond))

	router.GET("/no-id", func(c *gin.Context) {
		time.Sleep(200 * time.Millisecond)
		c.JSON(http.StatusOK, gin.H{"status": "completed"})
	})

	req := httptest.NewRequest(http.MethodGet, "/no-id", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should still timeout even without request ID
	assert.Equal(t, http.StatusRequestTimeout, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, false, response["success"])
	assert.Equal(t, "Request timeout", response["message"])
}

func TestRequestTimeoutMiddleware_MultipleRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Logger initialized by package

	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.Use(RequestTimeoutMiddleware(150 * time.Millisecond))

	router.GET("/multi", func(c *gin.Context) {
		delay := c.Query("delay")
		if delay == "short" {
			time.Sleep(50 * time.Millisecond)
		} else {
			time.Sleep(200 * time.Millisecond)
		}
		c.JSON(http.StatusOK, gin.H{"delay": delay})
	})

	// Test short request (should succeed)
	req1 := httptest.NewRequest(http.MethodGet, "/multi?delay=short", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Test long request (should timeout)
	req2 := httptest.NewRequest(http.MethodGet, "/multi?delay=long", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusRequestTimeout, w2.Code)
}

func TestRequestTimeoutMiddleware_ContextPropagation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Logger initialized by package

	var contextChecked bool
	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.Use(RequestTimeoutMiddleware(2 * time.Second))

	router.GET("/context", func(c *gin.Context) {
		// Verify context has a deadline
		_, hasDeadline := c.Request.Context().Deadline()
		contextChecked = hasDeadline
		c.JSON(http.StatusOK, gin.H{"context": "checked"})
	})

	req := httptest.NewRequest(http.MethodGet, "/context", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, contextChecked, "Context should have deadline set")
}

func TestRequestTimeoutMiddleware_DifferentTimeouts(t *testing.T) {
	tests := []struct {
		name           string
		timeout        time.Duration
		handlerDelay   time.Duration
		expectedStatus int
	}{
		{
			name:           "Very short timeout (50ms), fast handler (10ms)",
			timeout:        50 * time.Millisecond,
			handlerDelay:   10 * time.Millisecond,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Very short timeout (50ms), slow handler (100ms)",
			timeout:        50 * time.Millisecond,
			handlerDelay:   100 * time.Millisecond,
			expectedStatus: http.StatusRequestTimeout,
		},
		{
			name:           "Long timeout (1s), instant handler (0ms)",
			timeout:        1 * time.Second,
			handlerDelay:   0,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Medium timeout (200ms), medium handler (150ms)",
			timeout:        200 * time.Millisecond,
			handlerDelay:   150 * time.Millisecond,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			// Logger initialized by package

			router := gin.New()
			router.Use(RequestIDMiddleware())
			router.Use(RequestTimeoutMiddleware(tt.timeout))

			router.GET("/test", func(c *gin.Context) {
				if tt.handlerDelay > 0 {
					time.Sleep(tt.handlerDelay)
				}
				c.JSON(http.StatusOK, gin.H{"status": "done"})
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestRequestTimeoutMiddleware_ErrorResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Logger initialized by package

	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.Use(RequestTimeoutMiddleware(100 * time.Millisecond))

	router.GET("/timeout", func(c *gin.Context) {
		time.Sleep(200 * time.Millisecond)
		c.JSON(http.StatusOK, gin.H{"never": "returned"})
	})

	req := httptest.NewRequest(http.MethodGet, "/timeout", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestTimeout, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Verify response structure
	assert.Contains(t, response, "success")
	assert.Contains(t, response, "message")
	assert.Equal(t, false, response["success"])
	assert.Equal(t, "Request timeout", response["message"])

	// Ensure handler's response is not returned
	assert.NotContains(t, response, "never")
}

func TestRequestTimeoutMiddleware_WriteHeaderNow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequestTimeoutMiddleware(50 * time.Millisecond))

	router.GET("/timeout-now", func(c *gin.Context) {
		time.Sleep(100 * time.Millisecond) // wait for timeout
		c.Writer.WriteHeaderNow()          // trigger WriteHeaderNow AFTER timeout
	})

	router.GET("/success-now", func(c *gin.Context) {
		c.Writer.WriteHeaderNow() // trigger BEFORE timeout
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	t.Run("Timeout triggers 408 on WriteHeaderNow", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/timeout-now", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusRequestTimeout, w.Code)
	})

	t.Run("Success preserves WriteHeaderNow", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/success-now", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
