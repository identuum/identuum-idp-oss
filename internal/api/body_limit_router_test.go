package api

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	httpmw "github.com/identuum/identuum-idp-oss/mw"
)

// P2-1: BodyLimitMiddleware is mounted GLOBALLY by RegisterOSSRoutes, so every
// route on the OSS engine — including the public UNAUTHENTICATED ones (setup,
// login, password-reset, WebAuthn, DCR) — is body-capped. The probe below is
// registered on the SAME engine AFTER NewOSSEngine returns, so it inherits the
// exact global middleware chain (gin combines engine-global handlers into every
// route registered through the engine). A drain that returns 413 on
// *http.MaxBytesError models how the real handlers surface an over-limit body.
//
// Teeth: with the global mount removed, the drain reads the full oversized body
// and returns 200 — this test then fails.
func TestNewOSSEngine_BodyLimit_RejectsOversizedBody(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})

	// A stand-in for a public unauthenticated POST handler: it drains the body
	// (as ShouldBindJSON would) and maps the MaxBytesReader overflow to 413.
	e.POST("/api/v1/__body_probe", func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				c.String(http.StatusRequestEntityTooLarge, "too large")
				return
			}
			c.String(http.StatusBadRequest, "bad")
			return
		}
		c.String(http.StatusOK, "ok")
	})

	post := func(n int) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/__body_probe", strings.NewReader(strings.Repeat("x", n)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)
		return w.Code
	}

	if got := post(1024); got != http.StatusOK {
		t.Errorf("1 KB body: status=%d, want 200 (under the %d-byte cap)", got, httpmw.MaxBodySize)
	}
	if got := post(httpmw.MaxBodySize + 1); got != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: status=%d, want 413 (global body limit must reject it)", got)
	}
}
