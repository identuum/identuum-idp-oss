package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestUI_BFF_UnredactableAuthenticationResponseIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		body        string
	}{
		{"malformed-json", "application/json", `{"access_token":"synthetic-response-marker"`},
		{"text-response", "text/plain", "synthetic-response-marker"},
		{"array-response", "application/json", `["synthetic-response-marker"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := uiEngine(t, uiExportDir(t))
			e.POST("/api/v1/auth/unredactable", func(c *gin.Context) {
				c.Header("Set-Cookie", "access_token=synthetic-cookie-marker; Path=/; HttpOnly")
				c.Data(http.StatusOK, tc.contentType, []byte(tc.body))
			})
			rec := uiPost(e, "/bff/api/v1/auth/unredactable", withHeader(uiBFFRequiredHeader, uiBFFRequiredHeaderValue))
			if rec.Code != http.StatusBadGateway {
				t.Errorf("unredactable authentication response status = %d, want 502", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "synthetic-response-marker") {
				t.Error("unredactable authentication material reached the browser body")
			}
			if len(rec.Header().Values("Set-Cookie")) != 0 {
				t.Error("refused authentication response changed browser cookies")
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Error("refused authentication response is not marked no-store")
			}
		})
	}
}
