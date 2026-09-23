package api

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestUI_BFF_AuthenticatedResponsesCannotBeCached(t *testing.T) {
	for _, upstreamPolicy := range []string{"", "public, max-age=3600"} {
		t.Run(upstreamPolicy, func(t *testing.T) {
			e := uiEngine(t, uiExportDir(t))
			e.GET("/api/v1/cache-probe", func(c *gin.Context) {
				if upstreamPolicy != "" {
					c.Header("Cache-Control", upstreamPolicy)
				}
				c.JSON(http.StatusOK, gin.H{"ok": true})
			})
			rec := uiGet(e, "/bff/api/v1/cache-probe", func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "access_token", Value: "good"})
			})
			if rec.Code != http.StatusOK {
				t.Fatalf("BFF response status = %d, want 200", rec.Code)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Error("browser BFF response must prohibit storage regardless of upstream cache policy")
			}
		})
	}
}
