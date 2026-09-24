package uiserve_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing/fstest"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/pkg/uiserve"
)

// An importer outside identuum-idp-oss (an edition binary) mounts the UI from
// its own fs.FS and registers one route of its own; the boundary forwards
// to that route, and the shell answers the UI's client-side paths.
func Example() {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.GET("/api/v1/edition", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"edition": "ce"})
	})
	ui := fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html><title>edition shell</title>")},
		"assets/app.js": {Data: []byte("console.log('edition')")},
	}
	if err := uiserve.Mount(engine, uiserve.Options{
		UI:      ui,
		Source:  "the edition's UI",
		Status:  uiserve.Status{Product: "identuum-idp-ce"},
		Refresh: nil, // this example offers no session refresh
	}); err != nil {
		fmt.Println("mount:", err)
		return
	}

	get := func(target string, proof bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if proof {
			req.Header.Set(uiserve.RequestHeader, uiserve.RequestHeaderValue)
		}
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec
	}
	shell := get("/org-admin/users", false)
	fmt.Println(shell.Code, strings.Contains(shell.Body.String(), "edition shell"), shell.Header().Get("Cache-Control"))
	asset := get("/assets/app.js", false)
	fmt.Println(asset.Code, asset.Header().Get("Cache-Control"))
	route := get("/bff/api/v1/edition", true)
	fmt.Println(route.Code, strings.TrimSpace(route.Body.String()))
	refused := get("/bff/api/v1/edition", false)
	fmt.Println(refused.Code, strings.TrimSpace(refused.Body.String()))
	status := get("/api/status", false)
	fmt.Println(status.Code, strings.Contains(status.Body.String(), `"product":"identuum-idp-ce"`))
	// Output:
	// 200 true no-store
	// 200 public, max-age=31536000, immutable
	// 200 {"edition":"ce"}
	// 403 {"error":"csrf_failed","reason":"missing_request_header"}
	// 200 true
}
