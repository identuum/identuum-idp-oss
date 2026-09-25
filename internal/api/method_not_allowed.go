package api

import (
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// OSS-405: a request whose path the engine registers for other methods is
// answered 405 with an Allow header naming those methods, never the UI shell
// or a 404. gin finds the methods (HandleMethodNotAllowed) and sets Allow
// before any middleware runs; this file keeps that header off every answer
// but the 405 itself, so a CORS preflight, a NOT-SERVING 503 or a bearer
// 401 answers exactly as it did when the request fell through to NoRoute.

// allowMethodOrder is the order an Allow header names methods in.
var allowMethodOrder = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions}

// methodNotAllowedBody is the 405 body, the API's {"error": code} shape.
var methodNotAllowedBody = gin.H{"error": "method_not_allowed"}

// allowHeldKey carries gin's Allow header past the middleware to NoMethod.
const allowHeldKey = "oss405.allow"

// holdAllow is the first global middleware: it lifts the Allow header gin
// sets for a method mismatch, so no middleware answer carries it, and
// NoMethod puts it back on the 405.
func holdAllow(c *gin.Context) {
	if allow := c.Writer.Header().Get("Allow"); allow != "" {
		c.Writer.Header().Del("Allow")
		c.Set(allowHeldKey, allow)
	}
	c.Next()
}

// mountMethodNotAllowed turns on gin's method matching with a NoMethod
// handler. fallback is the engine's NoRoute answer (nil: gin's plain 404):
// gin routes no HEAD to GET, so a HEAD on a GET route keeps the answer it
// had before, the fallback's.
func mountMethodNotAllowed(router gin.IRouter, fallback gin.HandlerFunc) {
	engine, ok := router.(*gin.Engine)
	if !ok {
		return
	}
	engine.HandleMethodNotAllowed = true
	engine.NoMethod(func(c *gin.Context) {
		allowed := strings.Split(c.GetString(allowHeldKey), ", ")
		if c.Request.Method == http.MethodHead && slices.Contains(allowed, http.MethodGet) {
			if fallback != nil {
				fallback(c)
				return
			}
			c.Data(http.StatusNotFound, "text/plain", []byte("404 page not found"))
			return
		}
		c.Header("Allow", allowHeader(allowed))
		c.AbortWithStatusJSON(http.StatusMethodNotAllowed, methodNotAllowedBody)
	})
}

// allowHeader names methods in allowMethodOrder, then any other in the
// order given.
func allowHeader(methods []string) string {
	out := make([]string, 0, len(methods))
	for _, m := range allowMethodOrder {
		if slices.Contains(methods, m) {
			out = append(out, m)
		}
	}
	for _, m := range methods {
		if m != "" && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return strings.Join(out, ", ")
}

// routeAllow answers, from the engine's route table (read once, on first
// use, when every route is registered), the Allow list for a method the
// engine does not serve at path; nil when it serves it, when path is no
// route, or for a HEAD where GET is served (answered as before). It is the
// boundary's uiserve.Options.AllowedMethods, so a wrong-method /bff request
// is answered as the engine would answer it, without being forwarded.
func routeAllow(engine *gin.Engine) func(method, path string) []string {
	var once sync.Once
	var routes gin.RoutesInfo
	return func(method, path string) []string {
		once.Do(func() { routes = engine.Routes() })
		var methods []string
		for _, r := range routes {
			if routeMatches(r.Path, path) && !slices.Contains(methods, r.Method) {
				methods = append(methods, r.Method)
			}
		}
		if len(methods) == 0 || slices.Contains(methods, method) ||
			(method == http.MethodHead && slices.Contains(methods, http.MethodGet)) {
			return nil
		}
		return strings.Split(allowHeader(methods), ", ")
	}
}

// routeMatches is gin's match of one route pattern: a static segment by
// equality, a :param any one non-empty segment, a *wildcard the rest.
func routeMatches(pattern, path string) bool {
	ps, xs := strings.Split(pattern, "/"), strings.Split(path, "/")
	for i, s := range ps {
		if strings.HasPrefix(s, "*") {
			return true
		}
		if i >= len(xs) || (strings.HasPrefix(s, ":") && xs[i] == "") || (!strings.HasPrefix(s, ":") && s != xs[i]) {
			return false
		}
	}
	return len(ps) == len(xs)
}
