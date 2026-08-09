package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// serviceMissingFallback is the uniform P-018 NOT-SERVING-JUST-ALERTING
// fail-safe handler a route factory mounts when a required backing
// dependency is not wired. Previously such a factory panicked at
// construction time, killing the process; now it records a fatal
// StartupReport fault and mounts the group's routes to this handler, so
// the process stays alive and the surface is refused cleanly with a
// secret-free 503 rather than crashing.
//
// In the real runtime a fatal fault flips the process to NOT-SERVING and
// the top-level NotServingGuard returns 503 for every non-allow-listed
// route BEFORE the request reaches this handler; this fallback is the
// belt-and-suspenders response for any path that bypasses the guard (e.g.
// a route factory invoked directly with nil deps in a unit test).
func serviceMissingFallback(surface string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "service unavailable",
			"surface": surface,
			"reason":  surface + " surface unavailable: a required dependency is not wired",
		})
	}
}
