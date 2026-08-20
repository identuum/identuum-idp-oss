package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// SystemHealthDeps wires GET /api/v1/health/details — the site_admin runtime
// info surface (THE-HEALTH-DETAILS; owner ruling: Runtime info IS an OSS
// feature). Authority: site_admin only (AdminPermissionsModel — runtime
// info is infrastructure-level, and site_admin is the infrastructure
// authority). The response serves ONLY the fields OSS truly has; fields OSS
// cannot know are ABSENT (pointer + omitempty), never zero-faked. It carries
// NO database URL, key material, or session material.
type SystemHealthDeps struct {
	// Version is the build identifier surfaced to the operator.
	Version string
	// DBPinger, when wired, is a liveness check for the Postgres pool. Nil
	// (no-DB scaffold) makes the `database` component ABSENT — OSS does not
	// zero-fake a database status it cannot obtain.
	DBPinger func(ctx context.Context) error
	// AuditWired reports whether the persistent audit log is wired. When
	// false the `audit_system` component is ABSENT.
	AuditWired bool
	// StartupReport supplies the top-level status (P-018). Nil-safe.
	StartupReport *lifecycle.StartupReport
}

// systemHealthComponent is a single dependency's liveness. Only a status —
// never a URL, host, or credential.
type systemHealthComponent struct {
	Status string `json:"status"`
}

// systemAuditHealth is the audit subsystem's liveness. queue_depth is a
// pointer + omitempty: the OSS persistent audit log writes synchronously (no
// queue), so OSS cannot report a depth and OMITS the field rather than
// reporting a fake 0.
type systemAuditHealth struct {
	Status     string `json:"status"`
	QueueDepth *int   `json:"queue_depth,omitempty"`
}

// systemHealthResponse is the GET /api/v1/health/details body. status and
// version are ALWAYS present; database and audit_system are present only when
// OSS can obtain them; redis is ALWAYS absent on OSS (no Redis dependency).
type systemHealthResponse struct {
	Status      string                 `json:"status"`
	Version     string                 `json:"version"`
	Database    *systemHealthComponent `json:"database,omitempty"`
	AuditSystem *systemAuditHealth     `json:"audit_system,omitempty"`
	Redis       *systemHealthComponent `json:"redis,omitempty"`
}

// RegisterSystemHealthRoutes mounts GET /api/v1/health/details, site_admin
// gated. Distinct from the public liveness probe at /health.
func RegisterSystemHealthRoutes(router gin.IRouter, deps SystemHealthDeps) {
	g := router.Group("/api/v1/health/details")
	g.Use(mw.RequireSiteAdmin())

	// docgen:endpoint
	// docgen:surface=top-level
	// docgen:method=GET
	// docgen:path=/api/v1/health/details
	// docgen:summary=Site-admin runtime info: overall status, build version, and the liveness of the dependencies OSS actually has (database, audit log). Fields OSS cannot know (Redis, an audit queue depth) are ABSENT, never zero-faked. No URLs, credentials, or session material.
	// docgen:tier=oss
	// docgen:auth=site_admin
	// docgen:status=200
	g.GET("", handleSystemHealthDetails(deps))
}

func handleSystemHealthDetails(deps SystemHealthDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := systemHealthResponse{
			Status:  overallStatus(deps.StartupReport),
			Version: deps.Version,
		}

		// database: present ONLY when a pinger is wired. A ping error is a
		// real, reportable state ("unavailable"); nil pinger → field absent.
		if deps.DBPinger != nil {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
			defer cancel()
			status := "connected"
			if err := deps.DBPinger(ctx); err != nil {
				status = "unavailable"
			}
			resp.Database = &systemHealthComponent{Status: status}
		}

		// audit_system: present when wired. queue_depth stays ABSENT — the OSS
		// audit log is synchronous and has no queue to report.
		if deps.AuditWired {
			resp.AuditSystem = &systemAuditHealth{Status: "operational"}
		}

		// redis: ALWAYS absent on OSS — there is no Redis dependency, and a
		// zero-faked "unavailable" would be a lie about a dependency that does
		// not exist in this edition.

		c.JSON(http.StatusOK, resp)
	}
}

// overallStatus mirrors the public /health readiness contract (P-018):
// not_serving on a fatal fault, degraded on a non-fatal fault, else healthy.
// Nil-safe — an unwired report reads as healthy.
func overallStatus(report *lifecycle.StartupReport) string {
	switch {
	case report.HasFatal():
		return "not_serving"
	case len(report.Faults()) > 0:
		return "degraded"
	default:
		return "healthy"
	}
}
