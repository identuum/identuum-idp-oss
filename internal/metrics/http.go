package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTPRequests tracks API traffic
	HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_http_requests_total",
		Help: "Total number of HTTP requests by method, route, and status",
	}, []string{"method", "route", "status"})

	// HTTPRequestDuration tracks latency
	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "identuum_idp_http_request_duration_seconds",
		Help:    "Histogram of response latency (seconds) by method and route",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	// RateLimitHits tracks throttled requests
	RateLimitHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_ratelimit_hits_total",
		Help: "Total number of rate limit hits by route",
	}, []string{"route"})

	// DBConnectionStats tracks database pool health
	DBConnectionStats = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "identuum_idp_db_connection_stats",
		Help: "Database connection pool statistics",
	}, []string{"state"})
)
