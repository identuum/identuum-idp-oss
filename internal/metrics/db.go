package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// DBQueryDuration tracks latency of database queries
	DBQueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "identuum_idp_db_query_duration_seconds",
		Help:    "Histogram of database query latency",
		Buckets: prometheus.DefBuckets,
	}, []string{"repository", "method", "status"})

	// DBRequestDuration tracks low-level pgx query latency
	DBRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "identuum_idp_db_request_duration_seconds",
		Help:    "Histogram of low-level database query latency (pgx)",
		Buckets: prometheus.DefBuckets,
	}, []string{"command", "status"})
)
