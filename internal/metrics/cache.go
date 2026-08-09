package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// CacheOperations tracks cache hits, misses, and errors
	CacheOperations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_cache_operations_total",
		Help: "Total number of cache operations by result",
	}, []string{"cache", "operation", "result"})

	// CacheRequestDuration tracks latency of Redis operations
	CacheRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "identuum_idp_cache_request_duration_seconds",
		Help:    "Histogram of cache request latency",
		Buckets: prometheus.DefBuckets,
	}, []string{"operation", "result"})
)
