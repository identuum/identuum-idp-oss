package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// JobDuration tracks the duration of background jobs
	JobDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "identuum_idp_job_duration_seconds",
		Help:    "Duration of background jobs",
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600}, // Up to 10 minutes
	}, []string{"type", "status"}) // type=backup|cleanup, status=success|failure

	// JobLastSuccess tracks the timestamp of the last successful job run
	JobLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "identuum_idp_job_last_success_timestamp_seconds",
		Help: "Timestamp of the last successful job run",
	}, []string{"type"})

	// BackupSize tracks the size of the backup file in bytes
	BackupSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "identuum_idp_backup_size_bytes",
		Help: "Size of the backup file in bytes",
	}, []string{"type"}) // type=db|auto
)
