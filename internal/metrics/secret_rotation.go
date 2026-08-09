package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// §7.3 — live secret rotation observability. Exposed for Grafana
// dashboards that chart rotation cadence and failure rate.

var (
	// SecretRotationAttempts is incremented on every watcher poll that
	// reaches the provider — success or failure. Baseline rate equals
	// 1/poll_interval; any sustained deviation signals a stopped
	// watcher.
	SecretRotationAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "identuum_idp_secret_rotation_attempts_total",
		Help: "Total number of secret-rotation watcher polls (regardless of outcome)",
	})

	// SecretRotationSuccess is incremented on each successful rotation
	// (the Vault value actually changed and was swapped into the active
	// slot). A no-op poll with an unchanged value is NOT counted here —
	// see SecretRotationNoop.
	SecretRotationSuccess = promauto.NewCounter(prometheus.CounterOpts{
		Name: "identuum_idp_secret_rotation_success_total",
		Help: "Total number of successful secret rotations (active key swapped)",
	})

	// SecretRotationNoop is incremented on each poll that returned the
	// same value as the current active key. Useful as a liveness
	// signal — a ratio of (noop + failure + success) over a window
	// proves the watcher is alive.
	SecretRotationNoop = promauto.NewCounter(prometheus.CounterOpts{
		Name: "identuum_idp_secret_rotation_noop_total",
		Help: "Total number of secret-rotation polls that returned an unchanged value",
	})

	// SecretRotationFailures is incremented whenever the poll errored
	// (transport failure) or the returned value was rejected by the
	// CryptoService (malformed material). Labels keep the two causes
	// separable in dashboards.
	SecretRotationFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_secret_rotation_failures_total",
		Help: "Total number of secret-rotation failures by cause (transport|swap_rejected)",
	}, []string{"cause"})

	// SecretPreviousKeys is a gauge of how many previous keys the
	// CryptoService holds for legacy-ciphertext decryption. It grows
	// monotonically across rotations today (v0 has no retirement path)
	// so this metric is the operator's trigger for the manual
	// re-encryption sweep.
	SecretPreviousKeys = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "identuum_idp_secret_previous_keys",
		Help: "Count of previous encryption keys retained for legacy ciphertext decryption",
	})
)
