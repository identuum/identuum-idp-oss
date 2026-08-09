package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// OIDCUpstreamRequestDuration tracks latency of external IDP calls
	OIDCUpstreamRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "identuum_idp_oidc_upstream_request_duration_seconds",
		Help:    "Histogram of upstream OIDC provider response latency",
		Buckets: []float64{0.1, 0.5, 1, 2, 5, 10},
	}, []string{"provider_id", "provider_type", "operation"})

	// OIDCUpstreamRequests tracks total external IDP calls
	OIDCUpstreamRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_oidc_upstream_requests_total",
		Help: "Total number of upstream OIDC provider requests",
	}, []string{"provider_id", "status_code", "result"})

	// OIDCFlowDuration tracks the latency of the OIDC Initiation and Callback flows within the service
	OIDCFlowDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "identuum_idp_oidc_flow_duration_seconds",
		Help:    "Histogram of OIDC flow processing latency (Start/Finish)",
		Buckets: []float64{0.05, 0.1, 0.5, 1, 2, 5},
	}, []string{"provider_type", "step", "status"})

	// OIDCStrictReauthMissingAuthTime increments when a strict-reauth-enabled
	// callback completes without an `auth_time` claim in the IdP response.
	// The §1.5 freshness check silently degrades to "trust the IdP did what we
	// asked" in this branch (Google Workspace omits auth_time even when
	// max_age=0 is requested) — operators must be able to alert on the rate of
	// silent degradation without grepping container logs. Unlabeled to keep
	// cardinality bounded; the per-org/per-provider context is in the warn log.
	OIDCStrictReauthMissingAuthTime = promauto.NewCounter(prometheus.CounterOpts{
		Name: "identuum_idp_oidc_strict_reauth_missing_auth_time_total",
		Help: "Strict re-authentication callbacks where the IdP omitted the auth_time claim (silent fail-open path).",
	})
)
