package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// EmailDelivery tracks attempted SMTP deliveries from the unified
	// notification_service.sendEmail chokepoint. The kind label identifies
	// the calling Send* function so dashboards can spot SMTP outages that
	// only affect, e.g., compliance alerts.
	//
	// Allowed label values (do NOT extend without auditing every Send* caller):
	//   kind=verification    SendVerificationEmail
	//   kind=activation      SendActivationEmail
	//   kind=password_reset  SendPasswordResetEmail
	//   kind=invitation      SendUserInvitationEmail
	//   kind=claim_link      SendClaimLinkEmail
	//   kind=alert           SendAlertEmail
	//   kind=compliance      SendComplianceAlertEmail
	//
	//   result=sent          SMTP transport succeeded
	//   result=relay_error   SMTP transport failed (auth/dial/RCPT/data)
	//   result=mock_logged   mock or air-gapped mode — no SMTP attempted
	EmailDelivery = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_email_delivery_total",
		Help: "Total email delivery attempts by kind and result",
	}, []string{"kind", "result"})

	// EmailDeliveryDuration measures the wall-clock latency of SMTP delivery
	// attempts. Only observed on real SMTP paths (not mock/air-gapped) so the
	// histogram reflects real transport behaviour.
	EmailDeliveryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "identuum_idp_email_delivery_duration_seconds",
		Help:    "Latency of SMTP relay deliveries by kind",
		Buckets: []float64{0.05, 0.1, 0.5, 1, 2, 5, 10},
	}, []string{"kind"})
)
