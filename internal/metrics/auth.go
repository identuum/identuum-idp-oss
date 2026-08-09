package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AuthLoginAttempts tracks login traffic and status
	AuthLoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_login_attempts_total",
		Help: "The total number of login attempts by status and method",
	}, []string{"status", "method"})

	// AuthActiveSessions tracks the approximate number of active sessions
	AuthActiveSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "identuum_idp_active_sessions",
		Help: "The current number of active sessions",
	})

	// AuthTokenIssuance tracks token generation
	AuthTokenIssuance = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_token_issuance_total",
		Help: "The total number of tokens issued by type",
	}, []string{"token_type"})

	// AuthTokenRevocation tracks token revocation (logouts)
	AuthTokenRevocation = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_token_revocation_total",
		Help: "The total number of tokens revoked by reason",
	}, []string{"reason"})

	// AuthMFAChallenges tracks MFA flows
	AuthMFAChallenges = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_mfa_challenges_total",
		Help: "The total number of MFA challenges by status",
	}, []string{"status"})

	// AuthTokenIssuanceDetailed tracks granular token generation
	AuthTokenIssuanceDetailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_token_issuance_detailed_total",
		Help: "The total number of tokens issued by grant type and token type",
	}, []string{"grant_type", "token_type"})

	// AuthPolicyViolation tracks security policy blocks
	AuthPolicyViolation = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_policy_violation_total",
		Help: "Total number of security policy violations",
	}, []string{"policy", "org_id"})

	// AuthRiskBackendUnavailable counts how often the login-risk /
	// brute-force lockout backend (login_attempts store) was
	// unreachable at Check time, forcing the fail-CLOSED path (the
	// login is refused with a 503 rather than proceeding unguarded).
	// A non-zero rate means the brute-force lockout is degraded and the
	// store needs attention. Labelled by purpose (password | mfa).
	AuthRiskBackendUnavailable = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_login_risk_backend_unavailable_total",
		Help: "Total number of login-risk lockout checks that failed closed because the risk backend was unavailable",
	}, []string{"purpose"})

	// PasswordHashingDuration tracks the latency of argon2id hashing.
	PasswordHashingDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "identuum_idp_password_hashing_duration_seconds",
		Help:    "Histogram of password hashing latency",
		Buckets: []float64{0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.75, 1.0, 2.0},
	}, []string{"type"})

	// SessionOperations tracks session lifecycle events at a unified per-operation
	// granularity that the existing AuthTokenIssuance / AuthTokenRevocation
	// counters do not provide. The reason label is bounded — reject any future
	// PR that adds a value not in the documented enum below.
	//
	// Allowed label values:
	//   operation=created    new session row written to the DB
	//   operation=revoked    existing session row marked revoked
	//   operation=expired    session expired naturally (rare — most expiries are swept by cleaner)
	//   operation=cleaned    cleanup sweep deleted an expired session row
	//   operation=evicted    session forcibly closed to make room under max_sessions cap
	//
	//   reason=user_login        login flow created a fresh session
	//   reason=user_logout       user-initiated logout / RFC 7009 revoke
	//   reason=admin_action      admin called RevokeSession or RevokeUserSessions on another user
	//   reason=cap_exceeded      max-sessions-per-user cap forced an eviction
	//   reason=expiry            cleanup sweep deleted because expires_at < now
	//   reason=user_deleted      user deletion cascade
	//   reason=gateway_kill      gateway-session kill-switch cascade
	//   reason=token_reuse       token-reuse breach revoked all user sessions
	//   reason=automatic         automated/system action with no specific reason
	SessionOperations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_session_operations_total",
		Help: "Total session lifecycle operations by operation and reason",
	}, []string{"operation", "reason"})

	// RefreshTokenRotation tracks refresh-token rotation outcomes from
	// SessionService.rotateRefreshTokenPgx. The reuse_detected branch is the
	// load-bearing kill-switch on the selector/validator session model — until
	// this counter existed, SOC dashboards had no view of "successful rotation
	// rate" vs. "reuse detection rate".
	//
	// Allowed label values:
	//   result=success         token rotated successfully
	//   result=reuse_detected  token reuse detected — all user sessions revoked
	//   result=error           rotation failed for any other reason (DB / validator mismatch / etc.)
	RefreshTokenRotation = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identuum_idp_refresh_token_rotation_total",
		Help: "Total refresh token rotation events by result",
	}, []string{"result"})
)
