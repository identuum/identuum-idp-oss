// Package service — LoginRiskService is the OSS rate-limit /
// lockout helper. It does TWO things:
//
//  1. records each credential-exchange attempt as a row in
//     `login_attempts`, hashing email + IP before storage so the
//     table contains no raw PII.
//
//  2. answers "is this caller currently locked out?" via TWO
//     INDEPENDENT sliding-window counters (P2-10):
//
//     - the ACCOUNT counter: failures for the SAME (email_hash,
//     ip_hash) PAIR (AND, not OR) — trips at `threshold` (5). This
//     bounds one host hammering one account.
//     - the IP counter: COUNT(DISTINCT email_hash) of failures from
//     one ip_hash — trips at `ipThreshold` (10). This bounds a
//     credential-stuffing run spraying many accounts from one host.
//
//     Splitting the prior single `(email_hash OR ip_hash)` counter kills
//     two abuses it enabled: keying the lockout on email ALONE let 5
//     wrong-password tries from ANY IP lock any known account
//     (unauthenticated account-DoS, V1); counting RAW failures per IP let
//     5 failures behind one NAT deny every later user on that shared IP
//     (V2). (email AND ip) kills V1; COUNT(DISTINCT email) kills V2.
//
// The wire layer (LocalLoginService, the browser-login handler)
// calls Check BEFORE the password verification step. A locked-out
// caller (EITHER counter) gets the same generic
// ErrLoginInvalidCredentials wire response the existing "wrong password"
// path returns, so the caller cannot distinguish "wrong password" from
// "locked out" — matches the project's no-enumeration posture.
//
// Default policy:
//
//   - Window: 15 minutes (shared by both counters).
//   - Threshold: 5 failed attempts (account counter).
//   - IPThreshold: 10 distinct accounts (IP counter).
//   - Purpose taxonomy: "password" (the primary login step) and
//     "mfa" (the TOTP step). Each purpose has its own independent
//     counters.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// LoginRiskPurpose enumerates the credential surfaces the risk
// service guards.
type LoginRiskPurpose string

const (
	LoginRiskPurposePassword LoginRiskPurpose = "password"
	LoginRiskPurposeMFA      LoginRiskPurpose = "mfa"
)

// LoginRiskServiceOptions parameterises the service.
type LoginRiskServiceOptions struct {
	// Window is the shared sliding window for BOTH counters. Default 15m.
	Window time.Duration
	// Threshold is the ACCOUNT counter cap — failures for the same
	// (email, ip) pair. Default 5.
	Threshold int
	// IPThreshold is the IP counter cap — DISTINCT accounts sprayed from
	// one IP within the window. Default 10 (mirrors the Threshold default
	// of 5, but higher because a single shared IP legitimately serves
	// several failing users). <=0 → default.
	IPThreshold int
	// Logger receives the operator-visible ERROR emitted on the
	// fail-CLOSED path when the risk backend is unavailable. Defaults
	// to zap.NewNop() when nil, matching the sibling services'
	// (email_verification_service, claim_service) logger convention.
	Logger *zap.Logger
}

// LoginRiskService is the rate-limit/lockout helper.
type LoginRiskService struct {
	repo        repository.LoginAttemptRepository
	window      time.Duration
	threshold   int
	ipThreshold int
	now         func() time.Time
	logger      *zap.Logger
}

// NewLoginRiskService constructs the service.
func NewLoginRiskService(report *lifecycle.StartupReport, repo repository.LoginAttemptRepository, opts LoginRiskServiceOptions) *LoginRiskService {
	if repo == nil {
		report.Fatal("NewLoginRiskService", "service: NewLoginRiskService requires a non-nil LoginAttemptRepository")
	}
	w := opts.Window
	if w <= 0 {
		w = 15 * time.Minute
	}
	t := opts.Threshold
	if t <= 0 {
		t = 5
	}
	ipT := opts.IPThreshold
	if ipT <= 0 {
		ipT = 10
	}
	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &LoginRiskService{repo: repo, window: w, threshold: t, ipThreshold: ipT, now: time.Now, logger: logger}
}

// Sentinels.
//
//   - ErrLoginRateLimited: the caller is GENUINELY locked out (failure
//     count met/exceeded the threshold). The handler collapses this to
//     the generic invalid-credentials response so a locked account is
//     not enumerable.
//   - ErrLoginRiskBackendUnavailable: the risk backend (login_attempts
//     store) could not be consulted, so the brute-force bound cannot be
//     enforced. Check FAILS CLOSED and returns this DISTINCT sentinel;
//     the handler maps it to HTTP 503. This reveals only DB state, never
//     account state — the check runs before (and independently of) any
//     account lookup on the password gate.
var (
	ErrLoginRateLimited            = errors.New("service: login rate-limited")
	ErrLoginRiskBackendUnavailable = errors.New("service: login risk backend unavailable")
)

// Check enforces the TWO INDEPENDENT counters (P2-10):
//
//  1. ACCOUNT counter — failures for the same (email, ip) PAIR. At
//     >= threshold → ErrLoginRateLimited. (email AND ip) means an
//     attacker rotating IPs can never build a per-account lockout, so it
//     is no longer an unauthenticated account-DoS (V1).
//  2. IP counter — COUNT(DISTINCT email) of failures from this ip. Only
//     consulted when ipHash != "". At >= ipThreshold → ErrLoginRateLimited.
//     Counting DISTINCT accounts (not raw failures) means benign
//     co-tenants behind a NAT never trip it; only a stuffing run spraying
//     many accounts does (V2).
//
// nil when under BOTH thresholds. ErrLoginRiskBackendUnavailable when the
// backend errors on EITHER call.
//
// FAIL CLOSED on a backend error (P1-4): stressing the store MUST NOT
// disable the lockout and turn brute force unbounded. This mirrors the MFA
// brute-force counter, which also refuses rather than letting an uncounted
// guess through.
//
// The handler MUST translate ErrLoginRateLimited to the same wire shape as
// ErrLoginInvalidCredentials (so BOTH locks are indistinguishable from
// "wrong password"), and ErrLoginRiskBackendUnavailable to a 503.
func (s *LoginRiskService) Check(ctx context.Context, email, ip string, purpose LoginRiskPurpose) error {
	emailHash := hashLoginID(email)
	ipHash := hashLoginID(ip)
	since := s.now().UTC().Add(-s.window)

	// Account counter: the (email AND ip) pair. Self-consistent even when
	// ipHash == "" — it then matches only other no-IP rows for this email.
	n, err := s.repo.CountAccountFailuresSince(ctx, emailHash, ipHash, string(purpose), since)
	if err != nil {
		return s.failClosed(purpose, err)
	}
	if n >= s.threshold {
		return ErrLoginRateLimited
	}

	// IP counter: DISTINCT accounts sprayed from this IP. Skipped when
	// ipHash == "" — post-P2-2 the IP is server-derived, so "" is a
	// degenerate bucket and a COUNT(DISTINCT email) across it would
	// conflate unrelated no-IP rows into one meaningless keyspace.
	if ipHash != "" {
		d, dErr := s.repo.CountDistinctAccountsFromIPSince(ctx, ipHash, string(purpose), since)
		if dErr != nil {
			return s.failClosed(purpose, dErr)
		}
		if d >= s.ipThreshold {
			return ErrLoginRateLimited
		}
	}

	return nil
}

// failClosed emits exactly one operator-visible ERROR + one metric
// increment for a risk-backend failure and returns the distinct 503
// sentinel. No account-derived detail is logged (only the purpose label),
// so the signal reveals backend state, never account state (P1-4).
func (s *LoginRiskService) failClosed(purpose LoginRiskPurpose, err error) error {
	metrics.AuthRiskBackendUnavailable.WithLabelValues(string(purpose)).Inc()
	s.logger.Error("login_risk: backend unavailable; failing closed (login refused with 503)",
		zap.String("purpose", string(purpose)),
		zap.Error(err),
	)
	return ErrLoginRiskBackendUnavailable
}

// Record persists a single attempt row. Errors are returned to the
// caller; the handler may choose to swallow them (the wire path
// should not fail an otherwise-successful login because the audit
// row failed to persist).
func (s *LoginRiskService) Record(ctx context.Context, email, ip string, purpose LoginRiskPurpose, success bool) error {
	id, err := uuidgen.NewV7()
	if err != nil {
		return err
	}
	row := &domain.LoginAttempt{
		ID:        id,
		EmailHash: hashLoginID(email),
		IPHash:    hashLoginID(ip),
		Purpose:   string(purpose),
		Success:   success,
		CreatedAt: s.now().UTC(),
	}
	return s.repo.Insert(ctx, row)
}

// DeleteExpired prunes rows older than `now - window*2`. The
// double-window retention keeps a short history beyond the active
// lockout window for operator inspection.
func (s *LoginRiskService) DeleteExpired(ctx context.Context) (int64, error) {
	cutoff := s.now().UTC().Add(-2 * s.window)
	return s.repo.DeleteOlderThan(ctx, cutoff)
}

// hashLoginID computes the SHA-256 hex digest of the supplied
// identifier after lowercasing + trimming whitespace. Empty input
// returns the empty string so an absent identifier (e.g. an IP we
// could not resolve) does not collide with another absent value.
func hashLoginID(in string) string {
	s := strings.TrimSpace(strings.ToLower(in))
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// keep alive — uuid import balance.
var _ = uuid.Nil
