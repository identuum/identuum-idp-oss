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
// calls Check BEFORE the password verification step. A caller held by
// EITHER counter gets 429 login_throttled with the wait (FUNC-M2), the
// answer the account-wide slow-down gives: a correct password is never told
// it is wrong. Failures are recorded for unknown addresses alike, so the
// answer says nothing about whether an account exists.
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
	// AccountThreshold is where the account-wide slow-down starts: password
	// failures for one account from ANY address since its last success.
	// Default 5 (owner ruling, v0.9.5). <=0 → default.
	AccountThreshold int
	// Logger receives the operator-visible ERROR emitted on the
	// fail-CLOSED path when the risk backend is unavailable. Defaults
	// to zap.NewNop() when nil, matching the sibling services'
	// (email_verification_service, claim_service) logger convention.
	Logger *zap.Logger
}

// LoginRiskService is the rate-limit/lockout helper.
type LoginRiskService struct {
	repo             repository.LoginAttemptRepository
	window           time.Duration
	threshold        int
	ipThreshold      int
	accountThreshold int
	now              func() time.Time
	logger           *zap.Logger
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
	accT := opts.AccountThreshold
	if accT <= 0 {
		accT = 5
	}
	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &LoginRiskService{repo: repo, window: w, threshold: t, ipThreshold: ipT, accountThreshold: accT, now: time.Now, logger: logger}
}

// maxAccountSlowDown caps the account-wide wait (owner ruling, v0.9.5): a
// victim of spread-out guessing waits at most this long between attempts.
const maxAccountSlowDown = time.Minute

// accountSlowDown is the wait after n failures at a threshold of t:
// 1 s at n == t, doubling per further failure, capped at a minute.
func accountSlowDown(n, t int) time.Duration {
	if n < t {
		return 0
	}
	steps := n - t
	if steps >= 6 { // 2^6 s already exceeds the cap
		return maxAccountSlowDown
	}
	return min(time.Duration(1<<steps)*time.Second, maxAccountSlowDown)
}

// LoginThrottledError is ErrLoginThrottled with the wait that remains.
// Bounded is set when a failure bound holds (the address-and-account pair or
// the address's spray) rather than the account-wide slow-down.
type LoginThrottledError struct {
	RetryAfter time.Duration
	Bounded    bool
}

func (e *LoginThrottledError) Error() string { return ErrLoginThrottled.Error() }

// Is makes errors.Is(err, ErrLoginThrottled) true, and errors.Is(err,
// ErrLoginRateLimited) true for a bound that holds.
func (e *LoginThrottledError) Is(target error) bool {
	return target == ErrLoginThrottled || (e.Bounded && target == ErrLoginRateLimited)
}

// boundHeld is the answer while a failure bound holds (FUNC-M2): the same
// 429 login_throttled the slow-down gives, with the wait until the oldest
// counted failure leaves the window — when the pair bound lifts; the spray
// bound may need another wait. At least a second, so Retry-After is never 0.
func (s *LoginRiskService) boundHeld(oldest time.Time) error {
	wait := oldest.Add(s.window).Sub(s.now().UTC())
	return &LoginThrottledError{RetryAfter: max(wait, time.Second), Bounded: true}
}

// Sentinels.
//
//   - ErrLoginRateLimited: a failure bound holds (count met/exceeded the
//     threshold). Check returns it as a *LoginThrottledError (Bounded), so
//     it is also ErrLoginThrottled and answers 429 with the wait (FUNC-M2).
//   - ErrLoginRiskBackendUnavailable: the risk backend (login_attempts
//     store) could not be consulted, so the brute-force bound cannot be
//     enforced. Check FAILS CLOSED and returns this DISTINCT sentinel;
//     the handler maps it to HTTP 503. This reveals only DB state, never
//     account state — the check runs before (and independently of) any
//     account lookup on the password gate.
//   - ErrLoginThrottled: the account-wide slow-down (owner ruling, v0.9.5):
//     the account has failed often enough, from any address, that the next
//     attempt must wait; the error is a *LoginThrottledError carrying the
//     wait. It says nothing about whether the account exists — a failure for
//     an unknown address is recorded the same way — and the handler maps it
//     to 429 with Retry-After.
var (
	ErrLoginRateLimited            = errors.New("service: login rate-limited")
	ErrLoginRiskBackendUnavailable = errors.New("service: login risk backend unavailable")
	ErrLoginThrottled              = errors.New("service: login throttled; try again later")
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
// A bound that holds is a *LoginThrottledError (429 with Retry-After);
// ErrLoginRiskBackendUnavailable maps to a 503.
func (s *LoginRiskService) Check(ctx context.Context, email, ip string, purpose LoginRiskPurpose) error {
	emailHash := hashLoginID(email)
	// D-020: an IPv6 client counts by its /64; IPv4 keys are the address.
	ipHash := hashLoginID(domain.ClientIPKey(ip))
	since := s.now().UTC().Add(-s.window)

	// Account counter: the (email AND ip) pair. Self-consistent even when
	// ipHash == "" — it then matches only other no-IP rows for this email.
	n, oldest, err := s.repo.CountAccountFailuresSince(ctx, emailHash, ipHash, string(purpose), since)
	if err != nil {
		return s.failClosed(purpose, err)
	}
	if n >= s.threshold {
		return s.boundHeld(oldest)
	}

	// IP counter: DISTINCT accounts sprayed from this IP. Skipped when
	// ipHash == "" — post-P2-2 the IP is server-derived, so "" is a
	// degenerate bucket and a COUNT(DISTINCT email) across it would
	// conflate unrelated no-IP rows into one meaningless keyspace.
	if ipHash != "" {
		d, oldestFromIP, dErr := s.repo.CountDistinctAccountsFromIPSince(ctx, ipHash, string(purpose), since)
		if dErr != nil {
			return s.failClosed(purpose, dErr)
		}
		if d >= s.ipThreshold {
			return s.boundHeld(oldestFromIP)
		}
	}

	// Account-wide slow-down (owner ruling, v0.9.5), password sign-in only:
	// failures for this account from ANY address since its last success. It
	// delays the next attempt and never locks; the MFA step keeps its own
	// per-user bounds.
	if purpose == LoginRiskPurposePassword && emailHash != "" {
		n, last, aErr := s.repo.AccountFailuresAnyIPSince(ctx, emailHash, string(purpose), since)
		if aErr != nil {
			return s.failClosed(purpose, aErr)
		}
		if wait := accountSlowDown(n, s.accountThreshold); wait > 0 {
			if remaining := last.Add(wait).Sub(s.now().UTC()); remaining > 0 {
				return &LoginThrottledError{RetryAfter: remaining}
			}
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
		IPHash:    hashLoginID(domain.ClientIPKey(ip)),
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
