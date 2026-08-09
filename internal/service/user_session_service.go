// Package service — UserSessionService is the OSS user-session
// foundation: a thin façade in front of repository.SessionRepository
// that exposes the create / rotate / revoke / cleanup primitives the
// future /authorize handler will need WITHOUT pulling in any browser
// UI or authorization-code grant logic.
//
// This file is INTENTIONALLY scoped to the session lifecycle.
// Local-login-with-password and local-login-with-MFA are deferred:
//
//   - Password verification primitives already live in
//     internal/crypto/password.go, but the OSS slice does not yet
//     wire a "user authenticator" that combines password +
//     emailverified + org-active checks. That belongs in the next
//     slice once a stable authenticator seam is designed.
//   - OSS does not yet ship a TOTP / MFA verifier. The brief's
//     safety rule "If OSS lacks a safe password/MFA verifier:
//     do NOT fake it" applies — login is deferred until the MFA
//     primitives land.
//
// What IS in this slice:
//
//   - CreateUserSession (generates selector / validator and
//     persists the row via SessionRepository.Create).
//   - RotateRefreshToken (atomically rotates the selector +
//     validator; reuse / expiry / revocation all fail closed).
//   - RevokeSession + RevokeUserSessions (satisfies the existing
//     service.SessionRevoker seam so /oauth/revoke, RBAC role
//     mutations, and future browser logout can all hook in).
//   - DeleteExpired (the cleanup driver loops over this).
//
// All paths NEVER write the raw refresh token to the DB. The
// caller-visible refresh token is returned EXACTLY ONCE via the
// IssuedUserSession projection.
package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/identuum/identuum-idp-oss/tools"
)

// UserSessionService is the OSS façade in front of the
// repository.SessionRepository. Construction is bound to a single
// repository instance + TTL config; runtime concerns (cleanup
// cadence, audit emission) live in the cleanup driver and the
// future /auth handler respectively.
type UserSessionService struct {
	repo             repository.SessionRepository
	auditSvc         audit.Service
	defaultTTL       time.Duration
	rememberMeTTL    time.Duration
	absoluteLifetime time.Duration
	retentionPeriod  time.Duration
	cleanupBatch     int
	now              func() time.Time
	generateToken    func() (*domain.SecureRefreshToken, error)
}

// WithAudit composes the OSS-safe audit-emission seam. When wired,
// per-org MaxSessionsPerUser eviction during CreateUserSession emits
// a bounded `session_evicted_max_sessions` event per revoked session.
// When nil or absent, audit emission is a no-op and the metric still
// fires.
func (s *UserSessionService) WithAudit(a audit.Service) *UserSessionService {
	s.auditSvc = a
	return s
}

// UserSessionServiceOptions parameterises the service. Zero
// values fall back to OSS-default constants documented inline.
type UserSessionServiceOptions struct {
	// DefaultTTL is the lifetime of a non-remember-me session.
	// Defaults to 12 hours.
	DefaultTTL time.Duration
	// RememberMeTTL is the lifetime of a remember-me session.
	// Defaults to 30 days.
	RememberMeTTL time.Duration
	// AbsoluteLifetime caps how long a single session can be
	// rotation-extended before a fresh login is required. Defaults
	// to 30 days. Set to a negative value to disable (matches the
	// pre-this-slice behaviour for operators on a legacy schema).
	AbsoluteLifetime time.Duration
	// RetentionPeriod is the grace window the cleanup driver
	// passes to DeleteExpiredReturning. Rows revoked before this
	// window are pruned; younger revoked rows are kept for
	// auditing. Defaults to 24 hours.
	RetentionPeriod time.Duration
	// CleanupBatchSize caps how many rows the cleanup pass may
	// delete in a single call. Defaults to 1000.
	CleanupBatchSize int
}

const (
	defaultUserSessionTTL              = 12 * time.Hour
	defaultUserSessionRememberMe       = 30 * 24 * time.Hour
	defaultUserSessionAbsoluteLifetime = 30 * 24 * time.Hour
	defaultUserSessionRetention        = 24 * time.Hour
	defaultUserSessionCleanupBatch     = 1000

	// sessionRotationGraceWindow (P0-12b) bounds how long a just-superseded
	// validator hash (prev_validator_hash) is still accepted as a benign
	// concurrent racer rather than genuine refresh-token reuse. P0-12's CAS
	// guarantees exactly one winner per rotation; a losing sibling that reads
	// AFTER the winner commits sees the new hash and fails the read-time
	// compare against its own now-stale validator. Within this window that
	// read-time failure is treated as a benign double-click/retry (accept,
	// no rotation, no revocation); outside it, the same stale hash is treated
	// as theft (revoke the family), exactly as before this fix.
	//
	// Deliberate security tradeoff, not a bug: a genuinely stolen validator
	// replayed within this window is ALSO accepted as benign and does not
	// trigger the reuse alert for that one request — the schema cannot tell
	// the two apart (see migration 0021). Every production IdP that supports
	// concurrent refresh-token rotation makes this same tradeoff; the window
	// is kept short specifically to bound it. The CAS itself is untouched —
	// a benign racer that presents the CURRENT hash still goes through the
	// normal compare-and-set below, win-or-lose, exactly as under P0-12a.
	sessionRotationGraceWindow = 10 * time.Second
)

// NewUserSessionService constructs the service. repo is required;
// nil panics so a misconfigured deployment cannot silently no-op.
func NewUserSessionService(report *lifecycle.StartupReport, repo repository.SessionRepository, opts UserSessionServiceOptions) *UserSessionService {
	if repo == nil {
		report.Fatal("NewUserSessionService", "service: NewUserSessionService requires a non-nil SessionRepository")
	}
	ttl := opts.DefaultTTL
	if ttl <= 0 {
		ttl = defaultUserSessionTTL
	}
	rememberMe := opts.RememberMeTTL
	if rememberMe <= 0 {
		rememberMe = defaultUserSessionRememberMe
	}
	absolute := opts.AbsoluteLifetime
	if absolute == 0 {
		absolute = defaultUserSessionAbsoluteLifetime
	}
	// Negative AbsoluteLifetime disables the guard (operator opt-out).
	retention := opts.RetentionPeriod
	if retention <= 0 {
		retention = defaultUserSessionRetention
	}
	batch := opts.CleanupBatchSize
	if batch <= 0 {
		batch = defaultUserSessionCleanupBatch
	}
	return &UserSessionService{
		repo:             repo,
		defaultTTL:       ttl,
		rememberMeTTL:    rememberMe,
		absoluteLifetime: absolute,
		retentionPeriod:  retention,
		cleanupBatch:     batch,
		now:              time.Now,
		generateToken:    tools.GenerateSecureRefreshToken,
	}
}

// CreateUserSessionInput drives CreateUserSession. UserID is the
// only required field; every other field is optional and lands in
// the corresponding session column when non-zero.
type CreateUserSessionInput struct {
	UserID     uuid.UUID
	ClientID   *string
	IPAddress  *string
	UserAgent  *string
	RememberMe bool
	Acr        string
	Amr        []string

	// MaxSessionsPerUser is the per-org session cap consulted by the
	// best-effort eviction path landed in slice
	// agent-a-20260714-idp-oss-maxsessions-eviction-enforcement
	// (Decision D-015 §4). Zero or negative ⇒ no cap (preserves
	// pre-slice unlimited behaviour). Callers typically pass
	// `user.OrgMaxSessionsPerUser` dereferenced (or 0 when nil).
	MaxSessionsPerUser int

	// OrganizationID + Role are policy-context labels used ONLY for
	// the bounded metric + audit emission on eviction. They are NOT
	// stored on the session row. uuid.Nil OrganizationID and empty
	// Role degrade gracefully (the metric still increments with the
	// zero-string label).
	OrganizationID uuid.UUID
	Role           string
}

// IssuedUserSession is the one-time projection returned by
// CreateUserSession + RotateRefreshToken. RefreshToken is the
// caller-visible `<selector>.<base64url(validator)>` string and is
// returned EXACTLY ONCE — neither the service nor the repository
// can recover it later.
type IssuedUserSession struct {
	Session      *domain.Session
	RefreshToken string
	ExpiresAt    time.Time
}

// ListActiveUserSessions returns active sessions for one user. The
// repository seam may return rows that are valid-but-expired until
// cleanup runs, so the service applies the same CanBeUsed lifecycle
// check before exposing the list to handlers.
func (s *UserSessionService) ListActiveUserSessions(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	if userID == uuid.Nil {
		return nil, ErrUserSessionInvalidInput
	}
	sessions, err := s.repo.ListActiveByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	out := make([]*domain.Session, 0, len(sessions))
	for _, sess := range sessions {
		if sess == nil {
			continue
		}
		if ok, _ := sess.CanBeUsed(now); !ok {
			continue
		}
		out = append(out, sess)
	}
	return out, nil
}

// Sentinel errors. The wire mapping is the caller's job; the
// service surfaces granular sentinels so the future /auth handler
// can pin failure modes precisely.
var (
	// ErrUserSessionInvalidInput is the programmer-error sentinel
	// returned when UserID is uuid.Nil.
	ErrUserSessionInvalidInput = errors.New("service: user session requires a non-nil user_id")

	// ErrUserSessionGenerationFailed wraps a randomness-source
	// failure during selector/validator generation. The wire
	// layer maps this to 500.
	ErrUserSessionGenerationFailed = errors.New("service: user session token generation failed")

	// ErrUserSessionInvalidGrant is returned when a refresh token
	// is unknown / expired / revoked / malformed. The future
	// /auth/refresh handler maps this to 401.
	ErrUserSessionInvalidGrant = errors.New("service: user session invalid_grant")

	// ErrUserSessionReuse is returned when the supplied refresh
	// token parses BUT the stored validator hash does not match.
	// This is reuse-after-rotation evidence; callers MUST revoke
	// every session for the affected user.
	ErrUserSessionReuse = errors.New("service: user session refresh-token reuse detected")
)

// CreateUserSession generates a new selector/validator pair,
// persists the session row, and returns the one-time refresh
// token. The supplied input must include a non-nil UserID;
// every other field is optional.
func (s *UserSessionService) CreateUserSession(ctx context.Context, in CreateUserSessionInput) (*IssuedUserSession, error) {
	if in.UserID == uuid.Nil {
		return nil, ErrUserSessionInvalidInput
	}

	// Best-effort per-org MaxSessionsPerUser eviction. Runs BEFORE
	// the new-session insert so a cap of 1 ends with exactly one
	// active session for the user. The eviction is NOT serializable —
	// two simultaneous logins for the same user can each see count <
	// cap and both mint, exceeding the cap by one. The monolith ships
	// the same best-effort posture; OSS matches it here. Strict
	// concurrent enforcement is future hardening (see D-015 §4
	// race-posture caveat).
	//
	// Admin-local invariant (Decision D-004): site_admin AND org_admin
	// are EXEMPT from the cap. Admins are control-plane infrastructure
	// and MUST NOT be collapsed under another admin's login. The role
	// short-circuit runs BEFORE the active-session list query so admin
	// sessions are never even counted.
	// P3-4: THE CAP IS APPLIED AFTER THE INSERT, NOT BEFORE.
	//
	// It used to run here, ~28 lines ahead of s.repo.Create. Every path that
	// fails between the two — token generation, hashing, the insert itself —
	// left the user's oldest sessions ALREADY REVOKED for a session that never
	// came into existence. A user whose login failed came back to find they had
	// been logged out elsewhere for nothing.
	//
	// Running it after a SUCCESSFUL create also makes the arithmetic honest:
	// the eviction target is now a count that includes the new row, so the loop
	// trims to exactly the cap instead of predicting what the count will become.
	secure, err := s.generateToken()
	if err != nil {
		return nil, ErrUserSessionGenerationFailed
	}
	now := s.now().UTC()
	ttl := s.defaultTTL
	if in.RememberMe {
		ttl = s.rememberMeTTL
	}
	exp := now.Add(ttl)
	selector := secure.Selector
	validatorHash := hashSessionValidator(secure.Validator)
	session := &domain.Session{
		UserID:             in.UserID,
		ClientID:           in.ClientID,
		IPAddress:          in.IPAddress,
		UserAgent:          in.UserAgent,
		TokenSelector:      &selector,
		TokenValidatorHash: &validatorHash,
		IsValid:            true,
		RememberMe:         in.RememberMe,
		CreatedAt:          now,
		ExpiresAt:          exp,
		Acr:                in.Acr,
		Amr:                in.Amr,
	}
	persisted, err := s.repo.Create(ctx, session)
	if err != nil {
		return nil, err
	}

	// P3-4: trim to the cap now that the session actually exists. The new row
	// is the NEWEST, and the loop evicts oldest-first, so it is never its own
	// victim.
	s.applyMaxSessionsCap(ctx, in)
	return &IssuedUserSession{
		Session:      persisted,
		RefreshToken: secure.Encode(),
		ExpiresAt:    exp,
	}, nil
}

// RotateRefreshToken is the user-session counterpart of
// RefreshTokenService.Consume. It parses the wire refresh token,
// looks the session up by selector, constant-time compares the
// validator hash, enforces the (active + not-expired +
// not-revoked) lifecycle, and rotates: a new selector +
// validator + extended expiry are persisted on the SAME row, and
// the new wire refresh token is returned.
//
// Rotation behavior matches the monolith's SessionService.Rotate
// shape (same session row, new selector/validator pair) — the
// session ID is stable so existing access-token-bound state on
// the row is preserved.
//
// Reuse semantics:
//   - selector found AND validator matches → rotate + return new
//     refresh token.
//   - selector found AND validator does NOT match → REUSE
//     detected. The service revokes EVERY session for the
//     affected user (defense in depth) and returns
//     ErrUserSessionReuse so the caller can audit.
//   - selector not found / malformed / expired / revoked →
//     ErrUserSessionInvalidGrant.
func (s *UserSessionService) RotateRefreshToken(ctx context.Context, rawRefreshToken string) (*IssuedUserSession, error) {
	if strings.TrimSpace(rawRefreshToken) == "" {
		return nil, ErrUserSessionInvalidGrant
	}
	secure, parseErr := domain.ParseSecureRefreshToken(rawRefreshToken)
	if parseErr != nil {
		return nil, ErrUserSessionInvalidGrant
	}
	session, err := s.repo.GetByTokenSelector(ctx, secure.Selector)
	if err != nil || session == nil {
		return nil, ErrUserSessionInvalidGrant
	}
	now := s.now().UTC()
	if !sessionRotatable(session, now) {
		return nil, ErrUserSessionInvalidGrant
	}
	// Absolute-lifetime guard. A session can be rotation-extended
	// indefinitely without this check; the OSS slice enforces a
	// hard cap measured from the session's original CreatedAt.
	// AbsoluteLifetime<0 disables the guard (operator opt-out).
	if s.absoluteLifetime > 0 {
		if !session.CreatedAt.IsZero() && now.Sub(session.CreatedAt) >= s.absoluteLifetime {
			_ = s.repo.Revoke(ctx, session.ID, uuid.Nil, "absolute_lifetime_exceeded")
			return nil, ErrUserSessionInvalidGrant
		}
	}
	// Constant-time validator compare against the CURRENT hash. A match
	// means this is a normal (or CAS-racing) rotation attempt — fall
	// through to the CAS below exactly as before.
	presentedHash := hashSessionValidator(secure.Validator)
	if !constantTimeHashEqualSession(session.TokenValidatorHash, presentedHash) {
		// P0-12b: three-way classification of a current-hash mismatch.
		// P0-12a's CAS guarantees exactly one winner per rotation, but the
		// compare above runs at READ time, before the CAS — a benign
		// sibling that reads AFTER the winner already committed sees the
		// NEW hash and lands here holding what is now the immediate
		// predecessor, not an old stolen ancestor. Without prev_validator_hash
		// the two are indistinguishable; with it, we can tell them apart.
		if constantTimeHashEqualSession(session.PrevValidatorHash, presentedHash) &&
			session.PrevRotatedAt != nil &&
			now.Sub(*session.PrevRotatedAt) < sessionRotationGraceWindow {
			// BENIGN RACER: presented hash is the immediate predecessor,
			// superseded within the grace window — a double-click or
			// retry, not theft. Accept without rotating again or
			// revoking anything: `session` already reflects the CURRENT
			// row (the read that got us here happened after the
			// sibling's commit), so its CURRENT validator/expiry are
			// what the caller should keep using. We do NOT know the
			// sibling's newly-minted plaintext validator (only its own
			// caller received that), so we cannot mint a fresh wire
			// token here — echoing the caller's own just-presented
			// token back is safe: it is already what the caller holds,
			// changes nothing server-side, and a later reuse of this
			// same string is re-classified from scratch (benign again
			// if still within a fresh grace window off a subsequent
			// rotation, genuine reuse once prev_rotated_at ages out).
			wire := domain.SecureRefreshToken{Selector: secure.Selector, Validator: secure.Validator}
			return &IssuedUserSession{
				Session:      session,
				RefreshToken: wire.Encode(),
				ExpiresAt:    session.ExpiresAt,
			}, nil
		}
		// GENUINE REUSE: the presented hash is neither the current hash
		// nor a just-superseded predecessor within grace — an unknown
		// hash, or a predecessor stale enough that grace has elapsed.
		// Classic refresh-token rotation reuse (OAuth 2.1 / RFC 9700
		// §4.13.2). Revoke the ENTIRE session family for this user AND
		// emit the breach signal (ERROR log + token_reuse metric) so the
		// operator is alerted.
		_ = s.repo.RevokeByUserID(ctx, session.UserID, "security_breach_token_reuse")
		logger.ErrorContext(ctx, "SECURITY ALERT: refresh-token reuse detected on session rotation — revoking session family",
			zap.Stringer("user_id", session.UserID),
			zap.Stringer("session_id", session.ID),
		)
		// Metric label rule: NEVER a user UUID (or any unbounded,
		// attacker-drivable value) as a label — an attacker replaying
		// tokens would mint one Prometheus series per victim user
		// (cardinality DoS on a security metric). domain.Session does not
		// carry the organization, so org_id is emitted as the bounded
		// empty value; per-user attribution lives in the ERROR log above.
		metrics.AuthPolicyViolation.WithLabelValues("token_reuse", "").Inc()
		return nil, ErrUserSessionReuse
	}

	// Rotation-time user/org revalidation (R1-secondary, defense in
	// depth). Reuses the existing combined status lookup: if the user was
	// banned/deleted or the org deactivated AFTER login, refuse the
	// rotation and revoke the now-illegitimate session. A lookup error
	// leaves rotation to proceed (the lifecycle cascade is the primary
	// enforcement — revoked sessions are already non-rotatable); a
	// definitive inactive status fails closed.
	if info, statusErr := s.repo.GetSessionWithUserAndOrgStatus(ctx, session.ID); statusErr == nil && info != nil {
		if info.UserDeleted || !info.UserActive || info.OrgDeleted || !info.OrgActive {
			_ = s.repo.Revoke(ctx, session.ID, uuid.Nil, "user_or_org_inactive")
			return nil, ErrUserSessionInvalidGrant
		}
	}

	// Generate the successor VALIDATOR. The SELECTOR is kept STABLE across
	// rotations (NOT rotated) so a replayed pre-rotation token — same
	// selector, stale validator — resolves to this session and is caught
	// by the validator-mismatch reuse branch above on its next use (RFC
	// 9700 §4.13.2). The wire token returned pairs the stable selector
	// with the fresh validator.
	newSecure, genErr := s.generateToken()
	if genErr != nil {
		return nil, ErrUserSessionGenerationFailed
	}
	newValidatorHash := hashSessionValidator(newSecure.Validator)
	// Extend the session expiry on every rotation so an actively-used session
	// does not idle out. Persisted by the CAS below in the SAME statement (P0-12b
	// — the prior Update omitted expires_at, so the extension was never written).
	ttl := s.defaultTTL
	if session.RememberMe {
		ttl = s.rememberMeTTL
	}
	newExpiresAt := now.Add(ttl)

	// P0-12a: rotate via a COMPARE-AND-SET guarded on the validator hash we just
	// validated, persisting expires_at in the SAME statement. If a concurrent
	// sibling rotated first, it advanced the hash and our WHERE matches ZERO rows
	// — we LOSE the CAS.
	//
	// CAS-loser policy: a CAS loss is BENIGN concurrency (a double-click / retry
	// presented the then-current validator at the same instant), NOT reuse — and
	// it is provably distinct from genuine reuse. A stale/old token fails the
	// READ-TIME validator compare above (→ ErrUserSessionReuse + family
	// revocation); a CAS loser PASSED that compare and only lost the write race.
	// So we reject the loser with ErrUserSessionInvalidGrant and do NOT revoke
	// the family — the legitimate user stays logged in via the winner's fresh
	// token. (Reuse of a consumed predecessor is still caught on its next use.)
	rotated, won, rotErr := s.repo.RotateToken(ctx, session.ID, *session.TokenValidatorHash, newValidatorHash, newExpiresAt, now)
	if rotErr != nil {
		return nil, rotErr
	}
	if !won || rotated == nil {
		return nil, ErrUserSessionInvalidGrant
	}
	wire := domain.SecureRefreshToken{Selector: *rotated.TokenSelector, Validator: newSecure.Validator}
	return &IssuedUserSession{
		Session:      rotated,
		RefreshToken: wire.Encode(),
		ExpiresAt:    rotated.ExpiresAt,
	}, nil
}

// RevokeSession marks a single session revoked. Idempotent.
func (s *UserSessionService) RevokeSession(ctx context.Context, sessionID uuid.UUID, reason string) error {
	if sessionID == uuid.Nil {
		return ErrUserSessionInvalidInput
	}
	if reason == "" {
		reason = "session_revoked"
	}
	// The repository's Revoke needs an orgID for tenant scoping;
	// the OSS path passes uuid.Nil to mean "any org" so a single
	// session ID is sufficient at the service layer.
	return s.repo.Revoke(ctx, sessionID, uuid.Nil, reason)
}

// RevokeUserSessions satisfies the existing service.SessionRevoker
// seam so /oauth/revoke, RBAC role mutations, and future browser
// logout flows can call this service uniformly. The metadata map
// is intentionally ignored at this layer (the wire callers
// already filter it through their own audit allowlist) but the
// signature matches the interface for plug-and-play composition.
func (s *UserSessionService) RevokeUserSessions(ctx context.Context, userID uuid.UUID, reason string, _ map[string]any) error {
	if userID == uuid.Nil {
		return ErrUserSessionInvalidInput
	}
	if reason == "" {
		reason = "user_sessions_revoked"
	}
	return s.repo.RevokeByUserID(ctx, userID, reason)
}

// DeleteExpired prunes expired sessions older than the configured
// retention window. The cleanup driver loops over this on the
// configured interval. Returns the deleted-row count for
// observability.
func (s *UserSessionService) DeleteExpired(ctx context.Context) (int64, error) {
	deleted, err := s.repo.DeleteExpiredReturning(ctx, s.retentionPeriod, s.cleanupBatch)
	if err != nil {
		return 0, err
	}
	return int64(len(deleted)), nil
}

// Compile-time check that the service satisfies the existing
// SessionRevoker seam.
var _ SessionRevoker = (*UserSessionService)(nil)

// sessionRotatable folds the (IsValid && not-revoked &&
// not-expired) lifecycle into a single boolean so the rotate
// path stays linear.
func sessionRotatable(s *domain.Session, now time.Time) bool {
	if s == nil {
		return false
	}
	if !s.IsValid {
		return false
	}
	if s.RevokedAt != nil {
		return false
	}
	if !s.ExpiresAt.After(now) {
		return false
	}
	return true
}

// hashSessionValidator returns the SHA-256 hex digest of the
// validator bytes. Same hash family the OSS audit, password, and
// other refresh-token stores already use, so operators do not
// need to reason about multiple hash families on the same DB.
func hashSessionValidator(validator []byte) string {
	sum := sha256.Sum256(validator)
	return hex.EncodeToString(sum[:])
}

// constantTimeHashEqualSession constant-time-compares a stored
// validator hash pointer against a freshly computed digest. Nil
// stored hash is treated as "no match" without leaking timing.
func constantTimeHashEqualSession(stored *string, fresh string) bool {
	if stored == nil {
		return false
	}
	if len(*stored) != len(fresh) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(*stored), []byte(fresh)) == 1
}

// maxSessionsEvictReason is the canonical revoke-reason string the
// best-effort eviction loop writes onto the `sessions.revoked_reason`
// column. Matches the documented label in
// metrics.SessionOperations's reason enum (cap_exceeded) AND the
// monolith's prior art at internal/service/session_eviction.go in
// identuum-idp.
const maxSessionsEvictReason = "max_sessions_exceeded"

// applyMaxSessionsCap is the best-effort per-org eviction loop wired
// into CreateUserSession by slice
// agent-a-20260714-idp-oss-maxsessions-eviction-enforcement
// (Decision D-015 §4).
//
// Contract:
//   - Admin role short-circuit (site_admin OR org_admin) → no-op.
//     The locked admin-local invariant (Decision D-004) MUST NOT be
//     weakened by any session-cap enforcement.
//   - Zero or negative MaxSessionsPerUser → no-op (preserves
//     pre-slice unlimited behaviour for callers that don't plumb the
//     policy).
//   - List active sessions, sort by CreatedAt ASCENDING (oldest
//     first), revoke (count - cap + 1) oldest sessions with reason
//     "max_sessions_exceeded". The +1 accounts for the new session
//     that's about to be inserted by the caller — landing at exactly
//     `cap` active sessions post-insert.
//   - Each successful revoke emits one metric increment + (if audit
//     wired) one bounded audit event. Failed revokes are swallowed
//     (best-effort) and DO NOT block the new-session-create call.
//
// Bounded audit payload: subject = user, organization_id = org id
// from input, metadata = {reason, evicted_session_id, cap}. NO
// password / token / cookie / DB URL / raw session validator / IP /
// UA values are included even when present on the revoked session.
func (s *UserSessionService) applyMaxSessionsCap(ctx context.Context, in CreateUserSessionInput) {
	if in.MaxSessionsPerUser <= 0 {
		return
	}
	if isAdminRole(in.Role) {
		return
	}
	active, err := s.repo.ListActiveByUserID(ctx, in.UserID)
	if err != nil {
		// Best-effort: a list-failure must not block the new-session
		// create. The cap was best-effort to begin with.
		return
	}
	if len(active) <= in.MaxSessionsPerUser {
		return
	}
	// Sort by CreatedAt ascending so the oldest sessions are evicted
	// first. nil entries are filtered out defensively.
	sessions := make([]*domain.Session, 0, len(active))
	for _, sess := range active {
		if sess == nil {
			continue
		}
		sessions = append(sessions, sess)
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].CreatedAt.Before(sessions[j].CreatedAt)
	})
	// P3-4: the new session is ALREADY in this list, because the cap now runs
	// after the insert. So the target is a plain trim-to-cap; the `+ 1` that
	// used to predict the not-yet-inserted row would now evict one session too
	// many on every login.
	toEvict := len(sessions) - in.MaxSessionsPerUser
	if toEvict <= 0 {
		return
	}
	for i := 0; i < toEvict && i < len(sessions); i++ {
		sess := sessions[i]
		if revokeErr := s.repo.Revoke(ctx, sess.ID, uuid.Nil, maxSessionsEvictReason); revokeErr != nil {
			continue
		}
		metrics.SessionOperations.WithLabelValues("evicted", "cap_exceeded").Inc()
		s.recordSessionEvictedAudit(ctx, in, sess)
	}
}

// isAdminRole reports whether the supplied role string is one of the
// admin roles exempt from per-org session caps (site_admin or
// org_admin). Case-insensitive comparison so a future role-string
// normalization slice does not silently break the invariant.
func isAdminRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case string(domain.RoleSiteAdmin), string(domain.RoleOrgAdmin):
		return true
	}
	return false
}

// recordSessionEvictedAudit emits the bounded audit event for one
// evicted session. Best-effort: errors are swallowed.
//
// Sensitive-data invariant: the payload includes ONLY the actor +
// subject = user ID, the organization ID, the user's role label, and
// the evicted-session metadata (reason + session_id + cap). NO
// password / TOTP / raw session validator / refresh token / cookie /
// DB URL / hashed credential material appears.
func (s *UserSessionService) recordSessionEvictedAudit(ctx context.Context, in CreateUserSessionInput, evicted *domain.Session) {
	if s.auditSvc == nil {
		return
	}
	if evicted == nil {
		return
	}
	_ = s.auditSvc.Record(ctx, audit.Event{
		Action:         string(domain.AuditSessionEvictedMaxSessions),
		Outcome:        "success",
		ActorID:        in.UserID,
		ActorType:      "user",
		ActorRole:      in.Role,
		SubjectID:      in.UserID,
		SubjectType:    "user",
		OrganizationID: in.OrganizationID,
		Metadata: map[string]any{
			"reason":                maxSessionsEvictReason,
			"evicted_session_id":    evicted.ID.String(),
			"max_sessions_per_user": in.MaxSessionsPerUser,
		},
	})
}
