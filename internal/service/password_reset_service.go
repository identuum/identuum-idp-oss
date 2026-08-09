// password_reset_service.go — OSS port of the monolith password
// reset flow.
//
// Source-of-truth reference for behaviour:
//   identuum-idp/internal/service/password_service.go
//   identuum-idp/internal/handlers/handler_password_reset.go
//
// We do NOT import monolith code; the port reimplements the
// observable contract on top of OSS repository, audit, and
// notification seams.
//
// Wire contract (mirrors monolith for UI compatibility — see
// identuum-ui/src/app/forgot-password/actions.ts and
// identuum-ui/src/app/reset-password/actions.ts):
//
//   POST /api/v1/auth/password/reset-request
//       request:  { email }
//       response: always 200 { success: true, message: "..." }
//                 (oracle-hardened — unknown email → same body)
//
//   POST /api/v1/auth/password/reset
//       request:  { token, new_password }
//       response: 200 { success: true, message: "..." } on accept
//                 400 { error: "invalid_reset_token" }            on bad token
//                 400 { error: "weak_password" }                  on policy reject
//                 500 { error: "internal_error" }                 on unexpected
//
// Token model (matches the monolith's password_resets table):
//
//   - Generated via crypto/rand → 32 raw bytes → 64-hex-char string
//     (crypto.GenerateRandomString(32) — same primitive the DCR IAT
//     flow uses for its initial-access tokens).
//   - SHA-256(raw_token) is the only thing persisted (column
//     password_resets.token_hash). The raw token is NEVER logged,
//     audited, or stored.
//   - TTL: 1 hour (matches the monolith).
//   - Single-use: MarkAsUsed flips used_at on consume BEFORE the
//     password is rewritten (burn-before-write). A subsequent attempt
//     with the same raw token finds used_at != nil and is rejected
//     via IsValid.
//   - On a successful reset, every active session for the user is
//     revoked via SessionRepository.RevokeByUserID("password_reset")
//     so a compromised cookie cannot survive a recovery.
//
// Anti-enumeration:
//
//   - RequestPasswordReset always returns nil (no error) to the caller.
//     The handler always emits a 200 response with a generic message,
//     regardless of whether the email matches a user.
//   - The handler also injects a 100–300 ms random delay before
//     returning (matches the monolith's timing-leak hardening).
//   - Audit emission is per-user: zero events when no user matches,
//     one event per matching user when at least one matches.

package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// DefaultPasswordResetTTL is the wall-clock lifetime of a single-use
// password-reset token. Matches the monolith (1 hour).
const DefaultPasswordResetTTL = time.Hour

// ErrPasswordResetInvalidToken is the opaque sentinel returned when the
// supplied token is unknown, expired, already used, or its user row no
// longer exists. The HTTP layer maps it to 400 invalid_reset_token; the
// wire response is deliberately uniform across the failure modes so
// no token-state oracle is exposed.
var ErrPasswordResetInvalidToken = errors.New("password reset: invalid token")

// ErrPasswordResetWeakPassword is the sentinel returned when the new
// password fails policy validation (length / complexity / banned chars).
// The HTTP layer maps it to 400 weak_password.
var ErrPasswordResetWeakPassword = errors.New("password reset: weak password")

// ErrPasswordResetRevocationFailed is returned when the password WAS changed
// (the atomic claim+write committed) but the follow-on revocation of the user's
// existing sessions and/or OAuth refresh tokens failed. It is surfaced — never
// swallowed — so the flow does not report plain success while pre-existing
// credentials may survive (P0-9). Handlers map it to a 500-class response.
var ErrPasswordResetRevocationFailed = errors.New("password reset: credential revocation failed")

// passwordResetSessionRevoker is the narrow seam used to invalidate
// active sessions on a successful reset. Satisfied by
// repository.SessionRepository (which has RevokeByUserID) and by an
// optional UserSessionService wrapper.
type passwordResetSessionRevoker interface {
	RevokeByUserID(ctx context.Context, userID uuid.UUID, reason string) error
}

// passwordResetRefreshTokenRevoker is the narrow seam used to
// invalidate OAuth refresh tokens for a single user on a successful
// reset. Satisfied by *RefreshTokenService.RevokeAllForUser. When
// nil, the password reset flow runs session-only (its pre-this-slice
// behaviour) — the constructor remains source-compatible.
type passwordResetRefreshTokenRevoker interface {
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int64, error)
}

// passwordResetUserSurface is the narrow user-repo seam this service
// needs. PgxUserRepository satisfies it via FindUsersByEmail /
// GetByIDWithOrg / Update. GetByIDWithOrg is REQUIRED (not GetByID)
// so the per-org PasswordComplexityEnabled projection is available at
// the validator call site landed by slice
// agent-a-20260715-idp-oss-password-complexity-perorg-enforcement
// (Decision D-015 §9). The slim surface keeps the test fakes tiny.
type passwordResetUserSurface interface {
	FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error)
	GetByIDWithOrg(ctx context.Context, id uuid.UUID) (*domain.User, error)
	Update(ctx context.Context, id, orgID uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error)
}

// PasswordResetService orchestrates the request + complete flow.
type PasswordResetService struct {
	users         passwordResetUserSurface
	resets        repository.PasswordResetRepository
	sessions      passwordResetSessionRevoker
	refreshTokens passwordResetRefreshTokenRevoker
	notifier      PasswordResetNotifier
	audit         audit.Service
	logger        *zap.Logger
	now           func() time.Time
	tokenSize     int
	ttl           time.Duration

	// minPasswordLength is the policy floor applied on consume. The
	// monolith reads this from the dynamic config; the OSS port
	// honors a constructor-supplied value with a safe fallback of 8.
	//
	// PasswordComplexity is now enforced per-org via the existing
	// domain.ValidatePasswordPolicy helper landed by slice
	// agent-a-20260715-idp-oss-password-complexity-perorg-enforcement
	// (Decision D-015 §9). The validator is called AFTER the user
	// lookup so the user's org policy
	// (user.OrgPasswordComplexityEnabled) is known. nil ⇒ strict mode
	// (complexity required). The handler additionally rejects empty
	// strings.
	minPasswordLength int

	humanFacingBaseURL string
}

// PasswordResetNotifier is the minimum surface this service needs
// from the notification layer, provided by any implementation of
// SendPasswordResetEmail. Tests can substitute a stub that records
// calls without touching SMTP.
type PasswordResetNotifier interface {
	SendPasswordResetEmail(ctx context.Context, user *domain.User, resetLink string) error
}

// PasswordResetServiceConfig holds dependencies AND optional knobs.
// Refactored 2026-06-24 to satisfy the ≤5-arg target —
// `NewPasswordResetService` now takes a single argument of this type
// instead of 6 positional args.
//
// Required: Users, Resets. Optional: Sessions, Notifier, Audit
// (default audit.NoopService) — the service runs best-effort when
// these are nil.
//
// HumanFacingBaseURL is the absolute origin (no trailing slash) of
// the identuum-ui SPA — the password-reset email link is built as
// HumanFacingBaseURL + "/reset-password?token=<raw>". Empty disables
// only the link suffix; the request flow continues silently so a
// misconfigured deployment does not become an enumeration oracle.
type PasswordResetServiceConfig struct {
	Users    passwordResetUserSurface
	Resets   repository.PasswordResetRepository
	Sessions passwordResetSessionRevoker
	Notifier PasswordResetNotifier
	Audit    audit.Service

	HumanFacingBaseURL string
	TTL                time.Duration
	MinPasswordLength  int
	Logger             *zap.Logger
	Now                func() time.Time
}

// NewPasswordResetService constructs the service. cfg.Users / cfg.Resets
// are REQUIRED; cfg.Sessions / cfg.Notifier / cfg.Audit may be nil — the
// service runs in best-effort mode (no session revoke, no email send,
// no audit) when the corresponding dep is absent.
func NewPasswordResetService(cfg PasswordResetServiceConfig) *PasswordResetService {
	auditSvc := cfg.Audit
	if auditSvc == nil {
		auditSvc = audit.NoopService{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultPasswordResetTTL
	}
	minLen := cfg.MinPasswordLength
	if minLen <= 0 {
		minLen = 8
	}
	return &PasswordResetService{
		users:              cfg.Users,
		resets:             cfg.Resets,
		sessions:           cfg.Sessions,
		notifier:           cfg.Notifier,
		audit:              auditSvc,
		logger:             logger,
		now:                now,
		tokenSize:          32, // 32 raw bytes → 64 hex chars (matches monolith)
		ttl:                ttl,
		minPasswordLength:  minLen,
		humanFacingBaseURL: strings.TrimRight(cfg.HumanFacingBaseURL, "/"),
	}
}

// WithRefreshTokenRevoker installs the OAuth refresh-token revoker
// that the ResetPassword completion path fires after the session
// revoke. Source-compatible: deployments that never call this run
// session-only just like the pre-this-slice behaviour. A nil
// revoker resets the field to nil so a test fixture can drop it
// between cases without reconstructing the service.
func (s *PasswordResetService) WithRefreshTokenRevoker(r passwordResetRefreshTokenRevoker) *PasswordResetService {
	if s == nil {
		return nil
	}
	s.refreshTokens = r
	return s
}

// SetHumanFacingBaseURL updates the link prefix used in the
// password-reset email body. Safe to call at any time; a nil-receiver
// is a no-op so test fixtures can ignore the seam.
func (s *PasswordResetService) SetHumanFacingBaseURL(url string) {
	if s == nil {
		return
	}
	s.humanFacingBaseURL = strings.TrimRight(url, "/")
}

// BaseURL returns the captured human-facing base URL. Exposed for
// tests that need to verify the link prefix.
func (s *PasswordResetService) BaseURL() string {
	if s == nil {
		return ""
	}
	return s.humanFacingBaseURL
}

// RequestPasswordReset starts the flow for the supplied email.
//
// The handler ALWAYS returns 200 to the caller regardless of the
// outcome here, so this function deliberately swallows every error
// branch. The returned error is intentionally always nil — kept on
// the signature so future callers (background jobs, admin-recovery
// helpers) can extend the surface without a breaking change.
//
// Per-match outcome:
//   - zero matches → no-op (no audit event).
//   - one or more matches → one token per match; each receives
//     its own email + audit event.
//
// IPAddress / UserAgent flow into the audit event so SOC dashboards
// can correlate the reset request to the originating browser.
func (s *PasswordResetService) RequestPasswordReset(
	ctx context.Context,
	email string,
	ipAddress, userAgent string,
) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		// Empty email is wire-indistinguishable from an unknown
		// email at the handler boundary; return nil so the handler
		// emits the standard 200.
		return nil
	}
	users, err := s.users.FindUsersByEmail(ctx, email)
	if err != nil {
		// Hard repo error is treated as "no user found" so the
		// wire response cannot be used to probe DB health. We log
		// at warn level (no email in metadata) so operators still
		// see the underlying error.
		s.logger.Warn("password_reset: lookup failure", zap.Error(err))
		return nil
	}
	if len(users) == 0 {
		return nil
	}
	for _, user := range users {
		if user == nil || user.DeletedAt != nil || user.Banned {
			// Skip banned / deleted accounts silently. The wire
			// response is unchanged whether the account exists
			// in any state.
			continue
		}
		rawToken, tokenHash, err := s.generateToken()
		if err != nil {
			s.logger.Error("password_reset: token generation failed",
				zap.String("user_id", user.ID.String()),
				zap.Error(err),
			)
			continue
		}
		now := s.now().UTC()
		row := &domain.PasswordReset{
			UserID:    user.ID,
			TokenHash: tokenHash,
			ExpiresAt: now.Add(s.ttl),
			CreatedAt: now,
		}
		if err := s.resets.Create(ctx, row); err != nil {
			s.logger.Error("password_reset: persist token failed",
				zap.String("user_id", user.ID.String()),
				zap.Error(err),
			)
			continue
		}
		// Best-effort email delivery. A transient SMTP failure
		// does not block the flow — the operator can re-request,
		// and a successfully persisted token without delivery is
		// still recoverable via operator out-of-band channels.
		if s.notifier != nil {
			resetLink := s.humanFacingBaseURL + "/reset-password?token=" + rawToken
			if sendErr := s.notifier.SendPasswordResetEmail(ctx, user, resetLink); sendErr != nil {
				s.logger.Warn("password_reset: send email failed",
					zap.String("user_id", user.ID.String()),
					zap.Error(sendErr),
				)
			}
		}
		// Audit metadata carries only the user id + IP-derived
		// trace context. NEVER the raw token, reset link, or
		// email body.
		_ = s.audit.Record(ctx, audit.Event{
			Action:         string(domain.AuditUserPasswordResetRequested),
			Outcome:        "success",
			SubjectID:      user.ID,
			SubjectType:    "user",
			OrganizationID: user.OrganizationID,
			IPAddress:      ipAddress,
			UserAgent:      userAgent,
		})
	}
	return nil
}

// ResetPasswordInput captures the call-site values.
type ResetPasswordInput struct {
	Token       string
	NewPassword string
	IPAddress   string
	UserAgent   string
}

// ResetPassword consumes the supplied token. On success it sets a
// new password hash, revokes all active sessions for the user, and
// emits a single audit event.
//
// Failure modes collapse onto two sentinels:
//   - ErrPasswordResetInvalidToken (unknown / expired / consumed /
//     user-missing).
//   - ErrPasswordResetWeakPassword (policy violation).
//
// The handler maps both onto 400 with a distinct error code.
func (s *PasswordResetService) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if in.Token == "" {
		return ErrPasswordResetInvalidToken
	}
	// Cheap length floor before the DB roundtrip so a too-short
	// password is rejected without burning a DB query.
	if len(in.NewPassword) < s.minPasswordLength {
		return ErrPasswordResetWeakPassword
	}
	hash := hashToken(in.Token)
	row, err := s.resets.GetByTokenHash(ctx, hash)
	if err != nil || row == nil {
		return ErrPasswordResetInvalidToken
	}
	// Constant-time comparison defends against the (admittedly
	// remote) case where the DB returns a row whose token_hash
	// matches a prefix but not the full SHA-256.
	if subtle.ConstantTimeCompare([]byte(row.TokenHash), []byte(hash)) != 1 {
		return ErrPasswordResetInvalidToken
	}
	if !row.IsValid(s.now()) {
		return ErrPasswordResetInvalidToken
	}
	// P0-9: validate FULLY, THEN consume atomically. Load the user (for the
	// per-org policy + liveness) and validate the password policy BEFORE the
	// token is consumed, so a policy-invalid password can NEVER burn a valid
	// reset link.
	user, err := s.users.GetByIDWithOrg(ctx, row.UserID)
	if err != nil || user == nil {
		return ErrPasswordResetInvalidToken
	}
	if user.DeletedAt != nil || user.Banned {
		return ErrPasswordResetInvalidToken
	}
	// Per-org PasswordComplexityEnabled enforcement (Decision D-015 §9). nil ⇒
	// strict mode (complexity required) — safe backward-compat default.
	complexityEnabled := true
	if user.OrgPasswordComplexityEnabled != nil {
		complexityEnabled = *user.OrgPasswordComplexityEnabled
	}
	if err := domain.ValidatePasswordPolicy(in.NewPassword, s.minPasswordLength, complexityEnabled); err != nil {
		return ErrPasswordResetWeakPassword
	}
	// Atomic single-use claim + password write in ONE transaction. A concurrent
	// reset matches zero rows and gets ok=false; a failed write rolls the claim
	// back so a valid link survives. Pre-hash the password (argon2id).
	passwordHash, err := crypto.GenerateHash([]byte(in.NewPassword))
	if err != nil {
		return fmt.Errorf("password_reset: hash password: %w", err)
	}
	_, ok, err := s.resets.ClaimPasswordReset(ctx, row.TokenHash, passwordHash)
	if err != nil {
		return fmt.Errorf("password_reset: claim + persist: %w", err)
	}
	if !ok {
		// Already used / expired / lost the single-use race.
		return ErrPasswordResetInvalidToken
	}
	// P0-9: session + refresh-token revocation failures are NO LONGER swallowed.
	// The owner re-established control; any pre-existing cookie / refresh token
	// MUST stop authenticating. A revocation failure is logged at ERROR and
	// surfaced via ErrPasswordResetRevocationFailed so the flow never reports
	// plain success while pre-existing credentials survive. (The password change
	// itself has already committed atomically above.)
	revocationFailed := false
	if s.sessions != nil {
		if revokeErr := s.sessions.RevokeByUserID(ctx, user.ID, "password_reset"); revokeErr != nil {
			revocationFailed = true
			s.logger.Error("password_reset: revoke sessions failed",
				zap.String("user_id", user.ID.String()),
				zap.Error(revokeErr),
			)
		}
	}
	if s.refreshTokens != nil {
		if n, revokeErr := s.refreshTokens.RevokeAllForUser(ctx, user.ID); revokeErr != nil {
			revocationFailed = true
			s.logger.Error("password_reset: revoke refresh tokens failed",
				zap.String("user_id", user.ID.String()),
				zap.Error(revokeErr),
			)
		} else if n > 0 {
			s.logger.Info("password_reset: refresh tokens revoked",
				zap.String("user_id", user.ID.String()),
				zap.Int64("count", n),
			)
		}
	}
	_ = s.audit.Record(ctx, audit.Event{
		Action:         string(domain.AuditUserPasswordResetCompleted),
		Outcome:        "success",
		SubjectID:      user.ID,
		SubjectType:    "user",
		OrganizationID: user.OrganizationID,
		IPAddress:      in.IPAddress,
		UserAgent:      in.UserAgent,
	})
	if revocationFailed {
		return ErrPasswordResetRevocationFailed
	}
	return nil
}

// generateToken returns the raw token (caller emails it) and the
// SHA-256 hash (caller persists it). The raw token is NEVER stored.
func (s *PasswordResetService) generateToken() (string, string, error) {
	raw, err := crypto.GenerateRandomString(s.tokenSize)
	if err != nil {
		return "", "", err
	}
	return raw, hashToken(raw), nil
}

// hashToken is a thin wrapper around the internal/crypto SHA-256 hex
// helper. Centralised so a test cannot accidentally swap in a
// different hash algorithm.
func hashToken(raw string) string { return crypto.HashToken(raw) }
