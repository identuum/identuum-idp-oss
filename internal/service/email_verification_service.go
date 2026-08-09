// email_verification_service.go — OSS port of the monolith email
// verification flow.
//
// Source-of-truth reference for behaviour:
//   identuum-idp/internal/service/user_write_service_verification.go
//   identuum-idp/internal/handlers/verification.go
//
// We do NOT import monolith code; the port reimplements the
// observable contract on top of OSS repository, audit, and
// notification seams.
//
// Wire contract (mirrors monolith for UI compatibility — see
// identuum-ui/src/app/verify-email/actions.ts):
//
//   GET  /api/v1/auth/verify-email?token=<raw>
//       response: 200 { success: true, message: "..." } on accept
//                 400 { error: "invalid_token" }         on bad / expired / consumed token
//
//   POST /api/v1/auth/resend-verification
//       request:  { email }
//       response: always 200 { success: true, message: "..." }
//                 (oracle-hardened — unknown / already-verified email → same body)
//
// Token model (separate `email_verifications` table — mirrors
// `password_resets`):
//
//   - Generated via crypto.GenerateRandomString(32) → 64 hex chars.
//   - SHA-256(raw_token) persisted; raw token NEVER stored.
//   - TTL: 24 hours (matches the monolith's verification JWT exp).
//   - Single-use: MarkAsUsed flips used_at on consume BEFORE the
//     EmailVerified flag is flipped on the user row.
//   - On consume: only EmailVerified=true is written. The OSS port
//     deliberately does NOT clear `users.verification_token_hash`
//     because the dedicated email_verifications table is the source
//     of truth here.
//
// Anti-enumeration:
//
//   - ResendVerification always returns nil. The handler always
//     returns 200 regardless of whether any user matched.
//   - The per-user branch silently skips already-verified / banned /
//     deleted users; the wire response is unchanged.

package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// DefaultEmailVerificationTTL is the wall-clock lifetime of a single
// email verification token. Matches the monolith's 24-hour JWT
// expiry on the verification token.
const DefaultEmailVerificationTTL = 24 * time.Hour

// ErrEmailVerificationInvalidToken is the opaque sentinel returned
// when the supplied verification token is unknown, expired, already
// used, or its user row no longer exists / is deleted. Mapped to
// 400 invalid_token at the HTTP boundary.
var ErrEmailVerificationInvalidToken = errors.New("email verification: invalid token")

// EmailVerificationNotifier is the minimum surface this service
// needs from the notification layer, provided by any implementation
// of SendVerificationEmail.
type EmailVerificationNotifier interface {
	SendVerificationEmail(ctx context.Context, user *domain.User, rawToken string) error
}

// emailVerificationUserSurface is the narrow user-repo seam this
// service needs. PgxUserRepository satisfies it.
type emailVerificationUserSurface interface {
	FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	Update(ctx context.Context, id, orgID uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error)
}

// EmailVerificationService orchestrates the verify + resend flow.
type EmailVerificationService struct {
	users     emailVerificationUserSurface
	verifs    repository.EmailVerificationRepository
	notifier  EmailVerificationNotifier
	audit     audit.Service
	logger    *zap.Logger
	now       func() time.Time
	tokenSize int
	ttl       time.Duration
}

// EmailVerificationServiceOptions wires the optional knobs.
type EmailVerificationServiceOptions struct {
	TTL    time.Duration
	Logger *zap.Logger
	Now    func() time.Time
}

// NewEmailVerificationService constructs the service. users/verifs
// are REQUIRED; notifier/audit may be nil.
func NewEmailVerificationService(
	users emailVerificationUserSurface,
	verifs repository.EmailVerificationRepository,
	notifier EmailVerificationNotifier,
	auditSvc audit.Service,
	opts EmailVerificationServiceOptions,
) *EmailVerificationService {
	if auditSvc == nil {
		auditSvc = audit.NoopService{}
	}
	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultEmailVerificationTTL
	}
	return &EmailVerificationService{
		users:     users,
		verifs:    verifs,
		notifier:  notifier,
		audit:     auditSvc,
		logger:    logger,
		now:       now,
		tokenSize: 32,
		ttl:       ttl,
	}
}

// VerifyEmail consumes the supplied raw token.
//
// On success the user's email_verified flag is flipped to true and
// the verification row is marked used. The same caller submitting
// the same raw token again finds used_at != nil and is rejected.
//
// Wire mapping: nil → 200; ErrEmailVerificationInvalidToken → 400.
func (s *EmailVerificationService) VerifyEmail(ctx context.Context, rawToken, ipAddress, userAgent string) error {
	if rawToken == "" {
		return ErrEmailVerificationInvalidToken
	}
	hash := hashToken(rawToken)
	row, err := s.verifs.GetByTokenHash(ctx, hash)
	if err != nil || row == nil {
		return ErrEmailVerificationInvalidToken
	}
	if subtle.ConstantTimeCompare([]byte(row.TokenHash), []byte(hash)) != 1 {
		return ErrEmailVerificationInvalidToken
	}
	if !row.IsValid(s.now()) {
		return ErrEmailVerificationInvalidToken
	}
	// Burn-before-write: mark the row used BEFORE the email_verified
	// flag is flipped so a parallel attempt cannot win the race.
	if err := s.verifs.MarkAsUsed(ctx, row.TokenHash); err != nil {
		return ErrEmailVerificationInvalidToken
	}
	user, err := s.users.GetByID(ctx, row.UserID)
	if err != nil || user == nil {
		return ErrEmailVerificationInvalidToken
	}
	if user.DeletedAt != nil || user.Banned {
		return ErrEmailVerificationInvalidToken
	}
	// Idempotency guard — already verified is a no-op. We still
	// return nil so the operator sees the standard 200 even on a
	// stale link click.
	if user.EmailVerified {
		return nil
	}
	verified := true
	if _, err := s.users.Update(ctx, user.ID, user.OrganizationID, repository.UpdateUserOptions{
		EmailVerified: &verified,
	}); err != nil {
		return ErrEmailVerificationInvalidToken
	}
	_ = s.audit.Record(ctx, audit.Event{
		Action:         string(domain.AuditEmailVerified),
		Outcome:        "success",
		SubjectID:      user.ID,
		SubjectType:    "user",
		OrganizationID: user.OrganizationID,
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
	})
	return nil
}

// ResendVerification re-issues a verification token + email for the
// matching unverified user(s). Anti-enumeration: the wire response is
// 200 regardless of whether any user matched.
//
// Banned / deleted / already-verified users are silently skipped.
func (s *EmailVerificationService) ResendVerification(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil
	}
	users, err := s.users.FindUsersByEmail(ctx, email)
	if err != nil {
		s.logger.Warn("email_verification: lookup failure", zap.Error(err))
		return nil
	}
	for _, user := range users {
		if user == nil || user.DeletedAt != nil || user.Banned || user.EmailVerified {
			continue
		}
		raw, hash, err := s.generateToken()
		if err != nil {
			s.logger.Error("email_verification: token generation failed",
				zap.String("user_id", user.ID.String()),
				zap.Error(err),
			)
			continue
		}
		now := s.now().UTC()
		row := &domain.EmailVerification{
			UserID:    user.ID,
			TokenHash: hash,
			ExpiresAt: now.Add(s.ttl),
			CreatedAt: now,
		}
		if err := s.verifs.Create(ctx, row); err != nil {
			s.logger.Error("email_verification: persist failed",
				zap.String("user_id", user.ID.String()),
				zap.Error(err),
			)
			continue
		}
		if s.notifier != nil {
			if sendErr := s.notifier.SendVerificationEmail(ctx, user, raw); sendErr != nil {
				s.logger.Warn("email_verification: send email failed",
					zap.String("user_id", user.ID.String()),
					zap.Error(sendErr),
				)
			}
		}
		_ = s.audit.Record(ctx, audit.Event{
			Action:         string(domain.AuditEmailVerificationResent),
			Outcome:        "success",
			SubjectID:      user.ID,
			SubjectType:    "user",
			OrganizationID: user.OrganizationID,
		})
	}
	return nil
}

// IssueInitialVerification is a sibling helper for first-time email
// verification (e.g. the future self-registration flow). Identical
// in shape to ResendVerification's per-user branch but exposed so
// onboarding code can mint the first verification token without
// going through the resend handler's anti-enumeration gate.
//
// Returns the raw token to the caller so the caller can hand it off
// to whatever notification path it prefers (the notifier is also
// fired when wired).
func (s *EmailVerificationService) IssueInitialVerification(ctx context.Context, user *domain.User) (string, error) {
	if user == nil {
		return "", errors.New("email_verification: nil user")
	}
	if user.EmailVerified {
		return "", nil
	}
	raw, hash, err := s.generateToken()
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	row := &domain.EmailVerification{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: now.Add(s.ttl),
		CreatedAt: now,
	}
	if err := s.verifs.Create(ctx, row); err != nil {
		return "", err
	}
	if s.notifier != nil {
		_ = s.notifier.SendVerificationEmail(ctx, user, raw)
	}
	return raw, nil
}

func (s *EmailVerificationService) generateToken() (string, string, error) {
	raw, err := crypto.GenerateRandomString(s.tokenSize)
	if err != nil {
		return "", "", err
	}
	return raw, hashToken(raw), nil
}
