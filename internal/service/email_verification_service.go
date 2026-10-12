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
//                 400 { error: "email_changed", message } when the link was
//                     mailed to another address than the user's current one
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
//   - The row names the address it was mailed to (email_hash, migration
//     0054); a link proves only that address (OSS-0912-C2-FIX). An address
//     change spends the user's open links in the same write.
//   - TTL: 24 hours (matches the monolith's verification JWT exp).
//   - Single-use: MarkAsUsed flips used_at on consume BEFORE the
//     user row is written.
//   - On consume (OSS-0912-C2): email_verified_via=email_link is
//     written — the mailbox is proven — and EmailVerified=true (the
//     activation) unless an invite or activation link is still pending:
//     that link activates the account, and activating here would spend
//     it. The OSS port deliberately does NOT clear
//     `users.verification_token_hash` because the dedicated
//     email_verifications table is the source of truth here.
//
// Anti-enumeration:
//
//   - ResendVerification always returns nil. The handler always
//     returns 200 regardless of whether any user matched.
//   - The per-user branch silently skips mailbox-proven / banned /
//     deleted users; the wire response is unchanged.
//
// POST /api/v1/me/email/verification (OSS-0912-C2) is the signed-in
// form: SendOwnVerification mails the caller's own address and answers
// plainly, since the caller already knows the account exists.

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

// DefaultEmailVerificationTTL is the wall-clock lifetime of a single
// email verification token. Matches the monolith's 24-hour JWT
// expiry on the verification token.
const DefaultEmailVerificationTTL = 24 * time.Hour

// ErrEmailVerificationInvalidToken is the opaque sentinel returned
// when the supplied verification token is unknown, expired, already
// used, or its user row no longer exists / is deleted. Mapped to
// 400 invalid_token at the HTTP boundary.
var ErrEmailVerificationInvalidToken = errors.New("email verification: invalid token")

// ErrEmailVerificationAddressChanged answers a link mailed to another address
// than the user's current one (OSS-0912-C2-FIX), also when the address changes
// while the link is opened (OSS-0912-C2-FIX-2). The link proves nothing and is
// not spent. Mapped to 400 email_changed.
var ErrEmailVerificationAddressChanged = errors.New("email verification: the link was sent to another address")

// ErrEmailVerificationNotAvailable answers SendOwnVerification for the
// site_admin, whose address is the reserved sign-in name, not a mailbox.
var ErrEmailVerificationNotAvailable = errors.New("email verification: not available for this account")

// ErrEmailAlreadyProven answers SendOwnVerification for a user whose mailbox
// is already proven: nothing is sent.
var ErrEmailAlreadyProven = errors.New("email verification: mailbox already proven")

// ErrEmailDeliveryFailed wraps a send error SendOwnVerification met other
// than ErrEmailDeliveryNotConfigured.
var ErrEmailDeliveryFailed = errors.New("email verification: delivery failed")

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
	prover    repository.EmailVerificationProver
	notifier  EmailVerificationNotifier
	audit     audit.Service
	logger    *zap.Logger
	now       func() time.Time
	tokenSize int
	ttl       time.Duration
	// background runs the account-dependent part of a resend after the
	// response; nil runs it inline.
	background BackgroundRunner
}

// WithBackground hands the account-dependent part of ResendVerification to run,
// so the response does not wait for it (nor reveal, by its timing, whether the
// address has an unverified account). Nil runs it inline.
func (s *EmailVerificationService) WithBackground(run BackgroundRunner) *EmailVerificationService {
	if s == nil {
		return nil
	}
	s.background = run
	return s
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
	s := &EmailVerificationService{
		users:     users,
		verifs:    verifs,
		notifier:  notifier,
		audit:     auditSvc,
		logger:    logger,
		now:       now,
		tokenSize: 32,
		ttl:       ttl,
	}
	// The burn and the proof run in one transaction whenever the repository
	// can open one (PgxEmailVerificationRepository, the production wiring).
	// The in-memory fakes of the unit tests run the same steps without one.
	if p, ok := verifs.(repository.EmailVerificationProver); ok {
		s.prover = p
	} else {
		s.prover = emailProofWithoutTx{s: s}
	}
	return s
}

// emailProofWithoutTx is repository.EmailVerificationProver over the
// service's own repositories, for repositories that cannot open a transaction.
type emailProofWithoutTx struct{ s *EmailVerificationService }

func (p emailProofWithoutTx) ProveInTx(_ context.Context, _ uuid.UUID, fn func(repository.EmailVerificationProofTx) error) error {
	return fn(p)
}

func (p emailProofWithoutTx) MarkAsUsed(ctx context.Context, tokenHash string) error {
	return p.s.verifs.MarkAsUsed(ctx, tokenHash)
}

func (p emailProofWithoutTx) Update(ctx context.Context, id, orgID uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	return p.s.users.Update(ctx, id, orgID, opts)
}

// VerifyEmail consumes the supplied raw token.
//
// On success the mailbox is recorded as proven (email_link), the
// account is activated unless an invite or activation link is pending,
// and the verification row is marked used. The same caller submitting
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
	user, err := s.users.GetByID(ctx, row.UserID)
	if err != nil || user == nil {
		return ErrEmailVerificationInvalidToken
	}
	if user.DeletedAt != nil || user.Banned {
		return ErrEmailVerificationInvalidToken
	}
	// OSS-0912-C2-FIX: the link proves only the address it was mailed to.
	// A refused link stays unused; the user can ask for a new one.
	if !row.ProvesAddress(user.Email) {
		return ErrEmailVerificationAddressChanged
	}
	via := domain.EmailVerifiedViaEmailLink
	// OSS-0912-C2-FIX-2 (review F1): the write lands only while the address
	// is the one checked above.
	opts := repository.UpdateUserOptions{EmailVerifiedVia: &via, RequireEmail: &user.Email}
	// Q-C2-2 (a): a pending invite or activation is activated by its own
	// link; activating here would spend that link and leave the account
	// with no password anyone knows.
	if user.ActivationTokenHash == nil {
		verified := true
		opts.EmailVerified = &verified
	}
	// OSS-0912-C2-FIX-2 (review F1): the burn and the write run in one
	// transaction that holds the user's row. An address change that
	// committed after the read above has retired this link (the burn fails)
	// or changed the address (the write matches no row, and the transaction
	// rolls back); one that comes later waits for the commit.
	recorded := false
	err = s.prover.ProveInTx(ctx, user.ID, func(tx repository.EmailVerificationProofTx) error {
		// Burn-before-write: mark the row used BEFORE the email_verified
		// flag is flipped so a parallel attempt cannot win the race.
		if err := tx.MarkAsUsed(ctx, row.TokenHash); err != nil {
			return ErrEmailVerificationInvalidToken
		}
		// Idempotency guard — an already proven mailbox is a no-op. We
		// still return nil so the operator sees the standard 200 even on a
		// stale link click. An activated but unproven account (an
		// administrator's link or setting) goes on to record the proof.
		if user.MailboxProven() {
			return nil
		}
		if _, err := tx.Update(ctx, user.ID, user.OrganizationID, opts); err != nil {
			if errors.Is(err, domain.ErrUserNotFound) {
				return ErrEmailVerificationAddressChanged
			}
			return ErrEmailVerificationInvalidToken
		}
		recorded = true
		return nil
	})
	switch {
	case errors.Is(err, ErrEmailVerificationAddressChanged):
		return err
	case err != nil:
		return ErrEmailVerificationInvalidToken
	case !recorded:
		return nil
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
// Banned / deleted / mailbox-proven users are silently skipped.
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
	// Everything past the lookup depends on an unverified account existing, so
	// it runs after the response: the response time must not say whether the
	// address has one.
	runWith(s.background, ctx, func(ctx context.Context) { s.issueResends(ctx, users) })
	return nil
}

// issueResends issues one token, one email and one audit event per live
// account whose mailbox is not proven.
func (s *EmailVerificationService) issueResends(ctx context.Context, users []*domain.User) {
	for _, user := range users {
		// OSS-0912-C2-FIX-2 (review F2): the site_admin's address is the
		// reserved sign-in name, not a mailbox; the answer stays the same.
		if user == nil || user.DeletedAt != nil || user.Banned || user.MailboxProven() || user.IsSiteAdmin() {
			continue
		}
		if sendErr := s.issue(ctx, user); sendErr != nil && !errors.Is(sendErr, errEmailVerificationNotIssued) {
			s.logger.Warn("email_verification: send email failed",
				zap.String("user_id", user.ID.String()),
				zap.Error(sendErr),
			)
		}
	}
}

// issue persists one token for user, mails it and audits the send: Outcome
// success, or failure when the notifier refused it. It returns the notifier's
// error; a token or persistence failure is logged and returned as
// errEmailVerificationNotIssued, and nothing is mailed or audited.
func (s *EmailVerificationService) issue(ctx context.Context, user *domain.User) error {
	raw, hash, err := s.generateToken()
	if err != nil {
		s.logger.Error("email_verification: token generation failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		return errEmailVerificationNotIssued
	}
	if err := s.verifs.Create(ctx, s.newRow(user, hash)); err != nil {
		s.logger.Error("email_verification: persist failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		return errEmailVerificationNotIssued
	}
	var sendErr error
	if s.notifier != nil {
		sendErr = s.notifier.SendVerificationEmail(ctx, user, raw)
	}
	outcome := "success"
	if sendErr != nil {
		outcome = "failure"
	}
	_ = s.audit.Record(ctx, audit.Event{
		Action:         string(domain.AuditEmailVerificationResent),
		Outcome:        outcome,
		SubjectID:      user.ID,
		SubjectType:    "user",
		OrganizationID: user.OrganizationID,
	})
	return sendErr
}

var errEmailVerificationNotIssued = errors.New("email verification: token not issued")

// newRow is the verification row for a link mailed to user's current address.
func (s *EmailVerificationService) newRow(user *domain.User, tokenHash string) *domain.EmailVerification {
	now := s.now().UTC()
	return &domain.EmailVerification{
		UserID:      user.ID,
		TokenHash:   tokenHash,
		AddressHash: domain.EmailAddressHash(user.Email),
		ExpiresAt:   now.Add(s.ttl),
		CreatedAt:   now,
	}
}

// SendOwnVerification mails a verification link to the signed-in user's own
// address (POST /api/v1/me/email/verification, OSS-0912-C2). It answers
// ErrEmailVerificationNotAvailable for the site_admin (OSS-0912-C2-FIX),
// ErrEmailAlreadyProven for a proven mailbox, domain.ErrUserNotFound for a
// user that is gone, ErrEmailDeliveryNotConfigured when this server cannot
// send email, ErrEmailDeliveryFailed for any other send error. The raw token
// only ever travels in the mail.
func (s *EmailVerificationService) SendOwnVerification(ctx context.Context, userID uuid.UUID) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil || user.DeletedAt != nil || user.Banned {
		return domain.ErrUserNotFound
	}
	if user.IsSiteAdmin() {
		return ErrEmailVerificationNotAvailable
	}
	if user.MailboxProven() {
		return ErrEmailAlreadyProven
	}
	if s.notifier == nil {
		return ErrEmailDeliveryNotConfigured
	}
	if err := s.issue(ctx, user); err != nil {
		if errors.Is(err, ErrEmailDeliveryNotConfigured) {
			return ErrEmailDeliveryNotConfigured
		}
		if errors.Is(err, errEmailVerificationNotIssued) {
			return err
		}
		return fmt.Errorf("%w: %w", ErrEmailDeliveryFailed, err)
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
	if user.MailboxProven() {
		return "", nil
	}
	raw, hash, err := s.generateToken()
	if err != nil {
		return "", err
	}
	if err := s.verifs.Create(ctx, s.newRow(user, hash)); err != nil {
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
