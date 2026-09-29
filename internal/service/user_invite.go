package service

// user_invite.go — OSS-ONBOARD-A (owner ruling D-016, wiki
// platform/decisions.md): an organization admin invites a user with a
// one-time link instead of setting their password.
//
// The invite reuses the user row's activation columns
// (activation_token_hash, activation_token_expires_at — the ones the
// organization activation uses), so no migration is needed. A user is
// PENDING while it is unverified and holds an activation token hash; its
// password is a hash of random bytes nobody knows, so it cannot sign in
// until it redeems. The two uses of the columns never cross: an
// organization activation belongs to an organization that is not yet
// active, an invite to one that is, and each redeem refuses the other.
//
// The token is 32 random bytes (hex, 256-bit), stored only as its
// SHA-256, single-use, and lives the activation TTL. It is returned to the
// issuing admin at issue and at re-issue and is also mailed when SMTP is
// configured; it never enters a log line or an audit row.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// UserInviteNotifier mails an invite link. SMTPNotifier implements it; the
// runtime wires UnconfiguredEmailNotifier when SMTP is not configured.
type UserInviteNotifier interface {
	SendUserInviteEmail(ctx context.Context, user *domain.User, rawToken string, expiresAt time.Time) error
}

// inviteTokenRepository is the repository seam for the invite's token
// lookup and its single-use redeem. PgxUserRepository satisfies it.
type inviteTokenRepository interface {
	FindByActivationTokenHash(ctx context.Context, hash string) (*domain.User, error)
	ConsumeInviteToken(ctx context.Context, tokenHash, newPasswordHash string, now time.Time) (*domain.User, bool, error)
}

// inviteOrgReader resolves the user's organization for the redeem: it
// must be active (an inactive one is an organization activation's) and
// it carries the password policy. GetByID hides inactive organizations.
type inviteOrgReader interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error)
}

// UserInviteConfig wires the invite. Orgs is required for Validate and
// Redeem; Notifier, Now, TTL and Logger default to none, time.Now, the
// organization activation TTL and a no-op logger.
type UserInviteConfig struct {
	Orgs     inviteOrgReader
	Notifier UserInviteNotifier
	Now      func() time.Time
	TTL      time.Duration
	Logger   *zap.Logger
}

type userInvite struct {
	orgs     inviteOrgReader
	notifier UserInviteNotifier
	now      func() time.Time
	ttl      time.Duration
	logger   *zap.Logger
}

// WithInvite enables the invite on this service and returns it.
func (s *UserService) WithInvite(cfg UserInviteConfig) *UserService {
	inv := &userInvite{orgs: cfg.Orgs, notifier: cfg.Notifier, now: cfg.Now, ttl: cfg.TTL, logger: cfg.Logger}
	if inv.now == nil {
		inv.now = time.Now
	}
	if inv.ttl <= 0 {
		inv.ttl = DefaultOrganizationActivationTTL
	}
	if inv.logger == nil {
		inv.logger = zap.NewNop()
	}
	s.invite = inv
	return s
}

// InviteEnabled reports whether WithInvite wired the invite.
func (s *UserService) InviteEnabled() bool { return s != nil && s.invite != nil }

var (
	errInviteUnavailable    = errors.New("service: user invite is not available")
	errInviteInvalid        = errors.New("service: invite is invalid, expired or spent")
	errInviteWeakPassword   = errors.New("service: invite password does not meet the policy")
	errUserNotPendingInvite = errors.New("service: user has no pending invite")
)

// ErrInviteInvalid is the one answer for an unknown, expired or spent invite.
func ErrInviteInvalid() error { return errInviteInvalid }

// ErrInviteWeakPassword is a password that fails the organization's policy.
func ErrInviteWeakPassword() error { return errInviteWeakPassword }

// ErrUserNotPendingInvite is a re-issue for a user who is not pending.
func ErrUserNotPendingInvite() error { return errUserNotPendingInvite }

// ErrInviteUnavailable is an invite call on a service without WithInvite.
func ErrInviteUnavailable() error { return errInviteUnavailable }

// IsInvitePending reports the pending-invite state: unverified and
// holding an activation token hash.
func IsInvitePending(u *domain.User) bool {
	return u != nil && !u.EmailVerified && u.ActivationTokenHash != nil && u.DeletedAt == nil
}

// isPreD017Unverified is a local user created with a password before D-017
// (v0.7.0 and earlier): unverified, holding no invite token, so without mail
// it can never sign in. An invite is how an org_admin brings it in; redeeming
// sets a new password and verifies it (OSS-FIN-2).
func isPreD017Unverified(u *domain.User) bool {
	return u != nil && !u.EmailVerified && u.ActivationTokenHash == nil && u.DeletedAt == nil &&
		u.AuthSource == domain.AuthSourceLocal
}

// InviteUserForActor creates a pending user under the same authority as
// CreateUserForActor (an org_admin in its own organization; site_admin
// only for an organization's first org_admin) and returns it with the raw
// token and its expiry. opts.Password must be empty; the role defaults to
// org_user.
func (s *UserService) InviteUserForActor(ctx context.Context, actor *domain.Principal, opts CreateUserOptions) (*domain.User, string, time.Time, error) {
	if s.invite == nil {
		return nil, "", time.Time{}, errInviteUnavailable
	}
	if opts.Role == "" {
		opts.Role = domain.RoleOrgUser
	}
	if err := s.authorizeCreate(ctx, actor, &opts); err != nil {
		return nil, "", time.Time{}, err
	}
	if opts.OrganizationID.String() == domain.SystemOrgID {
		return nil, "", time.Time{}, domain.ErrForbidden
	}
	email := strings.TrimSpace(opts.Email)
	if err := domain.ValidateUserEmail(email); err != nil {
		return nil, "", time.Time{}, err
	}
	if !opts.Role.IsValid() || opts.Role == domain.RoleSiteAdmin {
		return nil, "", time.Time{}, fmt.Errorf("invalid role")
	}
	placeholder, err := unknowablePasswordHash()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	raw, hash, err := newInviteToken()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("user uuid generation failed: %w", err)
	}
	now := s.invite.now().UTC()
	expiresAt := now.Add(s.invite.ttl)
	user := &domain.User{
		ID:                       id,
		OrganizationID:           opts.OrganizationID,
		Email:                    email,
		PasswordHash:             placeholder,
		Role:                     opts.Role,
		AuthSource:               domain.AuthSourceLocal,
		EmailVerified:            false,
		ActivationTokenHash:      &hash,
		ActivationTokenExpiresAt: &expiresAt,
		CreatedAt:                now,
		UpdatedAt:                now,
	}
	if opts.Name != "" {
		n := opts.Name
		user.Name = &n
	}
	if err := user.Validate(); err != nil {
		return nil, "", time.Time{}, err
	}
	created, err := s.repo.Create(ctx, user)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	s.mailInvite(ctx, created, raw, expiresAt)
	return created, raw, expiresAt, nil
}

// ReissueInviteForActor mints a fresh token for a pending user; the older
// one stops working. An org_admin reaches only its own organization's
// users (another organization's user is not found, G10); a site_admin
// only the org_admin it may seed. A pre-D-017 unverified user is invited
// the same way (isPreD017Unverified). Any other user answers
// ErrUserNotPendingInvite.
func (s *UserService) ReissueInviteForActor(ctx context.Context, actor *domain.Principal, targetUserID uuid.UUID) (*domain.User, string, time.Time, error) {
	if s.invite == nil {
		return nil, "", time.Time{}, errInviteUnavailable
	}
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, "", time.Time{}, err
	}
	target, err := lookupManagedUser(ctx, s.repo, targetUserID)
	if err != nil || target == nil {
		if err == nil || errors.Is(err, domain.ErrUserNotFound) {
			return nil, "", time.Time{}, errUserNotFound
		}
		return nil, "", time.Time{}, err
	}
	switch {
	case actor.IsSiteAdmin():
		if target.Role != domain.RoleOrgAdmin {
			return nil, "", time.Time{}, domain.ErrForbidden
		}
	case actor.IsOrgAdminOnly():
		if actor.OrganizationID == uuid.Nil || target.OrganizationID != actor.OrganizationID || target.Role == domain.RoleSiteAdmin {
			return nil, "", time.Time{}, errUserNotFound
		}
	default:
		return nil, "", time.Time{}, domain.ErrForbidden
	}
	if !IsInvitePending(target) && !isPreD017Unverified(target) {
		return nil, "", time.Time{}, errUserNotPendingInvite
	}
	raw, hash, err := newInviteToken()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	expiresAt := s.invite.now().UTC().Add(s.invite.ttl)
	updated, err := s.repo.Update(ctx, target.ID, target.OrganizationID, repository.UpdateUserOptions{
		ActivationTokenHash:      &hash,
		ActivationTokenExpiresAt: &expiresAt,
	})
	if err != nil {
		return nil, "", time.Time{}, err
	}
	if updated == nil {
		updated = target
	}
	s.mailInvite(ctx, updated, raw, expiresAt)
	return updated, raw, expiresAt, nil
}

// ValidateInvite is the public pre-flight: the pending user the token
// belongs to, or ErrInviteInvalid. It does not spend the token.
func (s *UserService) ValidateInvite(ctx context.Context, rawToken string) (*domain.User, error) {
	user, _, err := s.lookupInvite(ctx, rawToken)
	return user, err
}

// RedeemInvite sets the password under the organization's policy, marks
// the user verified and spends the token, atomically. Unknown, expired and
// spent tokens answer ErrInviteInvalid; a policy failure answers
// ErrInviteWeakPassword and leaves the token usable.
func (s *UserService) RedeemInvite(ctx context.Context, rawToken, password string) (*domain.User, error) {
	user, org, err := s.lookupInvite(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	if err := domain.ValidatePasswordPolicy(password, inviteMinPasswordLength, org.PasswordComplexityEnabled); err != nil {
		return nil, errInviteWeakPassword
	}
	passwordHash, err := s.repo.HashPassword(password)
	if err != nil {
		return nil, errPasswordHashing
	}
	repo, ok := s.repo.(inviteTokenRepository)
	if !ok {
		return nil, errInviteUnavailable
	}
	redeemed, claimed, err := repo.ConsumeInviteToken(ctx, hashToken(rawToken), passwordHash, s.invite.now().UTC())
	if err != nil {
		return nil, err
	}
	if !claimed || redeemed == nil || redeemed.ID != user.ID {
		return nil, errInviteInvalid
	}
	return redeemed, nil
}

// inviteMinPasswordLength is the floor the admin create applies (the
// service default of CreateUserOptions.MinPasswordLength).
const inviteMinPasswordLength = 8

func (s *UserService) lookupInvite(ctx context.Context, rawToken string) (*domain.User, *domain.Organization, error) {
	if s.invite == nil {
		return nil, nil, errInviteUnavailable
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, nil, errInviteInvalid
	}
	repo, ok := s.repo.(inviteTokenRepository)
	if !ok || s.invite.orgs == nil {
		return nil, nil, errInviteUnavailable
	}
	hash := hashToken(rawToken)
	user, err := repo.FindByActivationTokenHash(ctx, hash)
	if err != nil || user == nil || user.ActivationTokenHash == nil ||
		subtle.ConstantTimeCompare([]byte(*user.ActivationTokenHash), []byte(hash)) != 1 {
		return nil, nil, errInviteInvalid
	}
	if !IsInvitePending(user) || user.Banned {
		return nil, nil, errInviteInvalid
	}
	if user.ActivationTokenExpiresAt != nil && !s.invite.now().Before(*user.ActivationTokenExpiresAt) {
		return nil, nil, errInviteInvalid
	}
	org, err := s.invite.orgs.GetByID(ctx, user.OrganizationID)
	if err != nil || org == nil || !org.Active {
		return nil, nil, errInviteInvalid
	}
	return user, org, nil
}

func (s *UserService) mailInvite(ctx context.Context, user *domain.User, raw string, expiresAt time.Time) {
	if s.invite.notifier == nil {
		return
	}
	if err := s.invite.notifier.SendUserInviteEmail(ctx, user, raw, expiresAt); err != nil {
		// D-016: no SMTP is the default and the admin hands the link over,
		// so an unmailed invite is expected, not a warning.
		if errors.Is(err, ErrEmailDeliveryNotConfigured) {
			s.invite.logger.Info("user invite: not mailed: delivery not configured",
				zap.String("user_id", user.ID.String()))
			return
		}
		s.invite.logger.Warn("user invite: send email failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
	}
}

func newInviteToken() (string, string, error) {
	raw, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", "", err
	}
	return raw, hashToken(raw), nil
}

// unknowablePasswordHash hashes 32 random bytes nobody keeps, as the
// organization's pending first admin gets (CreateWithInitialAdmin).
func unknowablePasswordHash() (string, error) {
	placeholder := make([]byte, 32)
	if _, err := rand.Read(placeholder); err != nil {
		return "", fmt.Errorf("placeholder generation failed: %w", err)
	}
	hash, err := crypto.GenerateHash(placeholder)
	if err != nil {
		return "", fmt.Errorf("placeholder hashing failed: %w", err)
	}
	return hash, nil
}
