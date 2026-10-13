package service

// password_reset_link.go — D9 (owner answers Q3 (b) and Q-D9 (a)): the
// administrator's one-time reset link. The token is the self-service reset's
// (generateToken, hash-only storage, spent by ResetPassword); it differs in
// three ways: it is RETURNED to the issuing administrator instead of mailed,
// it lives AdminSetPasswordTTL (24 hours) instead of an hour, and issuing it
// retires the user's other unused links in the same transaction. The raw
// token is never logged or audited here.

import (
	"context"
	"errors"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// passwordResetLinkStore is the store method D9 adds: insert the new row and
// mark the user's other unused rows used, atomically.
type passwordResetLinkStore interface {
	CreateRetiringOthers(ctx context.Context, reset *domain.PasswordReset) error
}

var errPasswordResetLinkUnavailable = errors.New("password reset: link store unavailable")

// ValidToken reports whether raw is an unused, unexpired reset token that
// ResetPassword would still accept for its user, without spending it (the
// /reset-link page's check).
func (s *PasswordResetService) ValidToken(ctx context.Context, raw string) bool {
	if raw == "" {
		return false
	}
	row, err := s.resets.GetByTokenHash(ctx, hashToken(raw))
	if err != nil || row == nil || !row.IsValid(s.now()) {
		return false
	}
	user, err := s.users.GetByIDWithOrg(ctx, row.UserID)
	return err == nil && user != nil && user.DeletedAt == nil && !user.Banned && localCredentialFlowAllowed(user)
}

// IssueLink mints an administrator's reset token for user and returns the raw
// token and its expiry. The caller has decided that user may receive one
// (UserService.PasswordResetLinkTargetForActor).
func (s *PasswordResetService) IssueLink(ctx context.Context, user *domain.User) (string, time.Time, error) {
	store, ok := s.resets.(passwordResetLinkStore)
	if !ok || user == nil {
		return "", time.Time{}, errPasswordResetLinkUnavailable
	}
	raw, hash, err := s.generateToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now().UTC()
	row := &domain.PasswordReset{UserID: user.ID, TokenHash: hash, ExpiresAt: now.Add(AdminSetPasswordTTL), CreatedAt: now}
	if err := store.CreateRetiringOthers(ctx, row); err != nil {
		return "", time.Time{}, err
	}
	return raw, row.ExpiresAt, nil
}
