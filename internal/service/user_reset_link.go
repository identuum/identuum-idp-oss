package service

// user_reset_link.go — D9 (owner answers Q3 (b) and Q-D9 (a), D-016
// Consequence): who may receive an administrator's one-time password reset
// link. The authority is the admin password set's
// (UpdateUserForActorRevokingFirst) plus no self target; the link itself is
// PasswordResetService.IssueLink's.

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

var (
	errResetLinkUserDisabled        = errors.New("service: user is disabled")
	errResetLinkUserNotActivated    = errors.New("service: user is not activated; use the invite")
	errResetLinkNoLocalPassword     = errors.New("service: user has no local password")
	errResetLinkLocalPasswordDenied = errors.New("service: the organization allows this user no local password")
)

// ErrResetLinkUserDisabled is a banned target (disabled or pending approval).
func ErrResetLinkUserDisabled() error { return errResetLinkUserDisabled }

// ErrResetLinkUserNotActivated is an unverified target: the invite is its way in.
func ErrResetLinkUserNotActivated() error { return errResetLinkUserNotActivated }

// ErrResetLinkNoLocalPassword is a target that signs in only upstream.
func ErrResetLinkNoLocalPassword() error { return errResetLinkNoLocalPassword }

// ErrResetLinkLocalPasswordNotAllowed is an org_user of an idp_only
// organization (IsLocalCredentialFlowAllowed denies it a local password).
func ErrResetLinkLocalPasswordNotAllowed() error { return errResetLinkLocalPasswordDenied }

// PasswordResetLinkTargetForActor returns the user an actor may hand a reset
// link to, read with its organization's policy. org_admin: its own
// organization, never a site_admin (404 outside visibility, G10); site_admin:
// no tenant user (D-025). Nobody targets itself: a stolen bearer must not turn
// into a password its holder chooses.
func (s *UserService) PasswordResetLinkTargetForActor(ctx context.Context, actor *domain.Principal, targetUserID uuid.UUID) (*domain.User, error) {
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, err
	}
	target, err := lookupManagedUser(ctx, s.repo, targetUserID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, errUserNotFound
		}
		return nil, err
	}
	if target == nil {
		return nil, errUserNotFound
	}
	switch {
	case actor.IsSiteAdmin():
		if err := refuseSiteAdminTenantUser(target); err != nil {
			return nil, err
		}
	case actor.IsOrgAdminOnly():
		if actor.OrganizationID == uuid.Nil || target.OrganizationID != actor.OrganizationID || target.Role == domain.RoleSiteAdmin {
			return nil, errUserNotFound
		}
	default:
		return nil, domain.ErrForbidden
	}
	if target.ID == actor.UserID {
		return nil, domain.ErrCannotResetSelf
	}
	// The password hash and the organization's sign-in policy come with the
	// organization-joined read.
	full, err := s.repo.GetByIDWithOrg(ctx, target.ID)
	if err != nil || full == nil || full.DeletedAt != nil {
		if err == nil || errors.Is(err, domain.ErrUserNotFound) {
			return nil, errUserNotFound
		}
		return nil, err
	}
	switch {
	case full.Banned:
		return nil, errResetLinkUserDisabled
	case full.AuthSource != "" && full.AuthSource != domain.AuthSourceLocal,
		full.PasswordHash == domain.NoPasswordSentinel:
		return nil, errResetLinkNoLocalPassword
	case !full.EmailVerified:
		return nil, errResetLinkUserNotActivated
	case !localCredentialFlowAllowed(full):
		return nil, errResetLinkLocalPasswordDenied
	}
	return full, nil
}
