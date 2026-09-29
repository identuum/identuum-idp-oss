package service

// login_password_change.go — the password-change step of a sign-in
// (OSS-FIN-1, owner ruling D-017). A user created with an admin-set password
// signs in with it and is answered a one-time pending handle of kind
// password_change instead of a session. Redeeming the handle with an
// acceptable new password (ChangePasswordService.ChangeRequiredAtSignIn)
// continues the sign-in: MFA enrolment or verification when the policy asks,
// then the session. Nothing before that point is a credential.

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// ErrLoginPasswordChangeRequired → 401 password_change_required. The
// partial LoginResult carries the user so the HTTP layer can mint the
// password_change handle; no session exists.
var ErrLoginPasswordChangeRequired = errors.New("service: login password change required")

// PeekPasswordChange validates a password_change handle WITHOUT consuming
// it, so a refused new password (policy, reuse) does not burn the handle.
// Returns the user it belongs to and the sign-in's remember-me choice.
func (s *MFAEnrollmentService) PeekPasswordChange(ctx context.Context, pendingID uuid.UUID) (uuid.UUID, bool, error) {
	row, err := s.pending.GetByID(ctx, pendingID)
	if err != nil {
		if errors.Is(err, repository.ErrMFAPendingSessionNotFound) {
			return uuid.Nil, false, ErrMFAEnrollmentNotFound
		}
		return uuid.Nil, false, ErrMFAEnrollmentInvalid
	}
	if ok, _ := row.CanBeUsed(s.now(), domain.MFAPendingKindPasswordChange); !ok {
		if row.ConsumedAt != nil {
			return uuid.Nil, false, ErrMFAEnrollmentAlreadyConsumed
		}
		if !row.ExpiresAt.After(s.now()) {
			return uuid.Nil, false, ErrMFAEnrollmentExpired
		}
		return uuid.Nil, false, ErrMFAEnrollmentInvalid
	}
	return row.UserID, row.RememberMe, nil
}

// ConsumePasswordChange claims the handle once the password has changed.
func (s *MFAEnrollmentService) ConsumePasswordChange(ctx context.Context, pendingID uuid.UUID) error {
	ok, err := s.pending.MarkConsumed(ctx, pendingID, s.now())
	if err != nil {
		return err
	}
	if !ok {
		return ErrMFAEnrollmentAlreadyConsumed
	}
	return nil
}
