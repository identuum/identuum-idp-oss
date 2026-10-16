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

// PendingPasswordChange is what a live password-change handle carries.
// PasskeyVerified is true only for a handle the passkey finish minted after
// verifying an assertion with user verification (OSS-G8-PASSKEY-MFA-CARRYOVER);
// it comes from the stored row's kind, never from the request.
type PendingPasswordChange struct {
	UserID          uuid.UUID
	RememberMe      bool
	PasskeyVerified bool
}

// PeekPasswordChange validates a password-change handle WITHOUT consuming
// it, so a refused new password (policy, reuse) does not burn the handle.
// Returns the user it belongs to, the sign-in's remember-me choice and
// whether the handle carries a verified passkey proof.
func (s *MFAEnrollmentService) PeekPasswordChange(ctx context.Context, pendingID uuid.UUID) (PendingPasswordChange, error) {
	row, err := s.pending.GetByID(ctx, pendingID)
	if err != nil {
		if errors.Is(err, repository.ErrMFAPendingSessionNotFound) {
			return PendingPasswordChange{}, ErrMFAEnrollmentNotFound
		}
		return PendingPasswordChange{}, ErrMFAEnrollmentInvalid
	}
	kind := domain.MFAPendingKindPasswordChange
	if row.Kind == domain.MFAPendingKindPasswordChangePasskeyUV {
		kind = domain.MFAPendingKindPasswordChangePasskeyUV
	}
	if ok, _ := row.CanBeUsed(s.now(), kind); !ok {
		if row.ConsumedAt != nil {
			return PendingPasswordChange{}, ErrMFAEnrollmentAlreadyConsumed
		}
		if !row.ExpiresAt.After(s.now()) {
			return PendingPasswordChange{}, ErrMFAEnrollmentExpired
		}
		return PendingPasswordChange{}, ErrMFAEnrollmentInvalid
	}
	return PendingPasswordChange{UserID: row.UserID, RememberMe: row.RememberMe, PasskeyVerified: kind == domain.MFAPendingKindPasswordChangePasskeyUV}, nil
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
