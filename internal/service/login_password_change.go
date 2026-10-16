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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

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

// passkeyBindingBytes is the entropy of the client secret that binds a
// passkey proof to the client that made the assertion.
const passkeyBindingBytes = 32

// CreatePasskeyPasswordChange mints the change handle of a passkey sign-in
// whose assertion was verified with user verification, bound to the client
// that made it (OSS-G8-PASSKEY-MFA-R2). It returns the row and the client's
// secret: the caller hands the secret to that client only, out of the
// response body (an HttpOnly cookie); the row stores its SHA-256. The secret
// is credential material: never logged, never in audit metadata.
func (s *MFAEnrollmentService) CreatePasskeyPasswordChange(ctx context.Context, user *domain.User, rememberMe bool) (*domain.MFAPendingLoginSession, string, error) {
	raw := make([]byte, passkeyBindingBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("service: passkey binding generation: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	row, err := s.createPending(ctx, user, domain.MFAPendingKindPasswordChangePasskeyUV, rememberMe, sum[:])
	if err != nil {
		return nil, "", err
	}
	return row, secret, nil
}

// PeekPasswordChange validates a password-change handle WITHOUT consuming
// it, so a refused new password (policy, reuse) does not burn the handle.
// Returns the user it belongs to, the sign-in's remember-me choice and
// whether the handle carries a verified passkey proof. A passkey proof is
// valid only with the secret of the client it was minted for (binding,
// compared in constant time); any other client is refused as an invalid
// handle, before anything changes (OSS-G8-PASSKEY-MFA-R2). binding is
// ignored for an ordinary handle.
func (s *MFAEnrollmentService) PeekPasswordChange(ctx context.Context, pendingID uuid.UUID, binding string) (PendingPasswordChange, error) {
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
	passkey := kind == domain.MFAPendingKindPasswordChangePasskeyUV
	if passkey {
		sum := sha256.Sum256([]byte(binding))
		if len(row.ClientBinding) != sha256.Size || binding == "" || subtle.ConstantTimeCompare(sum[:], row.ClientBinding) != 1 {
			return PendingPasswordChange{}, ErrMFAEnrollmentInvalid
		}
	}
	return PendingPasswordChange{UserID: row.UserID, RememberMe: row.RememberMe, PasskeyVerified: passkey}, nil
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
