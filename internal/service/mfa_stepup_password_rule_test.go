package service

import (
	"context"
	"errors"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// stepUpUserRepo is a UserRepository whose VerifyPassword outcome is controlled.
type stepUpUserRepo struct {
	repository.UserRepository
	verifyErr error
}

func (r stepUpUserRepo) VerifyPassword(context.Context, string, string) error { return r.verifyErr }

// verifyCurrentPasswordForStepUp accepts a step-up proof ONLY when the user is a
// local-auth account with a stored password hash and the supplied password
// verifies against it: a wrong password, a federated (non-local) user, an
// empty password, or a hash-less account is refused with ErrMFADisableInvalidCode.
// RULE: MFA-STEPUP-PASSWORD-1
func TestVerifyCurrentPasswordForStepUp(t *testing.T) {
	ctx := context.Background()
	local := &domain.User{AuthSource: domain.AuthSourceLocal, PasswordHash: "$argon2id$stored"}

	// Correct password on a local account passes.
	pass := &MFAEnrollmentService{users: stepUpUserRepo{}}
	if err := pass.verifyCurrentPasswordForStepUp(ctx, local, "correct-pw"); err != nil {
		t.Fatalf("a matching current password on a local account must pass, got %v", err)
	}

	// Wrong password fails.
	wrong := &MFAEnrollmentService{users: stepUpUserRepo{verifyErr: errors.New("mismatch")}}
	if err := wrong.verifyCurrentPasswordForStepUp(ctx, local, "wrong-pw"); err == nil {
		t.Errorf("a wrong current password must fail step-up")
	}

	// A federated (non-local) user cannot step up via password.
	fed := &domain.User{AuthSource: "oidc", PasswordHash: "$argon2id$stored"}
	if err := pass.verifyCurrentPasswordForStepUp(ctx, fed, "correct-pw"); err == nil {
		t.Errorf("a federated user must not step up via password")
	}

	// An empty password is refused before any verify.
	if err := pass.verifyCurrentPasswordForStepUp(ctx, local, "   "); err == nil {
		t.Errorf("an empty password must fail step-up")
	}
}
