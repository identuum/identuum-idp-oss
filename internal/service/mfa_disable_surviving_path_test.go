package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// The enrollment stub handles MFA fields only. Honor EmailVerified as well so
// these tests observe an accidental write to it, just as persistent storage does.
type disarmPreservationUserRepo struct {
	*stubUserRepoForMFAEnroll
}

func (r disarmPreservationUserRepo) Update(ctx context.Context, id, orgID uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	u, err := r.stubUserRepoForMFAEnroll.Update(ctx, id, orgID, opts)
	if err == nil && opts.EmailVerified != nil {
		r.byID[id].EmailVerified = *opts.EmailVerified
		u.EmailVerified = *opts.EmailVerified
	}
	return u, err
}

func TestMFAEnrollment_DisableSelfWithProof_PreservesEmailVerified(t *testing.T) {
	for _, proof := range []string{"totp", "recovery_code"} {
		t.Run(proof, func(t *testing.T) {
			svc, _, users, user := newEnrollSvc(t)
			seed := regenerateSeedForTest(t)
			seedEnrolledOrgUser(users, user, seed, []string{"REC-A", "REC-B"})
			user.EmailVerified = true
			svc.users = disarmPreservationUserRepo{users}
			code := "REC-A"
			if proof == "totp" {
				code = regenerateTOTPForTest(t, svc, seed)
			}
			if _, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Code: code}); err != nil {
				t.Fatalf("disable: %v", err)
			}
			if !users.byID[user.ID].EmailVerified {
				t.Error("successful disarm cleared EmailVerified")
			}
		})
	}
}

func TestMFAEnrollment_DisableSelfWithProof_ClearsTOTPEnrollment(t *testing.T) {
	svc, _, users, user := newEnrollSvc(t)
	seed := regenerateSeedForTest(t)
	seedEnrolledOrgUser(users, user, seed, []string{"REC-A", "REC-B"})
	code := regenerateTOTPForTest(t, svc, seed)
	if _, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Code: code}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	stored := users.byID[user.ID]
	if stored.MFASecret == nil || *stored.MFASecret != "" {
		t.Error("TOTP disarm must leave a non-nil, empty MFASecret")
	}
	if len(stored.MFARecoveryCodes) != 0 {
		t.Error("TOTP disarm must empty MFARecoveryCodes")
	}
}

func TestMFAEnrollment_DisableSelfWithProof_InvalidUserErrorIdentity(t *testing.T) {
	for _, state := range []string{"nil_id", "unknown_user", "banned", "deleted"} {
		t.Run(state, func(t *testing.T) {
			svc, _, _, user := newEnrollSvc(t)
			id := user.ID
			switch state {
			case "nil_id":
				id = uuid.Nil
			case "unknown_user":
				id = uuid.New()
			case "banned":
				user.Banned = true
			case "deleted":
				now := time.Now()
				user.DeletedAt = &now
			}
			_, err := svc.DisableSelfWithProof(context.Background(), id, MFADisableSelfInput{Code: "000000"})
			if !errors.Is(err, ErrMFAEnrollmentInvalid) {
				t.Errorf("disarm error = %v; want ErrMFAEnrollmentInvalid", err)
			}
		})
	}
}
