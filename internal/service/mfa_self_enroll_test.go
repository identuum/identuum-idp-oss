package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// FUNC-M1: the self-enrolment password proof spends the per-user proof budget,
// and past it even the right password gets sign-in's wait answer.
func TestMFASelfEnroll_WrongPasswordsSpendTheProofBudget(t *testing.T) {
	ctx := context.Background()
	svc, _, _, user := newEnrollSvc(t)
	svc.proofFailures = NewTOTPFailureBudget(3, 15*time.Minute, nil)
	user.PasswordHash = "HASH-CURRENT-PASSWORD"

	for i := 0; i < 3; i++ {
		if _, err := svc.InitiateSelf(ctx, user.ID, "wrong"); !errors.Is(err, ErrMFASelfProofInvalid) {
			t.Fatalf("wrong password %d: err=%v; want ErrMFASelfProofInvalid", i, err)
		}
	}
	_, err := svc.InitiateSelf(ctx, user.ID, "correct-current-password")
	var th *LoginThrottledError
	if !errors.As(err, &th) || th.RetryAfter <= 0 {
		t.Fatalf("the right password past the budget: err=%v; want a LoginThrottledError with a wait", err)
	}
}

// FUNC-M1: complete finds only the caller's own enrolment; another user's
// open enrolment is not theirs to finish.
func TestMFASelfEnroll_CompleteIsTheCallersOwn(t *testing.T) {
	ctx := context.Background()
	svc, _, userRepo, user := newEnrollSvc(t)
	user.PasswordHash = "HASH-CURRENT-PASSWORD"
	if _, err := svc.InitiateSelf(ctx, user.ID, "correct-current-password"); err != nil {
		t.Fatalf("initiate: %v", err)
	}
	other := *user
	other.ID = uuid.New()
	userRepo.byID[other.ID] = &other
	if _, err := svc.CompleteSelf(ctx, other.ID, "123456"); !errors.Is(err, ErrMFASelfNotStarted) {
		t.Fatalf("another user completing: err=%v; want ErrMFASelfNotStarted", err)
	}
	if _, err := svc.CompleteSelf(ctx, user.ID, "000000x"); !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("a wrong code: err=%v; want ErrMFAEnrollmentInvalid", err)
	}
}
