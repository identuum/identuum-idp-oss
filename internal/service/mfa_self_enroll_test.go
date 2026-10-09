package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
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

func selfEnrollCode(t *testing.T, svc *MFAEnrollmentService, secret string) string {
	t.Helper()
	code, err := computeHOTP(secret, uint64(svc.now().Unix())/defaultTOTPPeriod, defaultTOTPDigits)
	if err != nil {
		t.Fatalf("computeHOTP: %v", err)
	}
	return code
}

// OSS-HARDEN-1 item 2: the enrolment lives in the database, so a new service
// instance (a restarted process) completes an enrolment the old one started.
func TestMFASelfEnroll_CompletesAfterARestart(t *testing.T) {
	ctx := context.Background()
	svc, pendingRepo, userRepo, user := newEnrollSvc(t)
	user.PasswordHash = "HASH-CURRENT-PASSWORD"
	start, err := svc.InitiateSelf(ctx, user.ID, "correct-current-password")
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	restarted := NewMFAEnrollmentService(nil, MFAEnrollmentRepoOptions{
		Pending: pendingRepo, Users: userRepo, Issuer: "Identuum", Cipher: identityMFACipher{}, Replay: testReplayGuard(t),
	}, MFAEnrollmentServiceOptions{})
	restarted.now = svc.now
	codes, err := restarted.CompleteSelf(ctx, user.ID, selfEnrollCode(t, restarted, start.Secret))
	if err != nil || len(codes) == 0 {
		t.Fatalf("complete on a new instance: %d code(s), err=%v; want recovery codes", len(codes), err)
	}
}

// OSS-HARDEN-1 item 2 keeps FUNC-M1's rules: the newest initiate wins, a wrong
// code leaves the enrolment open, and an expired or used one is not started.
func TestMFASelfEnroll_NewestWinsWrongCodesKeepItOpenSpentOnesAreGone(t *testing.T) {
	ctx := context.Background()
	svc, pendingRepo, _, user := newEnrollSvc(t)
	user.PasswordHash = "HASH-CURRENT-PASSWORD"
	first, err := svc.InitiateSelf(ctx, user.ID, "correct-current-password")
	if err != nil {
		t.Fatalf("first initiate: %v", err)
	}
	second, err := svc.InitiateSelf(ctx, user.ID, "correct-current-password")
	if err != nil {
		t.Fatalf("second initiate: %v", err)
	}
	if _, err := svc.CompleteSelf(ctx, user.ID, selfEnrollCode(t, svc, first.Secret)); !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("the first secret's code: err=%v; want ErrMFAEnrollmentInvalid (the newest initiate wins)", err)
	}
	if _, err := svc.CompleteSelf(ctx, user.ID, wrongCodeForWindow(t, second.Secret, svc.now())); !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("a wrong code: err=%v; want ErrMFAEnrollmentInvalid", err)
	}
	if codes, err := svc.CompleteSelf(ctx, user.ID, selfEnrollCode(t, svc, second.Secret)); err != nil || len(codes) == 0 {
		t.Fatalf("the newest secret's code after wrong ones: err=%v; want recovery codes", err)
	}

	for name, spend := range map[string]func(row *domain.MFAPendingLoginSession){
		"expired": func(row *domain.MFAPendingLoginSession) { row.ExpiresAt = svc.now().Add(-time.Minute) },
		"used":    func(row *domain.MFAPendingLoginSession) { at := svc.now(); row.ConsumedAt = &at },
	} {
		s, rows, _, target := newEnrollSvc(t)
		target.PasswordHash = "HASH-CURRENT-PASSWORD"
		start, err := s.InitiateSelf(ctx, target.ID, "correct-current-password")
		if err != nil {
			t.Fatalf("%s: initiate: %v", name, err)
		}
		for _, row := range rows.rows {
			spend(row)
		}
		if _, err := s.CompleteSelf(ctx, target.ID, selfEnrollCode(t, s, start.Secret)); !errors.Is(err, ErrMFASelfNotStarted) {
			t.Fatalf("%s: err=%v; want ErrMFASelfNotStarted", name, err)
		}
	}
	_ = pendingRepo
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
