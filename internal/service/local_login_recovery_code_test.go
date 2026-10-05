package service

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// FUNC-H3 (audits/oss-functionality-2026-10-05.md): the recovery-codes page
// says "Each code can be used once to sign in if you lose access to your
// authenticator app". The browser sign-in page /authorize sends people to
// (and the JSON sign-in with an inline code) asks for the code in one form
// and checked it as TOTP only, so a recovery code never signed anyone in.
// The user store here is the production shape: it burns a code by its hash.

type recoveryUserStore struct {
	mu   sync.Mutex
	user *domain.User
}

func (s *recoveryUserStore) FindUsersByEmail(_ context.Context, email string) ([]*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user == nil || s.user.Email != email {
		return nil, nil
	}
	u := *s.user
	return []*domain.User{&u}, nil
}

func (s *recoveryUserStore) ConsumeRecoveryCode(_ context.Context, id uuid.UUID, codeHash string) (*domain.User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user == nil || s.user.ID != id {
		return nil, false, nil
	}
	i := slices.Index(s.user.MFARecoveryCodes, codeHash)
	if i < 0 {
		return nil, false, nil
	}
	s.user.MFARecoveryCodes = slices.Delete(slices.Clone(s.user.MFARecoveryCodes), i, i+1)
	u := *s.user
	return &u, true, nil
}

// The runtime hands NewLocalLoginService the user repository; it must be a
// RecoveryCodeConsumer or the code step silently stays TOTP only.
var _ RecoveryCodeConsumer = repository.UserRepository(nil)

const recoveryTestCode = "ABCDEFGHIJKLMNOP"

func newRecoveryLogin(t *testing.T) (*LocalLoginService, *recoveryUserStore) {
	t.Helper()
	secret, err := generateBase32Secret(20)
	if err != nil {
		t.Fatal(err)
	}
	store := &recoveryUserStore{user: &domain.User{
		ID: uuid.New(), Email: "alice@example.com", PasswordHash: hashPwd(t, "correct"),
		EmailVerified: true, Role: domain.RoleOrgAdmin, OrganizationID: uuid.New(),
		MFAEnabled: true, MFASecret: &secret,
		MFARecoveryCodes: []string{crypto.HashSecret("ZZZZZZZZZZZZZZZZ"), crypto.HashSecret(recoveryTestCode)},
	}}
	sessions := NewUserSessionService(nil, newSessionRepo(), UserSessionServiceOptions{DefaultTTL: time.Hour})
	mfa := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Replay: testReplayGuard(t)})
	return NewLocalLoginService(nil, store, sessions, mfa), store
}

func TestLogin_RecoveryCodeCompletesTheCodeStepOnce(t *testing.T) {
	svc, store := newRecoveryLogin(t)
	rec := &audit.Recorder{}
	svc.WithAudit(rec)
	in := LoginInput{Email: "alice@example.com", Password: "correct", TOTPCode: recoveryTestCode}
	result, err := svc.Login(context.Background(), in)
	if err != nil {
		t.Fatalf("sign-in with a recovery code: %v; want a session", err)
	}
	if result.Session == nil || result.RefreshToken == "" {
		t.Fatal("sign-in with a recovery code created no session")
	}
	if got := len(store.user.MFARecoveryCodes); got != 1 {
		t.Errorf("recovery codes left = %d; want 1 (the used one burned, the other kept)", got)
	}
	var recorded bool
	for _, e := range rec.Events() {
		if e.Action == "user_session.login.mfa_recovery_code_consumed" && e.Metadata["remaining_recovery_codes_count"] == 1 {
			recorded = true
		}
	}
	if !recorded {
		t.Error("no mfa_recovery_code_consumed audit event with the remaining count")
	}
	if _, err := svc.Login(context.Background(), in); !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Errorf("the same recovery code a second time: err = %v; want invalid credentials", err)
	}
}

// A recovery code at the code step counts against the same wrong-code budget
// as a TOTP code: wrong ones are recorded, and past the budget even a right
// one is refused and not burned.
func TestVerifySignIn_RecoveryCodesShareTheWrongCodeBudget(t *testing.T) {
	ctx := context.Background()
	frozen := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	budget := NewTOTPFailureBudget(3, 15*time.Minute, func() time.Time { return frozen })
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Replay: testReplayGuard(t), Failures: budget})
	svc.now = func() time.Time { return frozen }
	_, store := newRecoveryLogin(t)
	user := store.user
	for i := 0; i < 3; i++ {
		if used, _, err := svc.VerifySignIn(ctx, user, "QQQQQQQQQQQQQQQQ", store); used || !errors.Is(err, ErrMFAInvalid) {
			t.Fatalf("wrong recovery code %d: used=%v err=%v; want ErrMFAInvalid", i, used, err)
		}
	}
	if used, _, err := svc.VerifySignIn(ctx, user, recoveryTestCode, store); used || !errors.Is(err, ErrMFAInvalid) {
		t.Errorf("right recovery code past the budget: used=%v err=%v; want ErrMFAInvalid", used, err)
	}
	if got := len(store.user.MFARecoveryCodes); got != 2 {
		t.Errorf("recovery codes left = %d; want 2 (a refused code is not burned)", got)
	}
	// Step-up and the other proofs keep Verify: a recovery code is no TOTP.
	_, store2 := newRecoveryLogin(t)
	if err := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Replay: testReplayGuard(t)}).Verify(ctx, store2.user, recoveryTestCode); err == nil {
		t.Error("Verify accepted a recovery code")
	}
}

func TestLogin_WrongRecoveryCodeIsRefused(t *testing.T) {
	svc, store := newRecoveryLogin(t)
	_, err := svc.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "correct", TOTPCode: "QQQQQQQQQQQQQQQQ"})
	if !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Errorf("wrong recovery code: err = %v; want invalid credentials", err)
	}
	if got := len(store.user.MFARecoveryCodes); got != 2 {
		t.Errorf("recovery codes left = %d; want 2 (nothing burned)", got)
	}
}
