package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// The routes that must not reveal whether an address has an account (password
// reset, verification resend, self-registration) answer the same wire body either
// way, but a response that waits for the mail, or for a hash only a new account
// needs, tells them apart by its time. The account-dependent work runs after the
// response, and an existing address spends the hashing time a new one does.

// heldNotifier blocks every send until released and says when one arrived.
type heldNotifier struct {
	release chan struct{}
	sent    chan struct{}
	once    sync.Once
}

func newHeldNotifier() *heldNotifier {
	return &heldNotifier{release: make(chan struct{}), sent: make(chan struct{})}
}

func (h *heldNotifier) send() error {
	<-h.release
	h.once.Do(func() { close(h.sent) })
	return nil
}

func (h *heldNotifier) SendPasswordResetEmail(context.Context, *domain.User, string) error {
	return h.send()
}
func (h *heldNotifier) SendVerificationEmail(context.Context, *domain.User, string) error {
	return h.send()
}
func (h *heldNotifier) SendRegistrationNoticeEmail(context.Context, string, string) error {
	return h.send()
}

// returnsWhileTheMailIsHeld runs call with the mail held, requires it to return,
// then releases the mail and requires it to be sent.
func returnsWhileTheMailIsHeld(t *testing.T, n *heldNotifier, call func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { call(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(n.release)
		t.Fatal("the response waited for the mail to be sent")
	}
	close(n.release)
	select {
	case <-n.sent:
	case <-time.After(5 * time.Second):
		t.Fatal("the mail was never sent")
	}
}

func TestRequestPasswordReset_DoesNotWaitForTheMail(t *testing.T) {
	user := newPasswordResetUser(t, "known@example.test")
	n := newHeldNotifier()
	svc := NewPasswordResetService(PasswordResetServiceConfig{
		Users: newFakeUserRepo(user), Resets: newFakePasswordResetRepo(), Notifier: n,
		Audit: &fakeAuditRecorder{}, HumanFacingBaseURL: "https://ui.example.test", Now: time.Now,
	}).WithBackground(RunDetached)
	returnsWhileTheMailIsHeld(t, n, func() {
		_ = svc.RequestPasswordReset(context.Background(), "known@example.test", "ip", "ua")
	})
}

func TestResendVerification_DoesNotWaitForTheMail(t *testing.T) {
	user := newPasswordResetUser(t, "fresh@example.test")
	user.EmailVerified = false
	n := newHeldNotifier()
	svc := NewEmailVerificationService(newFakeUserRepo(user), newFakeEmailVerificationRepo(), n, &fakeAuditRecorder{},
		EmailVerificationServiceOptions{Now: time.Now}).WithBackground(RunDetached)
	returnsWhileTheMailIsHeld(t, n, func() {
		_ = svc.ResendVerification(context.Background(), "fresh@example.test")
	})
}

// openRegistrationRepo answers: sign-up is on for every organization.
type openRegistrationRepo struct {
	repository.RegistrationRepository
}

func (openRegistrationRepo) InstanceEnabled(context.Context) (bool, error) { return true, nil }
func (openRegistrationRepo) OrgSettings(context.Context, uuid.UUID) (*domain.OrgRegistrationSettings, error) {
	return &domain.OrgRegistrationSettings{Allow: true}, nil
}

type oneOrg struct{ org *domain.Organization }

func (o oneOrg) GetBySlug(context.Context, string) (*domain.Organization, error) { return o.org, nil }

type takenAddress struct{ registrationUsers }

func (takenAddress) FindUsersByEmail(context.Context, string) ([]*domain.User, error) {
	return []*domain.User{{ID: uuid.New(), Email: "taken@example.test"}}, nil
}

func registrationOfATakenAddress(n RegistrationNotifier) *RegistrationService {
	org := &domain.Organization{ID: uuid.New(), Name: "Acme", Active: true}
	return NewRegistrationService(RegistrationServiceConfig{
		Repo: openRegistrationRepo{}, Orgs: oneOrg{org}, Users: takenAddress{}, Notifier: n,
	}).WithBackground(RunDetached)
}

var takenRegistration = RegisterInput{Email: "taken@example.test", Password: "correct-horse-battery-9", Name: "T"}

func TestRegister_ATakenAddressDoesNotWaitForTheNotice(t *testing.T) {
	n := newHeldNotifier()
	svc := registrationOfATakenAddress(n)
	returnsWhileTheMailIsHeld(t, n, func() {
		_ = svc.Register(context.Background(), "acme", takenRegistration)
	})
}

// A new address pays for hashing the password; a taken one must cost the same,
// or the response time says which addresses have accounts.
func TestRegister_ATakenAddressSpendsTheHashingTimeANewOneDoes(t *testing.T) {
	n := newHeldNotifier()
	close(n.release)
	svc := registrationOfATakenAddress(n)

	start := time.Now()
	if _, err := crypto.GenerateHash([]byte(takenRegistration.Password)); err != nil {
		t.Fatalf("GenerateHash: %v", err)
	}
	oneHash := time.Since(start)

	start = time.Now()
	_ = svc.Register(context.Background(), "acme", takenRegistration)
	took := time.Since(start)
	if took < oneHash/2 {
		t.Errorf("a taken address answered in %s; a hash alone takes %s, so the answer is cheaper than a new account's", took, oneHash)
	}
}
