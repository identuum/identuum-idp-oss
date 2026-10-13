package service

import (
	"context"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// The pre-check does not see a banned account or an account of an inactive
// organization, so the database's refusal of the address (0056) reaches the
// create. That answer is the existing-address path, notice mail included.

type refusesTakenAddress struct{}

func (refusesTakenAddress) Create(context.Context, CreateUserOptions) (*domain.User, error) {
	return nil, domain.ErrUserAlreadyExists
}

func TestRegister_AnAddressTheDatabaseRefusesGetsTheNotice(t *testing.T) {
	n := newHeldNotifier()
	svc := NewRegistrationService(RegistrationServiceConfig{
		Repo: openRegistrationRepo{}, Orgs: oneOrg{&domain.Organization{Name: "Acme", Active: true}},
		Users: newAddress{}, Creator: refusesTakenAddress{}, Notifier: n,
	}).WithBackground(RunDetached)
	returnsWhileTheMailIsHeld(t, n, func() {
		_ = svc.Register(context.Background(), "acme", takenRegistration)
	})
}
