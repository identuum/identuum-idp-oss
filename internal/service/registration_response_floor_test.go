package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// A new address writes the account and its registration state; a taken one
// skips both. The answer therefore waits out a fixed floor on every path, so
// its time does not say which addresses have accounts. Only the password
// policy refusal, which answers differently anyway, does not wait.

type newAddress struct{ registrationUsers }

func (newAddress) FindUsersByEmail(context.Context, string) ([]*domain.User, error) { return nil, nil }

type createsUser struct{}

func (createsUser) Create(_ context.Context, o CreateUserOptions) (*domain.User, error) {
	return &domain.User{ID: uuid.New(), Email: o.Email, OrganizationID: o.OrganizationID}, nil
}

type recordsState struct{ openRegistrationRepo }

func (recordsState) SetUserState(context.Context, uuid.UUID, string) error {
	return nil
}

func floorRegistration(users registrationUsers) (*RegistrationService, *[]time.Duration, *time.Time) {
	org := &domain.Organization{ID: uuid.New(), Name: "Acme", Active: true}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	var slept []time.Duration
	svc := NewRegistrationService(RegistrationServiceConfig{
		Repo: recordsState{}, Orgs: oneOrg{org}, Users: users, Creator: createsUser{},
	}).WithClock(func() time.Time { return now }, func(d time.Duration) { slept = append(slept, d) })
	return svc, &slept, &now
}

func TestRegister_EveryAnswerWaitsOutTheSameFloor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		users registrationUsers
	}{{"a taken address", takenAddress{}}, {"a new address", newAddress{}}} {
		svc, slept, _ := floorRegistration(tc.users)
		if err := svc.Register(context.Background(), "acme", takenRegistration); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(*slept) != 1 || (*slept)[0] != registrationResponseFloor {
			t.Errorf("%s: waited %v, want one wait of %s", tc.name, *slept, registrationResponseFloor)
		}
	}

	svc, slept, _ := floorRegistration(newAddress{})
	if err := svc.Register(context.Background(), "acme", RegisterInput{Email: "a@example.test", Password: "short"}); err == nil {
		t.Fatal("a password the policy refuses was accepted")
	}
	if len(*slept) != 0 {
		t.Errorf("the policy refusal waited %v, want no wait", *slept)
	}
}
