package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// stubSABindingValidator satisfies ServiceAccountBindingValidator
// so the ClientService binding gates can be exercised without a
// real ServiceAccountService.
type stubSABindingValidator struct {
	want error
	saw  []uuid.UUID
}

func (s *stubSABindingValidator) ValidateBindingForClient(_ context.Context, saID uuid.UUID, _ *uuid.UUID) error {
	s.saw = append(s.saw, saID)
	return s.want
}

// ---------- RegisterClient binding gates ----------

func TestRegisterClient_PublicClientCannotBindSA(t *testing.T) {
	saID := uuid.New()
	svc := NewClientService(nil, newClientRepo())
	_, _, err := svc.RegisterClient(context.Background(), RegisterClientOptions{
		Name:             "x",
		RedirectURIs:     []string{"https://app.example.com/cb"},
		IsPublic:         true,
		ServiceAccountID: &saID,
	})
	// THE-MIRROR: the refusal now fires in Client.Validate (the full-document
	// check prepareClient runs), one step before RegisterClient's own binding
	// gate — same refusal, earlier and with the domain message.
	if err == nil || !strings.Contains(err.Error(), "service account") {
		t.Errorf("err = %v, want a public-client/service-account refusal", err)
	}
}

func TestRegisterClient_BindingValidatorRejectsCrossOrg(t *testing.T) {
	saID := uuid.New()
	validator := &stubSABindingValidator{want: ErrServiceAccountOrgMismatch}
	svc := NewClientService(nil, newClientRepo()).WithServiceAccountBindingValidator(validator)
	orgID := uuid.New()
	_, _, err := svc.RegisterClient(context.Background(), RegisterClientOptions{
		Name:             "x",
		RedirectURIs:     []string{"https://app.example.com/cb"},
		OrganizationID:   &orgID,
		ServiceAccountID: &saID,
	})
	if !errors.Is(err, ErrServiceAccountOrgMismatch) {
		t.Errorf("err = %v", err)
	}
	if len(validator.saw) != 1 || validator.saw[0] != saID {
		t.Errorf("validator was not called with SA id: %+v", validator.saw)
	}
}

func TestRegisterClient_BindingValidatorAcceptsActiveSA(t *testing.T) {
	saID := uuid.New()
	validator := &stubSABindingValidator{want: nil}
	svc := NewClientService(nil, newClientRepo()).WithServiceAccountBindingValidator(validator)
	_, _, err := svc.RegisterClient(context.Background(), RegisterClientOptions{
		Name:             "x",
		RedirectURIs:     []string{"https://app.example.com/cb"},
		ServiceAccountID: &saID,
	})
	if err != nil {
		t.Errorf("err = %v", err)
	}
}

// ---------- UpdateClient binding semantics ----------

func TestUpdateClient_ExplicitUnbind(t *testing.T) {
	saID := uuid.New()
	repo := newClientRepo()
	svc := NewClientService(nil, repo)
	c, _, err := svc.RegisterClient(context.Background(), RegisterClientOptions{
		Name:             "x",
		RedirectURIs:     []string{"https://app.example.com/cb"},
		ServiceAccountID: &saID,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	nilID := uuid.Nil
	updated, err := svc.UpdateClient(context.Background(), c.ID, UpdateClientOptions{
		ServiceAccountID: &nilID,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.ServiceAccountID != nil {
		t.Errorf("client still bound after explicit unbind: %v", updated.ServiceAccountID)
	}
}

func TestUpdateClient_BindingValidatorRejectsInactiveSA(t *testing.T) {
	saID := uuid.New()
	repo := newClientRepo()
	svc := NewClientService(nil, repo)
	c, _, _ := svc.RegisterClient(context.Background(), RegisterClientOptions{
		Name:         "x",
		RedirectURIs: []string{"https://app.example.com/cb"},
	})
	validator := &stubSABindingValidator{want: ErrServiceAccountInactive}
	svc = svc.WithServiceAccountBindingValidator(validator)
	_, err := svc.UpdateClient(context.Background(), c.ID, UpdateClientOptions{
		ServiceAccountID: &saID,
	})
	if !errors.Is(err, ErrServiceAccountInactive) {
		t.Errorf("err = %v", err)
	}
}
