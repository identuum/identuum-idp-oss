package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
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

func (s *stubSABindingValidator) RecheckLockedBinding(*domain.ServiceAccount, *uuid.UUID) error {
	return nil
}

// OSS-0912-C1-FIX: the re-check under the save's lock refuses a gone,
// foreign, inactive or expired account with a plain reason, and answers a
// foreign account exactly as a gone one, whatever its state.
func TestRecheckLockedBinding_VisibilityFirst(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	svc := &ServiceAccountService{now: func() time.Time { return now }}
	org, other := uuid.New(), uuid.New()
	past := now.Add(-time.Minute)
	for _, tc := range []struct {
		name string
		sa   *domain.ServiceAccount
		want string
	}{
		{"gone", nil, "the service account was not found; nothing was saved, reload the client and try again"},
		{"foreign_inactive", &domain.ServiceAccount{OrganizationID: other}, "the service account was not found; nothing was saved, reload the client and try again"},
		{"inactive", &domain.ServiceAccount{OrganizationID: org}, "the service account was deactivated; nothing was saved, reload the client and try again"},
		{"expired", &domain.ServiceAccount{OrganizationID: org, Active: true, ExpiresAt: &past}, "the service account has expired; nothing was saved, reload the client and try again"},
		{"live", &domain.ServiceAccount{OrganizationID: org, Active: true}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.RecheckLockedBinding(tc.sa, &org)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("a live account of the client's organization was refused: %v", err)
				}
				return
			}
			if err == nil || err.Error() != tc.want || !errors.Is(err, ErrServiceAccountChangedDuringSave) {
				t.Fatalf("got %v, want %q wrapping ErrServiceAccountChangedDuringSave", err, tc.want)
			}
		})
	}
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
	// THE-MIRROR moved this refusal into Client.Validate (the full-document
	// check prepareClient runs), one step before RegisterClient's own binding
	// gate. THE-INCONSISTENT-DOCUMENT restores the EXACT pin: a substring
	// proved only that some error mentioned service accounts; the message is
	// part of what this test exists to hold still.
	if err == nil || err.Error() != "public client cannot be linked to a service account" {
		t.Errorf("err = %v, want the exact domain refusal", err)
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
