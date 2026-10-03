package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// An activation link is re-sent only to an org_admin who never activated. An
// organization whose admin already activated (verified) — for example one a
// site_admin deactivated later — gets no new activation link.
func TestResendActivationToken_AdminAlreadyActivatedRefused(t *testing.T) {
	orgID := uuid.New()
	org := &domain.Organization{ID: orgID, Name: "Deactivated", Active: false}
	admin := &domain.User{ID: uuid.New(), OrganizationID: orgID, Email: "admin@x.test", Role: domain.RoleOrgAdmin, EmailVerified: true}
	svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
		Users: newFakeUserRepo(admin), Orgs: newFakeOrgRepo(org), OrgsAdmin: newFakeOrgRepo(org), Audit: audit.NoopService{},
	})
	if _, _, _, err := svc.ResendActivationToken(context.Background(), orgID); !errors.Is(err, ErrOrganizationActivationAdminActivated) {
		t.Errorf("resend for an already-activated admin: err=%v, want ErrOrganizationActivationAdminActivated", err)
	}
	if admin.ActivationTokenHash != nil {
		t.Error("no activation token may be stored on an already-activated admin")
	}
}
