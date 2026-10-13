package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// O8 (OSS-0913-A, D10): ValidateBindingForClient decides visibility FIRST,
// like RecheckLockedBinding. A service account of ANOTHER organization answers
// ErrServiceAccountOrgMismatch whatever its state, so a cross-org caller cannot
// learn whether that account is inactive or expired.
func TestValidateBindingForClient_CrossOrgProbeLearnsNoState(t *testing.T) {
	ctx := context.Background()
	saOrg := uuid.New()
	saID := uuid.New()
	callerOrg := uuid.New()
	past := time.Now().Add(-time.Hour)
	for _, c := range []struct {
		name   string
		active bool
		exp    *time.Time
	}{
		{"inactive account of another organization", false, nil},
		{"expired account of another organization", true, &past},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := NewServiceAccountService(nil, saBindRepo{sa: &domain.ServiceAccount{
				ID: saID, OrganizationID: saOrg, Active: c.active, ExpiresAt: c.exp,
			}})
			err := s.ValidateBindingForClient(ctx, saID, &callerOrg)
			if !errors.Is(err, ErrServiceAccountOrgMismatch) {
				t.Fatalf("O8: a cross-org binding must answer ErrServiceAccountOrgMismatch before any state check, got %v", err)
			}
		})
	}
}
