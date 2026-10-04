package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ServiceAccountOrgLookup resolves the organization a service account belongs to.
type ServiceAccountOrgLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error)
}

// ServiceAccountTokenLiveness returns the check the bearer middleware applies
// to a service-account token, whose subject is the account's id: the account
// exists, is active and unexpired, and its organization is operational. A
// token with no session is not covered by the session gate, so without this a
// disabled account or a deactivated organization kept working until the token
// expired. A subject that is not an account id, or a store that cannot answer,
// is not live: the second is returned as the store class so the wire answer is
// 503, never an admission.
func ServiceAccountTokenLiveness(sas *ServiceAccountService, orgs ServiceAccountOrgLookup) func(ctx context.Context, subject string) (bool, error) {
	return func(ctx context.Context, subject string) (bool, error) {
		id, err := uuid.Parse(subject)
		if err != nil || id == uuid.Nil {
			return false, nil
		}
		sa, err := sas.repo.GetByID(ctx, id)
		if err != nil {
			if errors.Is(err, domain.ErrServiceAccountNotFound) {
				return false, nil
			}
			return false, domain.AuthStoreUnavailable("service_account.liveness", err)
		}
		if sa == nil || !sa.Active {
			return false, nil
		}
		if sa.ExpiresAt != nil && !sa.ExpiresAt.After(sas.now()) {
			return false, nil
		}
		org, err := orgs.GetByID(ctx, sa.OrganizationID)
		if err != nil {
			if errors.Is(err, domain.ErrOrganizationNotFound) {
				return false, nil
			}
			return false, domain.AuthStoreUnavailable("organization.liveness", fmt.Errorf("service: service account organization: %w", err))
		}
		return org != nil && org.IsOperational(), nil
	}
}
