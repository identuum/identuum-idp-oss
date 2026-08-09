package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// OrganizationProtocolSettingsService is the OSS service layer
// for per-organization DCR + SCIM toggle configuration.
//
// The service implements two distinct callers:
//
//   - The HTTP handler-side gate. When a DCR or SCIM request
//     resolves to a specific organization, the handler calls
//     IsFeatureEnabledForOrg(orgID, feature) and 403s with the
//     standard envelope when the answer is false. The system
//     default for an absent row is "both false" — a tenant must
//     explicitly opt in via the org admin update API.
//
//   - The admin-facing org update path. The
//     /api/v1/organizations admin surface (and a future org_admin
//     self-service surface) call SetForOrg to flip a tenant's
//     toggles via the standard Upsert.
type OrganizationProtocolSettingsService struct {
	repo repository.OrganizationProtocolSettingsRepository
}

// NewOrganizationProtocolSettingsService builds the service.
// repo MUST be non-nil; passing nil is a bootstrap bug.
func NewOrganizationProtocolSettingsService(report *lifecycle.StartupReport, repo repository.OrganizationProtocolSettingsRepository) *OrganizationProtocolSettingsService {
	if repo == nil {
		report.Fatal("NewOrganizationProtocolSettingsService", "service: NewOrganizationProtocolSettingsService requires a non-nil repository")
	}
	return &OrganizationProtocolSettingsService{repo: repo}
}

// Feature keys consulted by the handler gate. These are the OSS
// foundation keys whose availability is per-org; they are
// distinct from the wire-shape `features.DynamicClientRegistration`
// / `features.SCIM` constants (which name the CE-side runtime
// entitlement check). The OSS handler gate uses these per-org
// keys; the CE-side runtime uses the global features.* keys to
// gate the advanced enterprise stack layered on top.
const (
	OrgFeatureDynamicClientRegistration = "dynamic_client_registration"
	OrgFeatureSCIM                      = "scim"
)

// GetEffective returns the effective settings for orgID. An
// absent row resolves to the system default: both booleans
// false. Other repository errors propagate to the caller.
//
// GetEffective never returns nil; callers can dereference the
// result unconditionally.
func (s *OrganizationProtocolSettingsService) GetEffective(ctx context.Context, orgID uuid.UUID) (*domain.OrganizationProtocolSettings, error) {
	if orgID == uuid.Nil {
		return &domain.OrganizationProtocolSettings{OrganizationID: orgID}, nil
	}
	row, err := s.repo.GetByOrgID(ctx, orgID)
	if err == nil {
		return row, nil
	}
	if errors.Is(err, repository.ErrOrganizationProtocolSettingsNotFound) {
		// Absent row → system default (both disabled). Document the
		// alignment: the migration's DEFAULT FALSE on both columns
		// and this fallback are deliberately the same value so an
		// operator never has to reason about a "table empty vs row
		// missing" distinction.
		return &domain.OrganizationProtocolSettings{OrganizationID: orgID}, nil
	}
	return nil, err
}

// IsFeatureEnabledForOrg is the canonical handler-side gate.
// Returns true ONLY when the per-org row exists AND the named
// feature is enabled. Unknown features return false (defensive
// fail-closed; only the two named constants above are honoured).
func (s *OrganizationProtocolSettingsService) IsFeatureEnabledForOrg(ctx context.Context, orgID uuid.UUID, feature string) (bool, error) {
	row, err := s.GetEffective(ctx, orgID)
	if err != nil {
		return false, err
	}
	switch feature {
	case OrgFeatureDynamicClientRegistration:
		return row.DCREnabled, nil
	case OrgFeatureSCIM:
		return row.SCIMEnabled, nil
	default:
		return false, nil
	}
}

// SetForOrg upserts the row for orgID with the supplied toggles.
// Used by the admin org update path.
func (s *OrganizationProtocolSettingsService) SetForOrg(ctx context.Context, orgID uuid.UUID, dcrEnabled, scimEnabled bool) (*domain.OrganizationProtocolSettings, error) {
	if orgID == uuid.Nil {
		return nil, errors.New("service: SetForOrg requires non-nil organization id")
	}
	return s.repo.Upsert(ctx, &domain.OrganizationProtocolSettings{
		OrganizationID: orgID,
		DCREnabled:     dcrEnabled,
		SCIMEnabled:    scimEnabled,
	})
}
