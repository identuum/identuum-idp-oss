package mappers

import (
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/types"
)

// ToOrganizationInfo converts a domain Organization to an API OrganizationInfo type.
// hasAdmin: CountOrgAdminsByOrganization > 0 (any pending/active org_admin exists).
// canAssignAdmin: hasAdmin=true AND CountVerifiedOrgAdminsByOrganization == 0
//
//	(expired-pending-invitation state; site_admin recovery delegation is available).
func ToOrganizationInfo(o *domain.Organization, hasAdmin bool, canAssignAdmin bool) *types.OrganizationInfo {
	if o == nil {
		return nil
	}

	return &types.OrganizationInfo{
		ID:                          o.ID,
		Name:                        o.Name,
		OrgSlug:                     o.OrgSlug,
		Domain:                      o.Domain,
		Active:                      o.Active,
		Deleted:                     o.DeletedAt != nil,
		MFAPolicy:                   o.MFAPolicy,
		AuthPolicy:                  o.AuthPolicy,
		AllowPublicRegistration:     o.AllowPublicRegistration,
		RequireRegistrationApproval: o.RequireRegistrationApproval,
		ServiceAccountExpiryDays:    o.ServiceAccountExpiryDays,
		M2MAnomalyLimit:             o.M2MAnomalyLimit,
		M2MAnomalyWindowSeconds:     o.M2MAnomalyWindowSeconds,
		RequireStrictReauth:         o.RequireStrictReauth,
		LocalAdminOnly:              o.LocalAdminOnly,
		PasswordComplexityEnabled:   o.PasswordComplexityEnabled,
		IsClaimed:                   hasAdmin,
		CanAssignAdmin:              canAssignAdmin,
		CreatedAt:                   o.CreatedAt,
		UpdatedAt:                   o.UpdatedAt,
		LastSCIMSyncAt:              o.LastSCIMSyncAt,
	}
}

// ToOrganizationWithUsers converts a domain Organization and UserInfos to API OrganizationWithUsers type.
// hasAdmin and canAssignAdmin follow the same semantics as ToOrganizationInfo.
func ToOrganizationWithUsers(o *domain.Organization, users []types.UserInfo, hasAdmin bool) *types.OrganizationWithUsers {
	if o == nil {
		return nil
	}

	// Ensure users slice is not nil for JSON output consistency
	if users == nil {
		users = []types.UserInfo{}
	}

	return &types.OrganizationWithUsers{
		ID:                          o.ID,
		Name:                        o.Name,
		Domain:                      o.Domain,
		Active:                      o.Active,
		Deleted:                     o.DeletedAt != nil,
		MFAPolicy:                   o.MFAPolicy,
		AuthPolicy:                  o.AuthPolicy,
		AllowPublicRegistration:     o.AllowPublicRegistration,
		RequireRegistrationApproval: o.RequireRegistrationApproval,
		ServiceAccountExpiryDays:    o.ServiceAccountExpiryDays,
		M2MAnomalyLimit:             o.M2MAnomalyLimit,
		M2MAnomalyWindowSeconds:     o.M2MAnomalyWindowSeconds,
		RequireStrictReauth:         o.RequireStrictReauth,
		LocalAdminOnly:              o.LocalAdminOnly,
		PasswordComplexityEnabled:   o.PasswordComplexityEnabled,
		IsClaimed:                   hasAdmin, // Provided by handler
		CreatedAt:                   o.CreatedAt,
		UpdatedAt:                   o.UpdatedAt,
		Users:                       users,
	}
}

// ToOrganizationList converts a slice of domain Organizations to a slice of API OrganizationInfo types.
// adminCounts: result of CountOrgAdminsByOrganizations (any active org_admin).
// verifiedAdminCounts: result of CountVerifiedOrgAdminsByOrganizations (email_verified=true org_admins).
// canAssignAdmin = hasAdmin && verifiedCount==0  (expired-pending-invitation state).
func ToOrganizationList(orgs []*domain.Organization, adminCounts map[uuid.UUID]int, verifiedAdminCounts map[uuid.UUID]int) []types.OrganizationInfo {
	if orgs == nil {
		return []types.OrganizationInfo{}
	}

	result := make([]types.OrganizationInfo, len(orgs))
	for i, o := range orgs {
		hasAdmin := adminCounts != nil && adminCounts[o.ID] > 0
		verifiedCount := 0
		if verifiedAdminCounts != nil {
			verifiedCount = verifiedAdminCounts[o.ID]
		}
		canAssignAdmin := hasAdmin && verifiedCount == 0
		if mapped := ToOrganizationInfo(o, hasAdmin, canAssignAdmin); mapped != nil {
			result[i] = *mapped
		}
	}
	return result
}
