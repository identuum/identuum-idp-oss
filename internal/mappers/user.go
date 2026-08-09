package mappers

import (
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/types"
)

// ToUserInfo converts a domain User to an API UserInfo type
func ToUserInfo(u *domain.User) *types.UserInfo {
	if u == nil {
		return nil
	}

	domainStr := ""
	if u.Domain != nil {
		domainStr = *u.Domain
	}

	return &types.UserInfo{
		ID:               u.ID,
		Email:            u.Email,
		Name:             u.Name,
		Role:             types.UserRole(u.Role),
		OrganizationID:   u.OrganizationID,
		Domain:           domainStr,
		OrganizationName: u.OrganizationName,
		Active:           !u.Banned, // Map backwards compatibility
		Banned:           u.Banned,
		EmailVerified:    u.EmailVerified,
		Deleted:          u.DeletedAt != nil,
		CreatedAt:        u.CreatedAt,
		LastLoginAt:      u.LastLoginAt,
		MfaEnabled:       u.MFAEnabled,
		MfaPolicy:        u.MFAPolicy,
	}
}

// ToUserList converts a slice of domain Users to a slice of API UserInfo types
func ToUserList(users []*domain.User) []types.UserInfo {
	if users == nil {
		return []types.UserInfo{}
	}

	result := make([]types.UserInfo, len(users))
	for i, u := range users {
		if mapped := ToUserInfo(u); mapped != nil {
			result[i] = *mapped
		}
	}
	return result
}
