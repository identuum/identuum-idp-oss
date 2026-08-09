package mappers

import (
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/types"
)

// ToIdentityProviderInfo converts a domain IDP to an API Info type and masks secrets
func ToIdentityProviderInfo(idp *domain.IdentityProvider) *types.IdentityProviderInfo {
	if idp == nil {
		return nil
	}

	// Map domain config to DTO config
	config := types.ProviderConfig{
		Host:                 idp.Config.Host,
		Port:                 idp.Config.Port,
		BindDN:               idp.Config.BindDN,
		BaseDN:               idp.Config.BaseDN,
		UserFilter:           idp.Config.UserFilter,
		IssuerURL:            idp.Config.IssuerURL,
		ClientID:             idp.Config.ClientID,
		RedirectURIs:         idp.Config.RedirectURIs,
		Scopes:               idp.Config.Scopes,
		EmailDomains:         idp.Config.EmailDomains,
		PKCERequired:         idp.Config.PKCERequired,
		ClaimMapping:         idp.Config.ClaimMapping,
		AttributeMapping:     idp.Config.AttributeMapping,
		AllowExternalDomains: idp.Config.AllowExternalDomains,
		SyncEnabled:          idp.Config.SyncEnabled,
		SyncSchedule:         idp.Config.SyncSchedule,
	}

	if idp.Config.TLSOptions != nil {
		config.TLSOptions = &types.TLSOptionsDTO{
			InsecureSkipVerify: idp.Config.TLSOptions.InsecureSkipVerify,
			DisableTLS:         idp.Config.TLSOptions.DisableTLS,
		}
	}

	return &types.IdentityProviderInfo{
		ID:             idp.ID,
		OrganizationID: idp.OrganizationID,
		Type:           idp.Type,
		Name:           idp.Name,
		Slug:           idp.Slug,
		Priority:       idp.Priority,
		Active:         idp.Active,
		Config:         config,
		CreatedAt:      idp.CreatedAt,
		UpdatedAt:      idp.UpdatedAt,
	}
}

// ToIdentityProviderList converts a slice of domain IDPs to a slice of API Info types
func ToIdentityProviderList(idps []*domain.IdentityProvider) []types.IdentityProviderInfo {
	if idps == nil {
		return []types.IdentityProviderInfo{}
	}

	result := make([]types.IdentityProviderInfo, len(idps))
	for i, idp := range idps {
		if mapped := ToIdentityProviderInfo(idp); mapped != nil {
			result[i] = *mapped
		}
	}
	return result
}
