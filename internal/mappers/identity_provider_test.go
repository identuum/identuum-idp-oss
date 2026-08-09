package mappers

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/types"
	"github.com/stretchr/testify/assert"
)

func TestToIdentityProviderInfo(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		input    *domain.IdentityProvider
		expected *types.IdentityProviderInfo
	}{
		{
			name:     "Nil input",
			input:    nil,
			expected: nil,
		},
		{
			name: "Masks Secrets",
			input: &domain.IdentityProvider{
				ID:             uuid.MustParse(domain.SystemOrgID),
				OrganizationID: uuid.MustParse("00000000-0000-0000-0000-000000000002"),
				Type:           domain.IDPTypeOIDC,
				Name:           "Test IDP",
				Slug:           "test-idp",
				Priority:       1,
				Active:         true,
				Config: domain.ProviderConfig{
					IssuerURL:             "https://example.com",
					BindPasswordEncrypted: "sensitive-password",
					ClientSecretEncrypted: "sensitive-secret",
				},
				CreatedAt: now,
				UpdatedAt: now,
			},
			expected: &types.IdentityProviderInfo{
				ID:             uuid.MustParse(domain.SystemOrgID),
				OrganizationID: uuid.MustParse("00000000-0000-0000-0000-000000000002"),
				Type:           domain.IDPTypeOIDC,
				Name:           "Test IDP",
				Slug:           "test-idp",
				Priority:       1,
				Active:         true,
				Config: types.ProviderConfig{
					IssuerURL: "https://example.com",
				},
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		{
			name: "LDAP IDP",
			input: &domain.IdentityProvider{
				ID:             uuid.MustParse("00000000-0000-0000-0000-000000000003"),
				OrganizationID: uuid.MustParse("00000000-0000-0000-0000-000000000002"),
				Type:           domain.IDPTypeLDAP,
				Name:           "LDAP IDP",
				Slug:           "ldap-idp",
				Priority:       2,
				Active:         true,
				Config: domain.ProviderConfig{
					Host:                  "ldap.example.com",
					Port:                  636,
					BindDN:                "cn=admin,dc=example,dc=com",
					BindPasswordEncrypted: "ldap-sensitive-password",
					BaseDN:                "dc=example,dc=com",
					UserFilter:            "(uid=%s)",
				},
				CreatedAt: now,
				UpdatedAt: now,
			},
			expected: &types.IdentityProviderInfo{
				ID:             uuid.MustParse("00000000-0000-0000-0000-000000000003"),
				OrganizationID: uuid.MustParse("00000000-0000-0000-0000-000000000002"),
				Type:           domain.IDPTypeLDAP,
				Name:           "LDAP IDP",
				Slug:           "ldap-idp",
				Priority:       2,
				Active:         true,
				Config: types.ProviderConfig{
					Host:       "ldap.example.com",
					Port:       636,
					BindDN:     "cn=admin,dc=example,dc=com",
					BaseDN:     "dc=example,dc=com",
					UserFilter: "(uid=%s)",
				},
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToIdentityProviderInfo(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToIdentityProviderList(t *testing.T) {
	i1 := &domain.IdentityProvider{Name: "IDP 1"}
	i2 := &domain.IdentityProvider{Name: "IDP 2"}

	list := []*domain.IdentityProvider{i1, i2}
	result := ToIdentityProviderList(list)

	assert.Len(t, result, 2)
	assert.Equal(t, "IDP 1", result[0].Name)
	assert.Equal(t, "IDP 2", result[1].Name)
}
