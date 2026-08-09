package mappers

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/types"
	"github.com/stretchr/testify/assert"
)

func TestToOrganizationInfo(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name           string
		input          *domain.Organization
		hasAdmin       bool
		canAssignAdmin bool
		expected       *types.OrganizationInfo
	}{
		{
			name:     "Nil input",
			input:    nil,
			hasAdmin: false,
			expected: nil,
		},
		{
			name: "Full organization with verified admin",
			input: &domain.Organization{
				ID:                 uuid.MustParse(domain.SystemOrgID),
				Name:               "Test Org",
				Domain:             "test.com",
				Active:             true,
				MaxSessionsPerUser: 5,
				MFAPolicy:          "required",
				AuthPolicy:         "local_only",
				OrgSlug:            "test-org",
				CreatedAt:          now,
			},
			hasAdmin:       true,
			canAssignAdmin: false,
			expected: &types.OrganizationInfo{
				ID:             uuid.MustParse(domain.SystemOrgID),
				Name:           "Test Org",
				OrgSlug:        "test-org",
				Domain:         "test.com",
				Active:         true,
				Deleted:        false,
				MFAPolicy:      "required",
				AuthPolicy:     "local_only",
				IsClaimed:      true,
				CanAssignAdmin: false,
				CreatedAt:      now,
			},
		},
		{
			name: "Expired-pending invitation — can_assign_admin=true",
			input: &domain.Organization{
				ID:     uuid.MustParse(domain.SystemOrgID),
				Name:   "Recovery Org",
				Domain: "recovery.local",
				Active: true,
			},
			hasAdmin:       true,
			canAssignAdmin: true,
			expected: &types.OrganizationInfo{
				ID:             uuid.MustParse(domain.SystemOrgID),
				Name:           "Recovery Org",
				Domain:         "recovery.local",
				Active:         true,
				IsClaimed:      true,
				CanAssignAdmin: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToOrganizationInfo(tt.input, tt.hasAdmin, tt.canAssignAdmin)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToOrganizationList(t *testing.T) {
	o1 := &domain.Organization{Name: "Org 1"}
	o2 := &domain.Organization{Name: "Org 2"}

	list := []*domain.Organization{o1, o2}
	result := ToOrganizationList(list, nil, nil)

	assert.Len(t, result, 2)
	assert.Equal(t, "Org 1", result[0].Name)
	assert.Equal(t, "Org 2", result[1].Name)
}

func TestToOrganizationWithUsers(t *testing.T) {
	org := &domain.Organization{Name: "Org 1"}
	users := []types.UserInfo{{Email: "user@test.com"}}

	result := ToOrganizationWithUsers(org, users, false)

	assert.Equal(t, "Org 1", result.Name)
	assert.Len(t, result.Users, 1)
	assert.Equal(t, "user@test.com", result.Users[0].Email)
}
