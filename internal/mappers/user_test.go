package mappers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/types"
	"github.com/stretchr/testify/assert"
)

func TestToUserInfo(t *testing.T) {
	now := time.Now()
	name := "John Doe"
	domainStr := "example.com"
	orgName := "Example Corp"

	tests := []struct {
		name     string
		input    *domain.User
		expected *types.UserInfo
	}{
		{
			name:     "Nil input",
			input:    nil,
			expected: nil,
		},
		{
			name: "Full user",
			input: &domain.User{
				ID:               uuid.MustParse(domain.SystemOrgID),
				Email:            "test@example.com",
				Name:             &name,
				OrganizationID:   uuid.MustParse("00000000-0000-0000-0000-000000000002"),
				Role:             domain.RoleOrgAdmin,
				Banned:           false,
				CreatedAt:        now,
				LastLoginAt:      &now,
				Domain:           &domainStr,
				OrganizationName: &orgName,
			},
			expected: &types.UserInfo{
				ID:               uuid.MustParse(domain.SystemOrgID),
				Email:            "test@example.com",
				Name:             &name,
				Role:             types.RoleOrgAdmin,
				OrganizationID:   uuid.MustParse("00000000-0000-0000-0000-000000000002"),
				Domain:           "example.com",
				OrganizationName: &orgName,
				Active:           true,
				Banned:           false,
				Deleted:          false,
				CreatedAt:        now,
				LastLoginAt:      &now,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToUserInfo(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToUserList(t *testing.T) {
	u1 := &domain.User{Email: "user1@example.com"}
	u2 := &domain.User{Email: "user2@example.com"}

	list := []*domain.User{u1, u2}
	result := ToUserList(list)

	assert.Len(t, result, 2)
	assert.Equal(t, "user1@example.com", result[0].Email)
	assert.Equal(t, "user2@example.com", result[1].Email)
}

func TestToUserInfo_Security_PIIStripping(t *testing.T) {
	// Setup a user with sensitive fields populated
	passwordHash := "$2a$12$R9h/cIPz0gi.URNNXRFXjOzpVsiyjaqjF.SA.y0YjCqfz7O/C/WCO"
	mfaSecret := "JBSWY3DPEHPK3PXP"
	recoveryCodes := []string{"123456", "789012"}
	externalID := "ext-12345"
	authSource := "oidc"

	u := &domain.User{
		ID:               uuid.New(),
		Email:            "sec-test@example.com",
		PasswordHash:     passwordHash,
		MFASecret:        &mfaSecret,
		MFARecoveryCodes: recoveryCodes,
		ExternalID:       &externalID,
		AuthSource:       authSource,
		Role:             domain.RoleOrgUser,
		OrganizationID:   uuid.New(),
	}

	// ACTION: Convert to UserInfo
	userInfo := ToUserInfo(u)

	// ASSERTION 1: Marshal to JSON to simulate API response
	data, err := json.Marshal(userInfo)
	assert.NoError(t, err)
	jsonStr := string(data)

	// ASSERTION 2: Verify PII values are NOT present in the output
	assert.NotContains(t, jsonStr, passwordHash, "Password hash must not be present in JSON output")
	assert.NotContains(t, jsonStr, mfaSecret, "MFA secret must not be present in JSON output")
	// Note: We don't check recovery codes values because they are []string and json representation might vary (spaces etc),
	// but we check keys below.

	// ASSERTION 3: Verify sensitive keys are NOT present
	assert.NotContains(t, jsonStr, "password_hash", "password_hash key must not be present in JSON")
	assert.NotContains(t, jsonStr, "password", "password key must not be present in JSON")
	assert.NotContains(t, jsonStr, "mfa_secret", "mfa_secret key must not be present in JSON")
	assert.NotContains(t, jsonStr, "recovery_codes", "recovery_codes key must not be present in JSON")
	assert.NotContains(t, jsonStr, "mfa_recovery_codes", "mfa_recovery_codes key must not be present in JSON")

	// ASSERTION 4: Verify external_id and auth_source are also stripped (as they are not in UserInfo struct currently)
	// If requirements change to include them, remove these assertions.
	// But currently UserInfo doesn't have them.
	assert.NotContains(t, jsonStr, "external_id", "external_id key must not be present in JSON")
	assert.NotContains(t, jsonStr, "auth_source", "auth_source key must not be present in JSON")
}
