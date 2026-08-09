package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureRefreshToken(t *testing.T) {
	selector, _ := uuid.NewV7()
	validator := []byte("secret-validator")

	srt := &SecureRefreshToken{
		Selector:  selector,
		Validator: validator,
	}

	encoded := srt.Encode()
	assert.Contains(t, encoded, selector.String())

	// Parse it back
	parsed, err := ParseSecureRefreshToken(encoded)
	require.NoError(t, err)
	assert.Equal(t, selector, parsed.Selector)
	assert.Equal(t, validator, parsed.Validator)

	// Error paths
	_, err = ParseSecureRefreshToken("invalid-format")
	assert.ErrorContains(t, err, "expected selector.validator")

	_, err = ParseSecureRefreshToken("not-uuid.validbase64")
	assert.ErrorContains(t, err, "invalid selector")

	_, err = ParseSecureRefreshToken(selector.String() + ".not@base64")
	assert.ErrorContains(t, err, "invalid validator")
}

func TestOrganizationClaim(t *testing.T) {
	c := &OrganizationClaim{}
	assert.ErrorContains(t, c.Validate(), "organization_id is required")

	c.OrganizationID = uuid.New()
	assert.ErrorContains(t, c.Validate(), "token_hash is required")

	c.TokenHash = "hash"
	assert.NoError(t, c.Validate())

	now := time.Now()
	c.ExpiresAt = now.Add(-time.Hour)
	assert.True(t, c.IsExpired(now))

	c.ExpiresAt = now.Add(time.Hour)
	assert.False(t, c.IsExpired(now))
}

func TestClient(t *testing.T) {
	c := &Client{}
	assert.ErrorContains(t, c.Validate(), "client_id is required")

	c.ClientID = "test"
	assert.ErrorContains(t, c.Validate(), "name is required")

	c.Name = "Test Client"
	assert.ErrorContains(t, c.Validate(), "at least one redirect_uri is required")

	c.RedirectURIs = []string{"https://example.com/callback"}
	assert.NoError(t, c.Validate())

	// Scope strings are intentionally NOT validated by client.Validate() — custom API Resource
	// scopes (user-defined, e.g. "billing:read") are dynamic and must be accepted here.
	// Scope permission enforcement is delegated to service.validateScopePermissions.
	c.Scope = "openid profile"
	assert.NoError(t, c.Validate())
	c.Scope = "any:custom-scope"
	assert.NoError(t, c.Validate())

	assert.True(t, c.IsRedirectURIAllowed("https://example.com/callback"))
	assert.False(t, c.IsRedirectURIAllowed("https://example.com/bad"))
}

func TestClient_PublicClientInvariants(t *testing.T) {
	saID := uuid.New()

	tests := []struct {
		name        string
		client      Client
		wantErr     bool
		errContains string
	}{
		{
			name: "public client with no secret and no SA is valid",
			client: Client{
				ClientID:         "pub-1",
				Name:             "Public App",
				RedirectURIs:     []string{"https://app.example/cb"},
				IsPublic:         true,
				ClientSecretHash: "",
			},
			wantErr: false,
		},
		{
			name: "public client with stored secret hash is invalid",
			client: Client{
				ClientID:         "pub-2",
				Name:             "Public App",
				RedirectURIs:     []string{"https://app.example/cb"},
				IsPublic:         true,
				ClientSecretHash: "somehash",
			},
			wantErr:     true,
			errContains: "public client must not have a client_secret",
		},
		{
			name: "public client linked to service account is invalid",
			client: Client{
				ClientID:         "pub-3",
				Name:             "Public App",
				RedirectURIs:     []string{"https://app.example/cb"},
				IsPublic:         true,
				ClientSecretHash: "",
				ServiceAccountID: &saID,
			},
			wantErr:     true,
			errContains: "public client cannot be linked to a service account",
		},
		{
			name: "confidential client with secret hash and no SA is valid",
			client: Client{
				ClientID:         "conf-1",
				Name:             "Confidential App",
				RedirectURIs:     []string{"https://app.example/cb"},
				IsPublic:         false,
				ClientSecretHash: "ahash",
			},
			wantErr: false,
		},
		{
			name: "confidential client with SA link is valid (M2M)",
			client: Client{
				ClientID:         "conf-2",
				Name:             "M2M Client",
				RedirectURIs:     []string{"https://app.example/cb"},
				IsPublic:         false,
				ClientSecretHash: "ahash",
				ServiceAccountID: &saID,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.client.Validate()
			if tt.wantErr {
				assert.ErrorContains(t, err, tt.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSession(t *testing.T) {
	s := &Session{}
	assert.ErrorContains(t, s.Validate(), "user_id is required")

	s.UserID = uuid.New()
	assert.ErrorContains(t, s.Validate(), "token_selector is required")

	selector := uuid.New()
	s.TokenSelector = &selector
	assert.ErrorContains(t, s.Validate(), "token_validator_hash is required")

	emptyHash := ""
	s.TokenValidatorHash = &emptyHash
	assert.ErrorContains(t, s.Validate(), "token_validator_hash is required")

	hash := "hash"
	s.TokenValidatorHash = &hash
	s.CreatedAt = time.Now()
	s.ExpiresAt = s.CreatedAt.Add(-time.Hour)
	assert.ErrorContains(t, s.Validate(), "expires_at must be after created_at")

	s.ExpiresAt = s.CreatedAt.Add(time.Hour)
	assert.NoError(t, s.Validate())

	now := time.Now()
	s.ExpiresAt = now.Add(-time.Hour)
	assert.True(t, s.IsExpired(now))

	s.ExpiresAt = now.Add(time.Hour)
	assert.False(t, s.IsExpired(now))

	s.IsValid = false
	canUse, reason := s.CanBeUsed(now)
	assert.False(t, canUse)
	assert.Equal(t, "session is not valid", reason)

	s.IsValid = true
	s.RevokedAt = &now
	canUse, reason = s.CanBeUsed(now)
	assert.False(t, canUse)
	assert.Equal(t, "session revoked", reason)

	reasonStr := "custom reason"
	s.RevokedReason = &reasonStr
	canUse, reason = s.CanBeUsed(now)
	assert.False(t, canUse)
	assert.Equal(t, "custom reason", reason)

	s.RevokedAt = nil
	s.RevokedReason = nil
	s.ExpiresAt = now.Add(-time.Hour)
	canUse, reason = s.CanBeUsed(now)
	assert.False(t, canUse)
	assert.Equal(t, "session expired", reason)

	s.ExpiresAt = now.Add(time.Hour)
	canUse, reason = s.CanBeUsed(now)
	assert.True(t, canUse)
	assert.Empty(t, reason)

	s.UpdateLastUsed(now)
	assert.NotNil(t, s.LastUsedAt)
	assert.Equal(t, now, *s.LastUsedAt)

	duration := s.TimeUntilExpiry()
	assert.True(t, duration > 0)

	s.Revoke(now, "compromised")
	assert.False(t, s.IsValid)
	assert.Equal(t, now, *s.RevokedAt)
	assert.Equal(t, "compromised", *s.RevokedReason)
}

func TestSessionValidationInfo(t *testing.T) {
	now := time.Now()

	validSession := &Session{
		IsValid:   true,
		ExpiresAt: now.Add(time.Hour),
	}

	svi := &SessionValidationInfo{}
	canUse, reason := svi.CanBeUsedForAuth(now)
	assert.False(t, canUse)
	assert.Equal(t, "session not found", reason)

	invalidSession := &Session{
		IsValid: false,
	}
	svi.Session = invalidSession
	canUse, reason = svi.CanBeUsedForAuth(now)
	assert.False(t, canUse)
	assert.Contains(t, reason, "session is not valid")

	svi.Session = validSession
	svi.UserDeleted = true
	canUse, reason = svi.CanBeUsedForAuth(now)
	assert.False(t, canUse)
	assert.Equal(t, "user account deleted", reason)

	svi.UserDeleted = false
	svi.UserActive = false
	canUse, reason = svi.CanBeUsedForAuth(now)
	assert.False(t, canUse)
	assert.Equal(t, "user account disabled", reason)

	svi.UserActive = true
	svi.OrgDeleted = true
	canUse, reason = svi.CanBeUsedForAuth(now)
	assert.False(t, canUse)
	assert.Equal(t, "organization deleted", reason)

	svi.OrgDeleted = false
	svi.OrgActive = false
	canUse, reason = svi.CanBeUsedForAuth(now)
	assert.False(t, canUse)
	assert.Equal(t, "organization disabled", reason)

	svi.OrgActive = true
	canUse, reason = svi.CanBeUsedForAuth(now)
	assert.True(t, canUse)
	assert.Empty(t, reason)
}

func TestPrincipal(t *testing.T) {
	p := &Principal{Role: RoleOrgUser}
	assert.False(t, p.IsSiteAdmin())
	assert.False(t, p.IsOrgAdmin())
	assert.False(t, p.IsOrgAdminOnly())

	p.Role = RoleOrgAdmin
	assert.False(t, p.IsSiteAdmin())
	assert.True(t, p.IsOrgAdmin())
	assert.True(t, p.IsOrgAdminOnly(), "IsOrgAdminOnly must be true for RoleOrgAdmin")

	p.Role = RoleSiteAdmin
	assert.True(t, p.IsSiteAdmin())
	assert.True(t, p.IsOrgAdmin(), "IsOrgAdmin returns true for RoleSiteAdmin (login-path semantics)")
	assert.False(t, p.IsOrgAdminOnly(), "IsOrgAdminOnly must be false for RoleSiteAdmin")
}

func TestPasswordReset(t *testing.T) {
	now := time.Now()
	pr := &PasswordReset{
		ExpiresAt: now.Add(time.Hour),
	}

	assert.False(t, pr.IsExpired(now))
	assert.True(t, pr.IsValid(now))

	pr.ExpiresAt = now.Add(-time.Hour)
	assert.True(t, pr.IsExpired(now))
	assert.False(t, pr.IsValid(now))

	pr.ExpiresAt = now.Add(time.Hour)
	used := now
	pr.UsedAt = &used
	assert.False(t, pr.IsExpired(now))
	assert.False(t, pr.IsValid(now))
}

func TestOrganization(t *testing.T) {
	o := &Organization{}
	assert.ErrorContains(t, o.Validate(), "name is required")

	o.Name = "Test Org"
	assert.ErrorContains(t, o.Validate(), "domain is required")

	o.Domain = "example.com"
	o.MaxSessionsPerUser = 0
	assert.ErrorContains(t, o.Validate(), "max_sessions_per_user must be at least 1")

	o.MaxSessionsPerUser = 101
	assert.ErrorContains(t, o.Validate(), "max_sessions_per_user cannot exceed 100")

	o.MaxSessionsPerUser = 5
	o.MFAPolicy = "invalid"
	assert.ErrorContains(t, o.Validate(), "mfa_policy must be 'optional' or 'required'")

	o.MFAPolicy = "optional"
	o.ServiceAccountExpiryDays = -1
	assert.ErrorContains(t, o.Validate(), "service_account_expiry_days must be between")

	o.ServiceAccountExpiryDays = 3651
	assert.ErrorContains(t, o.Validate(), "service_account_expiry_days must be between")

	o.ServiceAccountExpiryDays = 30
	assert.NoError(t, o.Validate())

	assert.Equal(t, "TierBase", TierBase.String())
	assert.Equal(t, "TierPro", TierPro.String())
	assert.Equal(t, "TierEnterprise", TierEnterprise.String())
	assert.Equal(t, TierBase, ParseTier("TierBase"))
	assert.Equal(t, TierPro, ParseTier("TierPro"))
	assert.Equal(t, TierEnterprise, ParseTier("TierEnterprise"))
	assert.Equal(t, TierBase, ParseTier("unknown"))

	o.Tier = TierBase
	assert.False(t, o.CanAccess(FeatureWebhooks))
	assert.False(t, o.CanAccess(FeatureAuditLog))

	o.Tier = TierPro
	assert.True(t, o.CanAccess(FeatureWebhooks))
	assert.True(t, o.CanAccess(FeatureAuditLog))

	o.Tier = TierEnterprise
	assert.True(t, o.CanAccess(FeatureWebhooks))
	assert.True(t, o.CanAccess(FeatureAuditLog))
	assert.False(t, o.CanAccess(Feature("unknown")))

	now := time.Now()

	// CanAcceptNewUsers and IsOperational
	o.DeletedAt = nil
	o.Active = true
	canAccept, reason := o.CanAcceptNewUsers()
	assert.True(t, canAccept)
	assert.Empty(t, reason)
	assert.True(t, o.IsOperational())

	o.Active = false
	canAccept, reason = o.CanAcceptNewUsers()
	assert.False(t, canAccept)
	assert.Equal(t, "organization not active", reason)
	assert.False(t, o.IsOperational())

	o.Active = true
	o.DeletedAt = &now
	canAccept, reason = o.CanAcceptNewUsers()
	assert.False(t, canAccept)
	assert.Equal(t, "organization not found", reason)
	assert.False(t, o.IsOperational())

	o.DeletedAt = nil
	o.DeletedAt = &now
	canAccept, reason = o.CanAcceptNewUsers()
	assert.False(t, canAccept)
	assert.Equal(t, "organization not found", reason)
	assert.False(t, o.IsOperational())

	// ValidateAdminAuth — strict admin sovereignty: admins must use a
	// device-local credential (local password or WebAuthn). External-IdP
	// transports (OIDC / LDAP / AD) remain blocked.
	// org_admin via local — allowed
	err := ValidateAdminAuth("org_admin", "local")
	assert.NoError(t, err)

	// org_admin via WebAuthn — allowed (FIDO2 is a device-local credential)
	err = ValidateAdminAuth("org_admin", "webauthn")
	assert.NoError(t, err)

	// site_admin via WebAuthn — allowed
	err = ValidateAdminAuth("site_admin", "webauthn")
	assert.NoError(t, err)

	// org_admin via OIDC — blocked unconditionally
	err = ValidateAdminAuth("org_admin", "oidc")
	assert.ErrorContains(t, err, "compliance violation")

	// site_admin via OIDC — blocked unconditionally
	err = ValidateAdminAuth("site_admin", "oidc")
	assert.ErrorContains(t, err, "compliance violation")

	// site_admin via LDAP — blocked unconditionally
	err = ValidateAdminAuth("site_admin", "ldap")
	assert.ErrorContains(t, err, "compliance violation")

	// org_user — not gated, any method allowed at this layer
	err = ValidateAdminAuth("org_user", "oidc")
	assert.NoError(t, err)
}

func TestUser(t *testing.T) {
	u := &User{}
	assert.ErrorContains(t, u.Validate(), "email is required")

	u.Email = "test@example.com"
	u.Role = RoleOrgUser
	assert.ErrorContains(t, u.Validate(), "organization_id is required")

	u.Role = RoleSiteAdmin
	assert.ErrorContains(t, u.Validate(), "password_hash is required")

	u.OrganizationID = uuid.New()
	u.Role = UserRole("invalid")
	assert.ErrorContains(t, u.Validate(), "invalid role")

	u.Role = RoleOrgUser
	u.PasswordHash = "hash"
	assert.NoError(t, u.Validate())

	canLogin, reason := u.CanLogin(false)
	assert.True(t, canLogin)
	assert.Empty(t, reason)

	canLogin, reason = u.CanLogin(true)
	assert.False(t, canLogin)
	assert.Equal(t, "email not verified", reason)

	u.EmailVerified = true
	canLogin, reason = u.CanLogin(true)
	assert.True(t, canLogin)
	assert.Empty(t, reason)

	u.Banned = true
	canLogin, reason = u.CanLogin(false)
	assert.False(t, canLogin)
	assert.Equal(t, "account banned", reason)

	u.Banned = false
	delAt := time.Now()
	u.DeletedAt = &delAt
	canLogin, reason = u.CanLogin(false)
	assert.False(t, canLogin)
	assert.Equal(t, "account not found", reason)

	u.DeletedAt = nil
	u.Role = RoleOrgUser
	assert.False(t, u.IsSiteAdmin())
	assert.False(t, u.IsOrgAdmin())
	assert.False(t, u.IsOrgAdminOnly())

	u.Role = RoleOrgAdmin
	assert.False(t, u.IsSiteAdmin())
	assert.True(t, u.IsOrgAdmin())
	assert.True(t, u.IsOrgAdminOnly(), "IsOrgAdminOnly must be true for RoleOrgAdmin")

	u.Role = RoleSiteAdmin
	assert.True(t, u.IsSiteAdmin())
	assert.True(t, u.IsOrgAdmin(), "IsOrgAdmin returns true for RoleSiteAdmin (login-path semantics)")
	assert.False(t, u.IsOrgAdminOnly(), "IsOrgAdminOnly must be false for RoleSiteAdmin")

	now := time.Now()
	u.UpdateLastLogin(now)
	assert.NotNil(t, u.LastLoginAt)
	assert.Equal(t, now, *u.LastLoginAt)

}

func TestScopes(t *testing.T) {
	assert.Equal(t, "Verify your identity (OpenID Connect)", GetScopeDescription(ScopeOpenID))
	assert.Equal(t, "unknown_scope", GetScopeDescription("unknown_scope"))

	held := map[string]struct{}{
		ScopeUsersRead: {},
	}
	assert.True(t, HasAnyScope(held, []string{ScopeUsersRead}))
	assert.False(t, HasAnyScope(held, []string{ScopeUsersCreate}))
	assert.True(t, HasAnyScope(held, []string{ScopeUsersCreate, ScopeUsersRead}))
	assert.False(t, HasAnyScope(map[string]struct{}{}, []string{ScopeUsersCreate}))
	assert.False(t, HasAnyScope(held, []string{}))
}

// minimalValidOrg returns an Organization that passes all existing Validate() checks so that
// individual test cases need only override the field under test.
func minimalValidOrg() Organization {
	return Organization{
		Name:                     "Test Org",
		Domain:                   "example.com",
		MaxSessionsPerUser:       1,
		MFAPolicy:                "optional",
		ServiceAccountExpiryDays: 0,
	}
}

func TestOrganizationValidate_PolicyFields(t *testing.T) {
	tests := []struct {
		name                   string
		authPolicy             string
		apiAuthorizationPolicy string
		wantErr                bool
		errContains            string
	}{
		{
			name:                   "both empty — valid legacy values",
			authPolicy:             "",
			apiAuthorizationPolicy: "",
			wantErr:                false,
		},
		{
			name:                   "local_only + STRICT — valid",
			authPolicy:             AuthPolicyLocalOnly,
			apiAuthorizationPolicy: APIAuthPolicyStrict,
			wantErr:                false,
		},
		{
			name:                   "idp_only + IMPLICIT — valid",
			authPolicy:             AuthPolicyIDPOnly,
			apiAuthorizationPolicy: APIAuthPolicyImplicit,
			wantErr:                false,
		},
		{
			name:                   "mixed + empty apiPolicy — valid",
			authPolicy:             AuthPolicyMixed,
			apiAuthorizationPolicy: "",
			wantErr:                false,
		},
		{
			name:                   "empty authPolicy + STRICT — valid",
			authPolicy:             "",
			apiAuthorizationPolicy: APIAuthPolicyStrict,
			wantErr:                false,
		},
		{
			name:                   "invalid authPolicy — rejected",
			authPolicy:             "INVALID",
			apiAuthorizationPolicy: "",
			wantErr:                true,
			errContains:            "auth_policy",
		},
		{
			name:                   "empty authPolicy + invalid apiAuthorizationPolicy — rejected",
			authPolicy:             "",
			apiAuthorizationPolicy: "WRONG",
			wantErr:                true,
			errContains:            "api_authorization_policy",
		},
		{
			name:                   "valid authPolicy + invalid apiAuthorizationPolicy — rejected",
			authPolicy:             AuthPolicyLocalOnly,
			apiAuthorizationPolicy: "BAD",
			wantErr:                true,
			errContains:            "api_authorization_policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org := minimalValidOrg()
			org.AuthPolicy = tt.authPolicy
			org.ApiAuthorizationPolicy = tt.apiAuthorizationPolicy
			err := org.Validate()
			if tt.wantErr {
				assert.ErrorContains(t, err, tt.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOrganizationIsOperational(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		deletedAt *time.Time
		active    bool
		want      bool
	}{
		{
			name:      "fully operational",
			deletedAt: nil,
			active:    true,
			want:      true,
		},
		{
			name:      "inactive (pre-claim or disabled)",
			deletedAt: nil,
			active:    false,
			want:      false,
		},
		{
			name:      "soft-deleted via DeletedAt",
			deletedAt: &now,
			active:    true,
			want:      false,
		},
		{
			name:      "soft-deleted and inactive",
			deletedAt: &now,
			active:    false,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org := Organization{
				DeletedAt: tt.deletedAt,
				Active:    tt.active,
			}
			assert.Equal(t, tt.want, org.IsOperational())
		})
	}
}
