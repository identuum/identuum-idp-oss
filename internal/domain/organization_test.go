package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOrganization_CanAccess(t *testing.T) {
	tests := []struct {
		name    string
		feature Feature
		tier    Tier
		want    bool
	}{
		{name: "Base tier cannot access Webhooks", tier: TierBase, feature: FeatureWebhooks, want: false},
		{name: "Pro tier can access Webhooks", tier: TierPro, feature: FeatureWebhooks, want: true},
		{name: "Enterprise tier can access Webhooks", tier: TierEnterprise, feature: FeatureWebhooks, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org := &Organization{Tier: tt.tier}
			assert.Equal(t, tt.want, org.CanAccess(tt.feature))
		})
	}
}

func TestValidateAdminAuth(t *testing.T) {
	// Strict Admin Sovereignty matrix:
	//   site_admin and org_admin → local only
	//   org_user → unrestricted (any method allowed; per-IdP policy enforces elsewhere)
	tests := []struct {
		name          string
		role          string
		method        string
		errorContains string
		wantErr       bool
	}{
		// org_user — never gated by this function
		{name: "org_user via local (allowed)", role: "org_user", method: "local", wantErr: false},
		{name: "org_user via oidc (allowed)", role: "org_user", method: "oidc", wantErr: false},
		{name: "org_user via ldap (allowed)", role: "org_user", method: "ldap", wantErr: false},
		{name: "org_user via ad (allowed)", role: "org_user", method: "ad", wantErr: false},

		// site_admin — local password OR WebAuthn (both bind to the user's
		// own device; external-IdP transports remain blocked)
		{name: "site_admin via local (allowed)", role: "site_admin", method: "local", wantErr: false},
		{name: "site_admin via webauthn (allowed)", role: "site_admin", method: "webauthn", wantErr: false},
		{name: "site_admin via oidc (blocked)", role: "site_admin", method: "oidc", wantErr: true, errorContains: "compliance violation"},
		{name: "site_admin via ldap (blocked)", role: "site_admin", method: "ldap", wantErr: true, errorContains: "compliance violation"},
		{name: "site_admin via ad (blocked)", role: "site_admin", method: "ad", wantErr: true, errorContains: "compliance violation"},

		// org_admin — local password OR WebAuthn (same allowlist as site_admin)
		{name: "org_admin via local (allowed)", role: "org_admin", method: "local", wantErr: false},
		{name: "org_admin via webauthn (allowed)", role: "org_admin", method: "webauthn", wantErr: false},
		{name: "org_admin via oidc (blocked)", role: "org_admin", method: "oidc", wantErr: true, errorContains: "compliance violation"},
		{name: "org_admin via ldap (blocked)", role: "org_admin", method: "ldap", wantErr: true, errorContains: "compliance violation"},
		{name: "org_admin via ad (blocked)", role: "org_admin", method: "ad", wantErr: true, errorContains: "compliance violation"},

		// Unknown role — treated as non-admin, unrestricted
		{name: "unknown role via oidc (allowed)", role: "guest", method: "oidc", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdminAuth(tt.role, tt.method)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
