package service

import (
	"errors"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// TestIsLocalCredentialFlowAllowed_Matrix exhaustively pins the cartesian
// product of (org auth_policy × user role × user nil): a non-idp_only policy
// lets every role (and a nil user) through; under auth_policy=idp_only the
// site_admin and org_admin roles still pass, while an org_user, a nil user,
// and any unknown/empty role are sealed FAIL-CLOSED — and every deny surfaces
// ErrLocalLoginDisabledForRole while every allow carries no SealReason.
//
// Ported from the auth-service ancestor matrix; the idp-oss signature takes an
// orgAuthPolicy string (domain.AuthPolicyIDPOnly is the sealed value) instead
// of the ancestor's bool flag.
// RULE: LOCAL-CREDENTIAL-FLOW-1
func TestIsLocalCredentialFlowAllowed_Matrix(t *testing.T) {
	const off = "" // any policy other than idp_only lets every role through

	cases := []struct {
		name        string
		policy      string
		role        domain.UserRole
		nilUser     bool
		wantAllowed bool
	}{
		// Not idp_only: every role passes through (backwards-compat baseline).
		{"off_site_admin", off, domain.RoleSiteAdmin, false, true},
		{"off_org_admin", off, domain.RoleOrgAdmin, false, true},
		{"off_org_user", off, domain.RoleOrgUser, false, true},
		{"off_nil_user", off, "", true, true},

		// idp_only: admin roles still pass; org_user is sealed; nil and
		// unknown/empty roles fail closed.
		{"idp_only_site_admin", domain.AuthPolicyIDPOnly, domain.RoleSiteAdmin, false, true},
		{"idp_only_org_admin", domain.AuthPolicyIDPOnly, domain.RoleOrgAdmin, false, true},
		{"idp_only_org_user", domain.AuthPolicyIDPOnly, domain.RoleOrgUser, false, false},
		{"idp_only_nil_user", domain.AuthPolicyIDPOnly, "", true, false},
		{"idp_only_unknown_role", domain.AuthPolicyIDPOnly, "future_role", false, false},
		{"idp_only_empty_role", domain.AuthPolicyIDPOnly, "", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var u *domain.User
			if !tc.nilUser {
				u = &domain.User{Role: tc.role}
			}
			got := IsLocalCredentialFlowAllowed(u, tc.policy)
			if got.Allowed != tc.wantAllowed {
				t.Fatalf("policy=%q role=%q nil=%v: Allowed=%v, want %v (%+v)",
					tc.policy, tc.role, tc.nilUser, got.Allowed, tc.wantAllowed, got)
			}
			if tc.wantAllowed {
				if got.SealReason != nil {
					t.Errorf("allow path must carry no SealReason, got %v", got.SealReason)
				}
			} else {
				if !errors.Is(got.SealReason, domain.ErrLocalLoginDisabledForRole) {
					t.Errorf("deny path must surface ErrLocalLoginDisabledForRole, got %v", got.SealReason)
				}
			}
		})
	}
}

// TestIsLocalCredentialFlowAllowed_SealReasonNeverNilOnDeny defends the audit
// path: a deny that returns no SealReason would lose the reason downstream, so
// every deny branch (org_user, nil user, unknown role) must populate it.
func TestIsLocalCredentialFlowAllowed_SealReasonNeverNilOnDeny(t *testing.T) {
	denyCases := []struct {
		name string
		user *domain.User
	}{
		{"org_user", &domain.User{Role: domain.RoleOrgUser}},
		{"nil_user", nil},
		{"unknown_role", &domain.User{Role: "rogue"}},
	}
	for _, tc := range denyCases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsLocalCredentialFlowAllowed(tc.user, domain.AuthPolicyIDPOnly)
			if got.Allowed {
				t.Fatalf("%s: expected deny under idp_only", tc.name)
			}
			if got.SealReason == nil {
				t.Errorf("%s: deny path must populate SealReason", tc.name)
			}
		})
	}
}
