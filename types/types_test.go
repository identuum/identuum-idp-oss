package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidUserRole(t *testing.T) {
	tests := []struct {
		name string
		role string
		want bool
	}{
		{
			name: "valid_role_org_user",
			role: "org_user",
			want: true,
		},
		{
			name: "valid_role_org_admin",
			role: "org_admin",
			want: true,
		},
		{
			name: "valid_role_site_admin",
			role: "site_admin",
			want: true,
		},
		{
			name: "invalid_role_empty",
			role: "",
			want: false,
		},
		{
			name: "invalid_role_unknown",
			role: "super_admin",
			want: false,
		},
		{
			name: "invalid_role_case_sensitive",
			role: "Org_User",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidUserRole(tt.role)
			assert.Equal(t, tt.want, got)
		})
	}
}
