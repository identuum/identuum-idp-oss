package domain_test

import (
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AdminPermissionsModel.md: 'System Organization name is "System Organization",
// slug is: system-local'.
//
// Measured before this landed: OSS had NO slug constant at all and the System
// org came back over the API with slug=null, while CE pinned
// SystemOrgSlug="system-org". Neither was system-local and they disagreed with
// each other — which rule one ("MUST be exact same in both") makes a
// divergence in its own right, on top of both being wrong.
func TestModel_SystemOrgNameAndSlug(t *testing.T) {
	if domain.SystemOrgName != "System Organization" {
		t.Errorf("SystemOrgName = %q, want %q", domain.SystemOrgName, "System Organization")
	}
	if domain.SystemOrgSlug != "system-local" {
		t.Errorf("SystemOrgSlug = %q, want %q — the model pins it verbatim",
			domain.SystemOrgSlug, "system-local")
	}
}
