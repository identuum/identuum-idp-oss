package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// THE-SILENT-DROP-2 (2026-09-01): the previous slice made both surfaces take
// a pointer description, then handled the supplied value DIFFERENTLY —
// OrgRoleService trimmed it, ServiceAccountService assigned it raw. So a
// whitespace-only description CLEARED an org role and was STORED as "   " on
// a service account: one convention, two answers, shipped together.
//
// The answer is TRIM on every surface, so "" and "   " both mean "cleared"
// wherever a description is written. This test asserts the two surfaces
// AGREE, which is the property that was actually missing — testing either
// one alone would have passed while they disagreed.
//
// RULE: DESCRIPTION-BLANK-UNIFORM-1
func TestDescriptionBlank_MeansTheSameOnEverySurface(t *testing.T) {
	orgID := uuid.New()

	// writeDescription applies a supplied description on one surface and
	// returns what that surface actually stored.
	surfaces := map[string]func(t *testing.T, supplied string) string{
		"org role (update)": func(t *testing.T, supplied string) string {
			roleID := uuid.New()
			repo := &recordingOrgRoleRepo{stored: domain.OrgRole{
				ID: roleID, OrgID: orgID, Name: "Auditor", Description: "reads audit logs",
			}}
			svc := NewOrgRoleService(nil, repo, nil)
			actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: orgID}
			got, err := svc.UpdateRoleForActor(context.Background(), actor, roleID, UpdateOrgRoleOptions{
				Description: &supplied,
			})
			if err != nil {
				t.Fatalf("org role update rejected description %q: %v", supplied, err)
			}
			return got.Description
		},
		"service account (update)": func(t *testing.T, supplied string) string {
			saID := uuid.New()
			svc, repo := newAdminSAService()
			repo.byID[saID] = &domain.ServiceAccount{
				ID: saID, OrganizationID: orgID, Active: true,
				Role: domain.RoleOrgUser, Name: "ci", Description: "build runner",
			}
			got, err := svc.UpdateForActor(context.Background(), newOrgAdmin(orgID), saID, ServiceAccountUpdateInput{
				Description: &supplied,
			})
			if err != nil {
				t.Fatalf("service account update rejected description %q: %v", supplied, err)
			}
			return got.Description
		},
		"service account (create)": func(t *testing.T, supplied string) string {
			svc, _ := newAdminSAService()
			got, err := svc.CreateForActor(context.Background(), newOrgAdmin(orgID), orgID, ServiceAccountAdminInput{
				Name: "ci", Role: domain.RoleOrgUser, Description: supplied,
			})
			if err != nil {
				t.Fatalf("service account create rejected description %q: %v", supplied, err)
			}
			return got.Description
		},
	}

	for _, supplied := range []struct {
		why   string
		value string
		want  string
	}{
		{"an empty description clears", "", ""},
		{"a whitespace-only description ALSO clears", "   ", ""},
		{"a tab-only description also clears", "\t", ""},
		{"a padded real description is stored trimmed", "  build runner v2  ", "build runner v2"},
		{"a real description is stored as given", "build runner v2", "build runner v2"},
	} {
		results := map[string]string{}
		for name, apply := range surfaces {
			results[name] = apply(t, supplied.value)
		}
		// Every surface must agree with the convention...
		for name, got := range results {
			if got != supplied.want {
				t.Errorf("%s: %s — stored %q, want %q", name, supplied.why, got, supplied.want)
			}
		}
		// ...and, stated separately because it is the property that broke,
		// they must agree with EACH OTHER.
		var first, firstName string
		for name, got := range results {
			if firstName == "" {
				first, firstName = got, name
				continue
			}
			if got != first {
				t.Errorf("SURFACES DISAGREE on %q: %s stored %q but %s stored %q",
					supplied.value, firstName, first, name, got)
			}
		}
	}
}
