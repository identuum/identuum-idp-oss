package handlers

import (
	"net/http"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Q1 (OSS-0913-A): POST /api/v1/organizations accepts auth_policy, and a new
// organization has no sign-in provider, so it cannot start as idp_only: 400
// no_active_identity_provider, nothing created. Other policies still create.
func TestCreateOrganization_IDPOnlyNeedsAProvider(t *testing.T) {
	for i, c := range []struct {
		policy string
		want   int
		rows   int
	}{
		{"idp_only", http.StatusBadRequest, 0},
		{"mixed", http.StatusCreated, 1},
		{"local_only", http.StatusCreated, 1},
	} {
		repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
		deps := OrganizationsHandlerDeps{Audit: audit.NoopService{}, OrganizationService: service.NewOrganizationService(nil, repo)}
		body := `{"name":"Policy ` + c.policy + `","domain":"policy-` + string(rune('a'+i)) + `.test","auth_policy":"` + c.policy + `"}`
		if code := runHandler(t, http.MethodPost, "/o", "/o", body, HandleCreateOrganization(deps)); code != c.want {
			t.Errorf("create with auth_policy %s = %d, want %d", c.policy, code, c.want)
		}
		repo.mu.Lock()
		n := len(repo.rows)
		repo.mu.Unlock()
		if n != c.rows {
			t.Errorf("create with auth_policy %s stored %d organizations, want %d", c.policy, n, c.rows)
		}
	}
}
