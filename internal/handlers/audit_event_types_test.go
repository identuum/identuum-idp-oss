package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func getAuditEventTypes(t *testing.T, principal *domain.Principal) *httptest.ResponseRecorder {
	t.Helper()
	r := auditEngine(t, principal, &recordingAuditReader{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/event-types", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// GET /api/v1/audit/event-types answers the console's contract
// {"groups":[{"label","types":[{"value","label"}]}]} with exactly the catalog
// (AUDIT-EVENT-CATALOG-1), for site_admin and for an org_admin with audit:read.
func TestAuditEventTypes_ServesCatalog(t *testing.T) {
	want := map[string]bool{}
	for _, g := range domain.AllAuditEventTypeGroups {
		for _, et := range g.Types {
			want[string(et)] = true
		}
	}
	for name, p := range map[string]*domain.Principal{
		"site_admin":           {UserID: uuid.New(), Role: domain.RoleSiteAdmin},
		"org_admin+audit:read": orgAdmin(uuid.New()),
	} {
		rec := getAuditEventTypes(t, p)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", name, rec.Code)
		}
		var body struct {
			Groups []struct {
				Label string `json:"label"`
				Types []struct {
					Value string `json:"value"`
					Label string `json:"label"`
				} `json:"types"`
			} `json:"groups"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: body is not the groups contract: %v", name, err)
		}
		got := map[string]bool{}
		for _, g := range body.Groups {
			if g.Label == "" {
				t.Errorf("%s: a group has no label", name)
			}
			for _, ty := range g.Types {
				if ty.Label == "" || ty.Label != domain.AuditEventTypeLabel(domain.AuditEventType(ty.Value)) {
					t.Errorf("%s: %q has label %q, want the AuditEventTypeLabel one", name, ty.Value, ty.Label)
				}
				got[ty.Value] = true
			}
		}
		if len(got) != len(want) {
			t.Errorf("%s: served %d types, catalog has %d", name, len(got), len(want))
		}
		for v := range want {
			if !got[v] {
				t.Errorf("%s: catalog type %q not served", name, v)
			}
		}
	}
}

// The catalog has the log's guard: org_user is refused even holding
// audit:read, an org_admin without the scope is refused, and an anonymous
// caller is refused before the handler.
func TestAuditEventTypes_Guard(t *testing.T) {
	cases := []struct {
		name string
		p    *domain.Principal
		want int
	}{
		{"org_user+audit:read", &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser, Scope: domain.ScopeAuditRead}, http.StatusForbidden},
		{"org_admin without scope", &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgAdmin}, http.StatusForbidden},
		{"anonymous", nil, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		rec := getAuditEventTypes(t, tc.p)
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.name, rec.Code, tc.want)
		}
		if rec.Code == http.StatusOK {
			t.Errorf("%s: the catalog must not be served", tc.name)
		}
	}
}
