package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// Owner ruling (v0.9.5): on a tenant organization a site_admin changes only
// lifecycle fields (active, and the name it gave at creation); the policy
// fields — and domain and local_admin_only — are the organization's own
// org_admin's, who never changes active. The system organization stays the
// site_admin's to edit in full.

func orgAdminOf(org uuid.UUID, scope string) *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgAdmin, Scope: scope}
}

func forbiddenFields(t *testing.T, body []byte) []string {
	t.Helper()
	var got struct {
		Error  string   `json:"error"`
		Fields []string `json:"fields"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if got.Error != "forbidden_field" {
		t.Fatalf("error = %q, want forbidden_field (%s)", got.Error, body)
	}
	return got.Fields
}

func TestUpdateOrganization_SiteAdminChangesOnlyLifecycleOfATenant(t *testing.T) {
	eng := newTenantEngine(t, siteAdminActor())
	org := uuid.New()
	seedTenantOrg(eng, org, "Acme")

	rec := tenantReq(t, eng, http.MethodPut, "/api/v1/organizations/"+org.String(), map[string]any{"mfa_policy": "required", "local_admin_only": true})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("site_admin policy edit of a tenant = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if got := forbiddenFields(t, rec.Body.Bytes()); len(got) != 2 || got[0] != "local_admin_only" || got[1] != "mfa_policy" {
		t.Errorf("fields = %v, want [local_admin_only mfa_policy]", got)
	}
	if o, _ := eng.orgRepo.GetByID(t.Context(), org); o == nil || o.MFAPolicy != "optional" || o.LocalAdminOnly {
		t.Errorf("a refused edit changed the organization: %+v", o)
	}

	rec = tenantReq(t, eng, http.MethodPut, "/api/v1/organizations/"+org.String(), map[string]any{"name": "Acme Two", "active": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("site_admin lifecycle edit = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if o, _ := eng.orgRepo.GetByID(t.Context(), org); o == nil || o.Name != "Acme Two" || o.Active {
		t.Errorf("lifecycle edit not applied: %+v", o)
	}
}

func TestUpdateOrganization_SiteAdminEditsTheSystemOrganizationInFull(t *testing.T) {
	eng := newTenantEngine(t, siteAdminActor())
	sys := uuid.MustParse(domain.SystemOrgID)
	seedTenantOrg(eng, sys, "System")
	rec := tenantReq(t, eng, http.MethodPut, "/api/v1/organizations/"+sys.String(), map[string]any{"max_sessions_per_user": 5, "mfa_policy": "required"})
	if rec.Code != http.StatusOK {
		t.Fatalf("site_admin edit of the system organization = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateOrganization_OrgAdminSetsItsOwnPolicy(t *testing.T) {
	org := uuid.New()
	actor := orgAdminOf(org, "orgs:read orgs:update")
	eng := newTenantEngine(t, actor)
	seedTenantOrg(eng, org, "Acme")

	body := map[string]any{
		"name": "Acme Renamed", "domain": "acme-renamed.test", "local_admin_only": true,
		"mfa_policy": "required", "max_sessions_per_user": 3, "require_strict_reauth": true,
	}
	rec := tenantReq(t, eng, http.MethodPut, "/api/v1/organizations/"+org.String(), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("org_admin policy edit of its own organization = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	o, _ := eng.orgRepo.GetByID(t.Context(), org)
	if o == nil || o.Name != "Acme Renamed" || o.Domain != "acme-renamed.test" || !o.LocalAdminOnly || o.MFAPolicy != "required" || o.MaxSessionsPerUser != 3 || !o.RequireStrictReauth {
		t.Errorf("policy edit not applied: %+v", o)
	}
	var updated bool
	for _, e := range eng.rec.Events() {
		if e.Action == "organization.updated" {
			updated = true
			if e.ActorID != actor.UserID || e.ActorRole != string(domain.RoleOrgAdmin) || e.OrganizationID != org {
				t.Errorf("audit actor=%s role=%s org=%s, want the org_admin of %s", e.ActorID, e.ActorRole, e.OrganizationID, org)
			}
			fields, _ := e.Metadata["fields"].([]string)
			if len(fields) != len(body) {
				t.Errorf("audit fields = %v, want the %d changed field names", e.Metadata["fields"], len(body))
			}
		}
	}
	if !updated {
		t.Error("no organization.updated audit event")
	}
}

func TestUpdateOrganization_OrgAdminNeverChangesActive(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, orgAdminOf(org, "orgs:update"))
	seedTenantOrg(eng, org, "Acme")
	rec := tenantReq(t, eng, http.MethodPut, "/api/v1/organizations/"+org.String(), map[string]any{"active": false})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("org_admin deactivating its organization = %d, want 403", rec.Code)
	}
	if got := forbiddenFields(t, rec.Body.Bytes()); len(got) != 1 || got[0] != "active" {
		t.Errorf("fields = %v, want [active]", got)
	}
}

func TestUpdateOrganization_OrgAdminOfAnotherOrganizationOrWithoutScopeIsRefused(t *testing.T) {
	org := uuid.New()
	other := uuid.New()
	eng := newTenantEngine(t, orgAdminOf(other, "orgs:update"))
	seedTenantOrg(eng, org, "Acme")
	if rec := tenantReq(t, eng, http.MethodPut, "/api/v1/organizations/"+org.String(), map[string]any{"mfa_policy": "required"}); rec.Code != http.StatusForbidden {
		t.Errorf("another organization's org_admin = %d, want 403", rec.Code)
	}

	eng = newTenantEngine(t, orgAdminOf(org, "orgs:read"))
	seedTenantOrg(eng, org, "Acme")
	if rec := tenantReq(t, eng, http.MethodPut, "/api/v1/organizations/"+org.String(), map[string]any{"mfa_policy": "required"}); rec.Code != http.StatusForbidden {
		t.Errorf("org_admin without orgs:update = %d, want 403", rec.Code)
	}
}
