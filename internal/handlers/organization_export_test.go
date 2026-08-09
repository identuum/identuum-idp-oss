package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// seedExportOrg creates an organization row directly via the in-memory
// repo (bypassing HandleCreateOrganization) so tests control every
// field precisely, including inactive/"shell" orgs the create handler
// wouldn't normally produce.
func seedExportOrg(t *testing.T, eng identityEngine, id uuid.UUID, name string, active bool) *domain.Organization {
	t.Helper()
	now := time.Now().UTC()
	o := &domain.Organization{
		ID:        id,
		Name:      name,
		Domain:    name + ".test",
		OrgSlug:   name,
		Active:    active,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if _, err := eng.orgRepo.Create(context.Background(), o); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return o
}

// (a) The endpoint no longer returns 501; a site_admin gets the real
// export-candidates list.
func TestOrgExportCandidates_SiteAdmin_Returns200NotDeferred(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	seedExportOrg(t, eng, uuid.New(), "acme", true)
	seedExportOrg(t, eng, uuid.New(), "globex", true)

	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/export-candidates", nil)
	if rec.Code == http.StatusNotImplemented {
		t.Fatalf("endpoint still returns 501 (deferred) — the OSS port did not take effect")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Organizations []organizationExportCandidate `json:"organizations"`
		Total         int                           `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 2 || len(body.Organizations) != 2 {
		t.Fatalf("total=%d len=%d, want 2 and 2", body.Total, len(body.Organizations))
	}
}

// (b) Authorization: an unauthenticated caller is rejected 401 — same
// gate (RequireSiteAdminOrOrgAdminWithScopesAudit) as the sibling
// GET /organizations list route.
func TestOrgExportCandidates_Unauthenticated_401(t *testing.T) {
	eng := newIdentityEngine(t, nil, nil)
	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/export-candidates", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// (b) Authorization: an org_admin actor WITHOUT the orgs:read scope is
// rejected 403 before any DB call — matching the sibling list route's
// documented gate behavior exactly.
func TestOrgExportCandidates_OrgAdminWithoutScope_Forbidden(t *testing.T) {
	eng := newIdentityEngine(t, &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgAdmin}, nil)
	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/export-candidates", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (org_admin lacking orgs:read scope)", rec.Code)
	}
}

// An org_admin WITH the orgs:read scope is admitted by the gate but
// sees only their own org (single-row) — mirrors HandleListOrganizations
// so this route never becomes a new cross-tenant enumeration surface.
func TestOrgExportCandidates_OrgAdminWithScope_SeesOnlyOwnOrg(t *testing.T) {
	ownOrgID := uuid.New()
	principal := &domain.Principal{UserID: uuid.New(), OrganizationID: ownOrgID, Role: domain.RoleOrgAdmin, Scope: domain.ScopeOrgsRead}
	eng := newIdentityEngine(t, principal, nil)
	seedExportOrg(t, eng, ownOrgID, "own-org", true)
	seedExportOrg(t, eng, uuid.New(), "other-org", true)

	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/export-candidates", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Organizations []organizationExportCandidate `json:"organizations"`
		Total         int                           `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 1 || len(body.Organizations) != 1 {
		t.Fatalf("total=%d len=%d, want 1 and 1 (own org only)", body.Total, len(body.Organizations))
	}
	if body.Organizations[0].ID != ownOrgID {
		t.Errorf("id = %s, want own org id %s", body.Organizations[0].ID, ownOrgID)
	}
}

// (c) The projection is SAFE and EXPLICIT: the response contains
// exactly the seven named fields and nothing else — no policy fields,
// no secrets, no internal flags.
func TestOrgExportCandidates_ResponseIsExactSafeProjection(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	orgID := uuid.New()
	seedExportOrg(t, eng, orgID, "acme", true)

	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/export-candidates", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var raw struct {
		Organizations []map[string]json.RawMessage `json:"organizations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	if len(raw.Organizations) != 1 {
		t.Fatalf("organizations len=%d, want 1", len(raw.Organizations))
	}

	wantFields := map[string]bool{
		"id": true, "name": true, "slug": true, "status": true,
		"created_at": true, "updated_at": true, "source_component": true,
	}
	got := raw.Organizations[0]
	if len(got) != len(wantFields) {
		t.Fatalf("field count = %d, want %d; fields=%v", len(got), len(wantFields), keysOf(got))
	}
	for k := range got {
		if !wantFields[k] {
			t.Errorf("unexpected field %q in export-candidates projection — must carry ONLY the seven safe fields", k)
		}
	}
	for k := range wantFields {
		if _, ok := got[k]; !ok {
			t.Errorf("missing required safe field %q", k)
		}
	}

	// Sensitive/internal fields present on safeOrganization / domain.Organization
	// must NEVER leak through this projection.
	forbidden := []string{
		"domain", "active", "max_sessions_per_user", "mfa_policy", "auth_policy",
		"api_authorization_policy", "allow_public_registration",
		"require_registration_approval", "require_strict_reauth", "local_admin_only",
		"password_complexity_enabled", "tier", "deleted_at", "password_hash",
		"encryption_key", "last_scim_sync_at",
	}
	for _, f := range forbidden {
		if _, ok := got[f]; ok {
			t.Errorf("forbidden field %q leaked into export-candidates projection", f)
		}
	}
}

// (d) Empty case: no organizations returns a well-formed empty list,
// not an error.
func TestOrgExportCandidates_NoOrgs_EmptyArrayNotError(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/export-candidates", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		Organizations []organizationExportCandidate `json:"organizations"`
		Total         int                           `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Organizations == nil {
		t.Error("organizations is null, want a well-formed empty array")
	}
	if len(body.Organizations) != 0 || body.Total != 0 {
		t.Errorf("organizations=%v total=%d, want empty/0", body.Organizations, body.Total)
	}
}

// Active AND inactive ("shell") orgs are both returned — matches the
// ancestor's "site_admin needs to see all orgs that may be candidates
// for linking" intent — while status derivation distinguishes them.
func TestOrgExportCandidates_ActiveAndInactiveBothIncluded_StatusDerived(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	activeID := uuid.New()
	inactiveID := uuid.New()
	seedExportOrg(t, eng, activeID, "active-org", true)
	seedExportOrg(t, eng, inactiveID, "inactive-org", false)

	rec := doIdentityJSON(t, eng, http.MethodGet, "/api/v1/organizations/export-candidates", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Organizations []organizationExportCandidate `json:"organizations"`
		Total         int                           `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 2 {
		t.Fatalf("total=%d, want 2 (active + inactive both surfaced)", body.Total)
	}
	statuses := map[uuid.UUID]string{}
	for _, o := range body.Organizations {
		statuses[o.ID] = o.Status
	}
	if statuses[activeID] != "active" {
		t.Errorf("active org status = %q, want active", statuses[activeID])
	}
	if statuses[inactiveID] != "disabled" {
		t.Errorf("inactive org status = %q, want disabled", statuses[inactiveID])
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
