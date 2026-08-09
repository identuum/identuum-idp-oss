package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// stubOrgRecoveryRepo satisfies repository.OrganizationRepository by
// embedding the interface (all methods nil) and overriding only GetByID
// — the sole method HandleListOrgAdminRecoveryCandidates calls. A nil
// `org` with a nil `err` models "organization not found".
type stubAdminRecOrgRepo struct {
	repository.OrganizationRepository
	org *domain.Organization
	err error
}

func (s stubAdminRecOrgRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	return s.org, s.err
}

// stubRecoveryMemberLister implements the OrgMemberLister seam with an
// in-memory, pagination-aware slice so tests control exactly which org
// members the handler sees (and so the handler's paging loop is
// exercised honestly).
type stubAdminRecMemberLister struct {
	users []*domain.User
	err   error
}

func (s stubAdminRecMemberLister) ListByOrganization(ctx context.Context, orgID uuid.UUID, opts repository.ListUserOptions) ([]*domain.User, int, error) {
	if s.err != nil {
		return nil, 0, s.err
	}
	off := opts.Pagination.Offset
	if off < 0 || off >= len(s.users) {
		return []*domain.User{}, len(s.users), nil
	}
	end := off + opts.Pagination.PageSize
	if end > len(s.users) {
		end = len(s.users)
	}
	return s.users[off:end], len(s.users), nil
}

func newAdminRecEngine(t *testing.T, principal *domain.Principal, deps OrganizationsHandlerDeps) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	RegisterOrganizationsRoutes(r, deps)
	return r
}

func doAdminRecGET(t *testing.T, r *gin.Engine, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// recoveryTestUsers returns a membership containing one org_admin (the
// sole recovery candidate), one org_user, and one site_admin. The
// org_user and site_admin MUST be filtered out — the site_admin case
// guards against using domain.User.IsOrgAdmin() (which is true for
// site_admin) instead of the strict role-constant match.
func adminRecTestUsers(orgID uuid.UUID) []*domain.User {
	name := "Ada Admin"
	last := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	return []*domain.User{
		{
			ID:             uuid.New(),
			OrganizationID: orgID,
			Email:          "admin@tenant.test",
			Name:           &name,
			Role:           domain.RoleOrgAdmin,
			MFAEnabled:     true,
			EmailVerified:  true,
			CreatedAt:      time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC),
			LastLoginAt:    &last,
		},
		{
			ID:             uuid.New(),
			OrganizationID: orgID,
			Email:          "user@tenant.test",
			Role:           domain.RoleOrgUser,
		},
		{
			ID:             uuid.New(),
			OrganizationID: orgID,
			Email:          "site@system.test",
			Role:           domain.RoleSiteAdmin,
		},
	}
}

// (a) The endpoint no longer returns 501; a site_admin gets the real
// recovery list (org_admin only; org_user + site_admin filtered out).
func TestOrgAdminRecovery_SiteAdmin_Returns200NotDeferred(t *testing.T) {
	orgID := uuid.New()
	r := newAdminRecEngine(t, siteAdminPrincipal(), OrganizationsHandlerDeps{
		OrganizationRepo: stubAdminRecOrgRepo{org: &domain.Organization{ID: orgID}},
		MemberLister:     stubAdminRecMemberLister{users: adminRecTestUsers(orgID)},
	})
	rec := doAdminRecGET(t, r, "/api/v1/organizations/"+orgID.String()+"/admin-recovery-candidates")
	if rec.Code == http.StatusNotImplemented {
		t.Fatalf("endpoint still returns 501 (deferred) — the OSS port did not take effect")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp orgAdminRecoveryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Admins) != 1 {
		t.Fatalf("admins len = %d, want 1 (org_admin only; org_user + site_admin filtered)", len(resp.Admins))
	}
	if resp.Admins[0].Email != "admin@tenant.test" {
		t.Errorf("candidate email = %q, want admin@tenant.test", resp.Admins[0].Email)
	}
}

// (b) Authorization: a non-site_admin caller is rejected 403 by the
// siteOnly group's RequireSiteAdmin gate — consistent with the sibling
// org lifecycle routes.
func TestOrgAdminRecovery_NonSiteAdmin_Forbidden(t *testing.T) {
	orgID := uuid.New()
	r := newAdminRecEngine(t, &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgAdmin}, OrganizationsHandlerDeps{
		OrganizationRepo: stubAdminRecOrgRepo{org: &domain.Organization{ID: orgID}},
		MemberLister:     stubAdminRecMemberLister{users: adminRecTestUsers(orgID)},
	})
	rec := doAdminRecGET(t, r, "/api/v1/organizations/"+orgID.String()+"/admin-recovery-candidates")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-site_admin status = %d, want 403", rec.Code)
	}
}

// (b') Unauthenticated (no principal) is rejected 401 by the gate.
func TestOrgAdminRecovery_Unauthenticated_401(t *testing.T) {
	orgID := uuid.New()
	r := newAdminRecEngine(t, nil, OrganizationsHandlerDeps{
		OrganizationRepo: stubAdminRecOrgRepo{org: &domain.Organization{ID: orgID}},
		MemberLister:     stubAdminRecMemberLister{users: adminRecTestUsers(orgID)},
	})
	rec := doAdminRecGET(t, r, "/api/v1/organizations/"+orgID.String()+"/admin-recovery-candidates")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rec.Code)
	}
}

// (c) The response contract matches the CE reference: the {admins:[...]}
// envelope and every snake_case candidate field, with OSS emitting real
// values for mfa_enabled / email_verified / last_login_at.
func TestOrgAdminRecovery_ResponseContractMatchesCE(t *testing.T) {
	orgID := uuid.New()
	users := adminRecTestUsers(orgID)
	r := newAdminRecEngine(t, siteAdminPrincipal(), OrganizationsHandlerDeps{
		OrganizationRepo: stubAdminRecOrgRepo{org: &domain.Organization{ID: orgID}},
		MemberLister:     stubAdminRecMemberLister{users: users},
	})
	rec := doAdminRecGET(t, r, "/api/v1/organizations/"+orgID.String()+"/admin-recovery-candidates")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Envelope shape: top-level `admins`.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if _, ok := envelope["admins"]; !ok {
		t.Fatalf("response missing top-level `admins` key (CE envelope shape)")
	}

	// Candidate wire keys must exactly cover the CE contract.
	var rawList struct {
		Admins []map[string]json.RawMessage `json:"admins"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rawList); err != nil {
		t.Fatalf("decode raw list: %v", err)
	}
	if len(rawList.Admins) != 1 {
		t.Fatalf("admins len=%d want 1", len(rawList.Admins))
	}
	for _, k := range []string{"id", "email", "name", "role", "mfa_enabled", "email_verified", "active", "deleted", "created_at", "last_login_at"} {
		if _, ok := rawList.Admins[0][k]; !ok {
			t.Errorf("candidate missing wire key %q (CE contract)", k)
		}
	}

	// Field semantics.
	var resp orgAdminRecoveryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode typed: %v", err)
	}
	got := resp.Admins[0]
	if got.ID != users[0].ID.String() {
		t.Errorf("id=%q want %q", got.ID, users[0].ID.String())
	}
	if got.Role != "org_admin" {
		t.Errorf("role=%q want org_admin", got.Role)
	}
	if !got.MFAEnabled {
		t.Errorf("mfa_enabled=false want true (OSS real column)")
	}
	if !got.EmailVerified {
		t.Errorf("email_verified=false want true (OSS real column)")
	}
	if !got.Active {
		t.Errorf("active=false want true (not banned, not deleted)")
	}
	if got.Deleted {
		t.Errorf("deleted=true want false")
	}
	if got.Name != "Ada Admin" {
		t.Errorf("name=%q want Ada Admin", got.Name)
	}
	if got.CreatedAt == "" {
		t.Errorf("created_at empty; want RFC3339 timestamp")
	}
	if got.LastLoginAt == "" {
		t.Errorf("last_login_at empty; want RFC3339 timestamp (OSS real column)")
	}
}

// (d) Empty/edge: an org with members but zero org_admins returns a
// well-formed empty array, not null and not an error.
func TestOrgAdminRecovery_NoAdmins_EmptyArrayNotError(t *testing.T) {
	orgID := uuid.New()
	onlyUser := []*domain.User{{ID: uuid.New(), OrganizationID: orgID, Email: "u@tenant.test", Role: domain.RoleOrgUser}}
	r := newAdminRecEngine(t, siteAdminPrincipal(), OrganizationsHandlerDeps{
		OrganizationRepo: stubAdminRecOrgRepo{org: &domain.Organization{ID: orgID}},
		MemberLister:     stubAdminRecMemberLister{users: onlyUser},
	})
	rec := doAdminRecGET(t, r, "/api/v1/organizations/"+orgID.String()+"/admin-recovery-candidates")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s want 200", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"admins":[]}` {
		t.Fatalf("body=%q want {\"admins\":[]}", got)
	}
}

// Edge: an unknown org id is an honest 404, not an empty list.
func TestOrgAdminRecovery_UnknownOrg_404(t *testing.T) {
	orgID := uuid.New()
	r := newAdminRecEngine(t, siteAdminPrincipal(), OrganizationsHandlerDeps{
		OrganizationRepo: stubAdminRecOrgRepo{org: nil},
		MemberLister:     stubAdminRecMemberLister{},
	})
	rec := doAdminRecGET(t, r, "/api/v1/organizations/"+orgID.String()+"/admin-recovery-candidates")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 (unknown org)", rec.Code)
	}
}

// Edge: the System Organization is infrastructure and is never surfaced
// through the tenant org tree — 404.
func TestOrgAdminRecovery_SystemOrg_404(t *testing.T) {
	r := newAdminRecEngine(t, siteAdminPrincipal(), OrganizationsHandlerDeps{
		OrganizationRepo: stubAdminRecOrgRepo{org: &domain.Organization{}},
		MemberLister:     stubAdminRecMemberLister{},
	})
	rec := doAdminRecGET(t, r, "/api/v1/organizations/"+domain.SystemOrgID+"/admin-recovery-candidates")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 (System Org never surfaced)", rec.Code)
	}
}

// Edge: a non-UUID :id is a 400, before any backend lookup.
func TestOrgAdminRecovery_InvalidID_400(t *testing.T) {
	r := newAdminRecEngine(t, siteAdminPrincipal(), OrganizationsHandlerDeps{
		OrganizationRepo: stubAdminRecOrgRepo{org: &domain.Organization{}},
		MemberLister:     stubAdminRecMemberLister{},
	})
	rec := doAdminRecGET(t, r, "/api/v1/organizations/not-a-uuid/admin-recovery-candidates")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (invalid id)", rec.Code)
	}
}

// Edge: an unwired member-lister fails closed with 503 rather than a
// misleading empty list.
func TestOrgAdminRecovery_UnwiredLister_503(t *testing.T) {
	orgID := uuid.New()
	r := newAdminRecEngine(t, siteAdminPrincipal(), OrganizationsHandlerDeps{
		OrganizationRepo: stubAdminRecOrgRepo{org: &domain.Organization{ID: orgID}},
		// MemberLister deliberately nil.
	})
	rec := doAdminRecGET(t, r, "/api/v1/organizations/"+orgID.String()+"/admin-recovery-candidates")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 (member lister unwired)", rec.Code)
	}
}
