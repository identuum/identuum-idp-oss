package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// memProtoSettingsRepoForHandlers is an in-memory
// OrganizationProtocolSettingsRepository tailored for the
// handler tests in this file.
type memProtoSettingsRepoForHandlers struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.OrganizationProtocolSettings
}

func newMemProtoSettingsRepoForHandlers() *memProtoSettingsRepoForHandlers {
	return &memProtoSettingsRepoForHandlers{rows: map[uuid.UUID]*domain.OrganizationProtocolSettings{}}
}

func (r *memProtoSettingsRepoForHandlers) GetByOrgID(_ context.Context, orgID uuid.UUID) (*domain.OrganizationProtocolSettings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[orgID]
	if !ok {
		return nil, repository.ErrOrganizationProtocolSettingsNotFound
	}
	cp := *row
	return &cp, nil
}

func (r *memProtoSettingsRepoForHandlers) Upsert(_ context.Context, s *domain.OrganizationProtocolSettings) (*domain.OrganizationProtocolSettings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *s
	now := time.Now().UTC()
	if existing, ok := r.rows[s.OrganizationID]; ok {
		cp.CreatedAt = existing.CreatedAt
	} else {
		cp.CreatedAt = now
	}
	cp.UpdatedAt = now
	r.rows[s.OrganizationID] = &cp
	cp2 := cp
	return &cp2, nil
}

// orgProtoAdminEngine wires the admin handler + the
// underlying services against in-memory repos.
type orgProtoAdminEngine struct {
	r          *gin.Engine
	orgRepo    *memOrgRepo
	protoRepo  *memProtoSettingsRepoForHandlers
	clientRepo *memClientRepo
	iatRepo    *memIATRepo
	userRepo   *memUserRepo
	rec        *audit.Recorder
	protoSvc   *service.OrganizationProtocolSettingsService
	iatSvc     *service.DCRInitialAccessTokenService
}

func newOrgProtoAdminEngine(t *testing.T, principal *domain.Principal) orgProtoAdminEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	orgRepo := newMemOrgRepo()
	protoRepo := newMemProtoSettingsRepoForHandlers()
	clientRepo := newMemClientRepo()
	iatRepo := newMemIATRepo()
	userRepo := newMemUserRepo()
	rec := &audit.Recorder{}

	orgSvc := service.NewOrganizationService(nil, orgRepo)
	protoSvc := service.NewOrganizationProtocolSettingsService(nil, protoRepo)
	clientSvc := service.NewClientService(nil, clientRepo)
	iatSvc := service.NewDCRInitialAccessTokenService(nil, iatRepo)

	RegisterOrganizationProtocolSettingsRoutes(r, OrganizationProtocolSettingsHandlerDeps{
		ProtocolSettingsService: protoSvc,
		OrganizationService:     orgSvc,
		Audit:                   rec,
	})
	// Also mount DCR with the real OrgFeatureLookup so the "DCR
	// route observes setting after admin PUT" test can exercise
	// the end-to-end path. (SCIM was removed — see
	// docs/audit/changelog/scim-oss-leak-removal.md.)
	RegisterDCRRoutes(r, DCRHandlerDeps{
		ClientService:       clientSvc,
		IATService:          iatSvc,
		RegistrationBaseURL: "https://idp.example.com",
		Audit:               rec,
		OrgFeatureLookup:    protoSvc,
	})
	return orgProtoAdminEngine{
		r: r, orgRepo: orgRepo, protoRepo: protoRepo, clientRepo: clientRepo,
		iatRepo: iatRepo, userRepo: userRepo, rec: rec, protoSvc: protoSvc, iatSvc: iatSvc,
	}
}

func adminJSON(t *testing.T, eng orgProtoAdminEngine, method, path string, body any, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf.Write(b)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	eng.r.ServeHTTP(rec, req)
	return rec
}

// seedProtoOrg creates an active org so the admin handler's
// existence check passes.
func seedProtoOrg(t *testing.T, eng orgProtoAdminEngine) uuid.UUID {
	t.Helper()
	id := uuid.New()
	eng.orgRepo.rows[id] = &domain.Organization{
		ID:     id,
		Name:   "Tenant",
		Domain: id.String() + ".test",
		Active: true,
	}
	return id
}

// newProtoOrgAdminSeeded is the THE-REMAINING-FOUR replacement for the
// site_admin-driven setup: protocol-settings answer to the org's own org_admin
// now, so the engine's actor is a full-scope org_admin and the seeded active
// org is ITS org. Returns the engine and that org id.
func newProtoOrgAdminSeeded(t *testing.T) (orgProtoAdminEngine, uuid.UUID) {
	t.Helper()
	org := uuid.New()
	eng := newOrgProtoAdminEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          domain.SessionScopesForRole(domain.RoleOrgAdmin),
	})
	eng.orgRepo.rows[org] = &domain.Organization{
		ID:     org,
		Name:   "Tenant",
		Domain: org.String() + ".test",
		Active: true,
	}
	return eng, org
}

// TestOrgProtoAdmin_GetAbsentReturnsDefaultFalse pins the
// system default: a GET against an org with no settings row
// returns {dcr=false, scim=false, source=default}.
func TestOrgProtoAdmin_GetAbsentReturnsDefaultFalse(t *testing.T) {
	eng, id := newProtoOrgAdminSeeded(t)
	rec := adminJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+id.String()+"/protocol-settings", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var resp organizationProtocolSettingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.DynamicClientRegistrationEnabled || resp.SCIMEnabled {
		t.Errorf("absent row → {DCR=%v SCIM=%v}, want {false false}", resp.DynamicClientRegistrationEnabled, resp.SCIMEnabled)
	}
	if resp.Source != "default" {
		t.Errorf("source = %q, want \"default\"", resp.Source)
	}
	if resp.CreatedAt != nil || resp.UpdatedAt != nil {
		t.Errorf("absent row → no timestamps, got created=%v updated=%v", resp.CreatedAt, resp.UpdatedAt)
	}
}

// TestOrgProtoAdmin_PutCreatesRowAndAudit pins the create
// path: PUT on a fresh org creates the row, returns 200 with
// source=explicit, and emits the org.protocol_settings_changed
// audit event with safe metadata.
func TestOrgProtoAdmin_PutCreatesRowAndAudit(t *testing.T) {
	eng, id := newProtoOrgAdminSeeded(t)
	rec := adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        false,
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var resp organizationProtocolSettingsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.DynamicClientRegistrationEnabled || resp.SCIMEnabled {
		t.Errorf("after PUT {true, false} → {DCR=%v SCIM=%v}", resp.DynamicClientRegistrationEnabled, resp.SCIMEnabled)
	}
	if resp.Source != "explicit" {
		t.Errorf("source = %q, want \"explicit\"", resp.Source)
	}
	events := eng.rec.Events()
	if len(events) != 1 || events[0].Action != "org.protocol_settings_changed" {
		t.Fatalf("expected one org.protocol_settings_changed audit event, got %+v", events)
	}
	meta := events[0].Metadata
	if meta["target_organization_id"] != id.String() {
		t.Errorf("audit target_organization_id = %v, want %s", meta["target_organization_id"], id)
	}
	// THE-REMAINING-FOUR: the actor is the org's own org_admin now.
	if meta["actor_kind"] != "org_admin" {
		t.Errorf("audit actor_kind = %v, want org_admin", meta["actor_kind"])
	}
	if meta["old_dynamic_client_registration_enabled"] != false || meta["new_dynamic_client_registration_enabled"] != true {
		t.Errorf("audit dcr old/new = %v/%v, want false/true", meta["old_dynamic_client_registration_enabled"], meta["new_dynamic_client_registration_enabled"])
	}
	if meta["new_scim_enabled"] != false {
		t.Errorf("audit new_scim_enabled = %v, want false", meta["new_scim_enabled"])
	}
	if meta["actor_role"] != "org_admin" {
		t.Errorf("audit actor_role = %v, want org_admin", meta["actor_role"])
	}
	// The org_admin actor carries its OrganizationID, so the audit MUST
	// surface actor_organization_id so a consumer can correlate the actor
	// to a tenant; only a principal with OrganizationID == uuid.Nil omits
	// the field (defensive omission for the SystemActor case).
	if _, present := meta["actor_organization_id"]; !present {
		t.Errorf("audit must include actor_organization_id when principal carries one")
	}
}

// TestOrgProtoAdmin_GetAfterPutReturnsExplicit pins the
// roundtrip: PUT then GET returns the persisted values with
// source=explicit and non-nil timestamps.
func TestOrgProtoAdmin_GetAfterPutReturnsExplicit(t *testing.T) {
	eng, id := newProtoOrgAdminSeeded(t)
	_ = adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}, "")
	rec := adminJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+id.String()+"/protocol-settings", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp organizationProtocolSettingsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.DynamicClientRegistrationEnabled || !resp.SCIMEnabled {
		t.Errorf("GET after PUT → {DCR=%v SCIM=%v}, want both true", resp.DynamicClientRegistrationEnabled, resp.SCIMEnabled)
	}
	if resp.Source != "explicit" {
		t.Errorf("source = %q, want explicit", resp.Source)
	}
	if resp.CreatedAt == nil || resp.UpdatedAt == nil {
		t.Errorf("explicit row must have non-nil timestamps")
	}
}

// TestOrgProtoAdmin_PutAuditCarriesBeforeAfterDelta pins that
// a SECOND PUT carries the prior row's values as the
// before/old fields and the new values as the new fields.
func TestOrgProtoAdmin_PutAuditCarriesBeforeAfterDelta(t *testing.T) {
	eng, id := newProtoOrgAdminSeeded(t)
	_ = adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}, "")
	eng.rec.Reset()
	_ = adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": false,
		"scim_enabled":                        true,
	}, "")
	events := eng.rec.Events()
	if len(events) != 1 {
		t.Fatalf("expected one audit event, got %d", len(events))
	}
	meta := events[0].Metadata
	if meta["old_dynamic_client_registration_enabled"] != true || meta["new_dynamic_client_registration_enabled"] != false {
		t.Errorf("dcr delta: got %v→%v, want true→false", meta["old_dynamic_client_registration_enabled"], meta["new_dynamic_client_registration_enabled"])
	}
	if meta["old_scim_enabled"] != true || meta["new_scim_enabled"] != true {
		t.Errorf("scim delta: got %v→%v, want true→true (no change)", meta["old_scim_enabled"], meta["new_scim_enabled"])
	}
}

// TestOrgProtoAdmin_OrgAdminWithoutScopeForbidden pins that an
// org_admin LACKING the per-verb scope is rejected with 403
// even when acting on its own organization. Replaces the prior
// site-admin-only assertion (org_admin same-org access is now
// allowed by this slice — but only with the correct scope).
func TestOrgProtoAdmin_OrgAdminWithoutScopeForbidden(t *testing.T) {
	id := uuid.New()
	eng := newOrgProtoAdminEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: id,
		Role:           domain.RoleOrgAdmin,
		// No Scope set — the gate must deny.
	})
	eng.orgRepo.rows[id] = &domain.Organization{ID: id, Name: "T", Domain: "t.test", Active: true}
	if rec := adminJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+id.String()+"/protocol-settings", nil, ""); rec.Code != http.StatusForbidden {
		t.Errorf("GET as org_admin (no scope): status = %d, want 403", rec.Code)
	}
	if rec := adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}, ""); rec.Code != http.StatusForbidden {
		t.Errorf("PUT as org_admin (no scope): status = %d, want 403", rec.Code)
	}
}

// TestOrgProtoAdmin_UnauthenticatedUnauthorized pins that no
// principal returns 401.
func TestOrgProtoAdmin_UnauthenticatedUnauthorized(t *testing.T) {
	eng := newOrgProtoAdminEngine(t, nil)
	id := seedProtoOrg(t, eng)
	rec := adminJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+id.String()+"/protocol-settings", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestOrgProtoAdmin_UnknownOrgReturns404 pins that GET/PUT
// against an unknown org id returns 404 (no row created on
// PUT, no enumeration leak on GET).
func TestOrgProtoAdmin_UnknownOrgReturns404(t *testing.T) {
	// THE-REMAINING-FOUR: the actor is the org's OWN org_admin; the route
	// targets its own (unseeded) org so the handler's 404 is reached (a
	// cross-org route would 403 at the middleware before the handler).
	missingID := uuid.New()
	eng := newOrgProtoAdminEngine(t, &domain.Principal{
		UserID: uuid.New(), OrganizationID: missingID, Role: domain.RoleOrgAdmin,
		Scope: domain.SessionScopesForRole(domain.RoleOrgAdmin),
	})
	missing := missingID.String()
	if rec := adminJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+missing+"/protocol-settings", nil, ""); rec.Code != http.StatusNotFound {
		t.Errorf("GET unknown: status = %d, want 404", rec.Code)
	}
	if rec := adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+missing+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}, ""); rec.Code != http.StatusNotFound {
		t.Errorf("PUT unknown: status = %d, want 404", rec.Code)
	}
}

// TestOrgProtoAdmin_DeletedOrgReturns404 pins that a
// soft-deleted org is invisible to the admin surface.
func TestOrgProtoAdmin_DeletedOrgReturns404(t *testing.T) {
	id := uuid.New()
	eng := newOrgProtoAdminEngine(t, &domain.Principal{
		UserID: uuid.New(), OrganizationID: id, Role: domain.RoleOrgAdmin,
		Scope: domain.SessionScopesForRole(domain.RoleOrgAdmin),
	})
	deleted := time.Now()
	eng.orgRepo.rows[id] = &domain.Organization{
		ID: id, Name: "T", Domain: "t.test", Active: false, DeletedAt: &deleted,
	}
	rec := adminJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+id.String()+"/protocol-settings", nil, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET deleted: status = %d, want 404", rec.Code)
	}
}

// TestOrgProtoAdmin_PutRequiresBothBooleans pins the partial-
// update rejection: both booleans MUST be present.
func TestOrgProtoAdmin_PutRequiresBothBooleans(t *testing.T) {
	eng, id := newProtoOrgAdminSeeded(t)
	for _, payload := range []map[string]any{
		{"dynamic_client_registration_enabled": true}, // missing scim
		{"scim_enabled": true},                        // missing dcr
		{},                                            // missing both
	} {
		rec := adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id.String()+"/protocol-settings", payload, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("payload %v: status = %d, want 400", payload, rec.Code)
		}
	}
}

// TestOrgProtoAdmin_DCRRouteObservesSettingAfterPut pins the
// end-to-end contract: flipping DCR on for org X via the admin
// PUT actually unblocks DCR via that org's IAT.
func TestOrgProtoAdmin_DCRRouteObservesSettingAfterPut(t *testing.T) {
	eng, id := newProtoOrgAdminSeeded(t)
	// Mint an org-bound IAT.
	res, err := eng.iatSvc.Issue(context.Background(), service.IssueOptions{
		TTL: time.Hour, MaxUses: 2, OrganizationID: &id,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// 1. Before admin PUT, DCR is disabled for `id` → 403.
	if rec := adminJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Phase1",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, res.RawIAT); rec.Code != http.StatusForbidden {
		t.Fatalf("pre-PUT DCR: status = %d, want 403", rec.Code)
	}
	// 2. Admin PUT flips DCR on.
	if rec := adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        false,
	}, ""); rec.Code != http.StatusOK {
		t.Fatalf("admin PUT: status = %d", rec.Code)
	}
	// 3. Post-PUT, DCR succeeds.
	if rec := adminJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Phase2",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, res.RawIAT); rec.Code != http.StatusCreated {
		t.Fatalf("post-PUT DCR: status = %d, want 201", rec.Code)
	}
}

// (TestOrgProtoAdmin_SCIMRouteObservesSettingAfterPut was removed with the
// SCIM v2 surface — see docs/audit/changelog/scim-oss-leak-removal.md. The
// per-org protocol-settings PUT/GET coverage for the scim_enabled FIELD is
// retained above; only the SCIM-ROUTE end-to-end probe was excised.)

// TestOrgProtoAdmin_AuditNoTokenLeakage pins the secret-leak
// guard: a request with a sentinel Authorization header MUST
// NOT cause the sentinel to appear in the audit metadata.
func TestOrgProtoAdmin_AuditNoTokenLeakage(t *testing.T) {
	eng, id := newProtoOrgAdminSeeded(t)
	sentinel := "SECRET-BEARER-MUST-NOT-LEAK"
	_ = adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}, sentinel)
	events := eng.rec.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	for k, v := range events[0].Metadata {
		if s, ok := v.(string); ok && strings.Contains(s, sentinel) {
			t.Errorf("audit metadata key %q leaks bearer sentinel: %v", k, v)
		}
	}
}

// orgAdminWithScope is a small helper that constructs an
// org_admin principal scoped to a specific organization id
// with the supplied scope set. Used by the org_admin self-
// service tests below.
func orgAdminWithScope(orgID uuid.UUID, scope string) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgAdmin,
		Scope:          scope,
	}
}

// TestOrgProtoAdmin_OrgAdminSameOrgGetWorks pins that a
// same-org org_admin with `orgs:read` can read its own org's
// protocol settings.
func TestOrgProtoAdmin_OrgAdminSameOrgGetWorks(t *testing.T) {
	actorOrg := uuid.New()
	eng := newOrgProtoAdminEngine(t, orgAdminWithScope(actorOrg, domain.ScopeOrgsRead))
	eng.orgRepo.rows[actorOrg] = &domain.Organization{ID: actorOrg, Name: "Tenant", Domain: "t.test", Active: true}
	rec := adminJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+actorOrg.String()+"/protocol-settings", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var resp organizationProtocolSettingsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.OrganizationID != actorOrg {
		t.Errorf("organization_id = %s; want %s", resp.OrganizationID, actorOrg)
	}
	if resp.Source != "default" {
		t.Errorf("source = %q; want default", resp.Source)
	}
}

// TestOrgProtoAdmin_OrgAdminSameOrgPutWorks pins that a
// same-org org_admin with `orgs:settings:update` can flip its
// own org's protocol settings, and that the audit event
// carries `actor_kind=org_admin` + `actor_organization_id` =
// the target org id (since same-org PUT means actor == target).
func TestOrgProtoAdmin_OrgAdminSameOrgPutWorks(t *testing.T) {
	actorOrg := uuid.New()
	eng := newOrgProtoAdminEngine(t, orgAdminWithScope(actorOrg, domain.ScopeOrgsSettingsUpdate))
	eng.orgRepo.rows[actorOrg] = &domain.Organization{ID: actorOrg, Name: "Tenant", Domain: "t.test", Active: true}
	rec := adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+actorOrg.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	events := eng.rec.Events()
	if len(events) != 1 || events[0].Action != "org.protocol_settings_changed" {
		t.Fatalf("expected one org.protocol_settings_changed event, got %+v", events)
	}
	meta := events[0].Metadata
	if meta["actor_kind"] != "org_admin" {
		t.Errorf("actor_kind = %v, want org_admin", meta["actor_kind"])
	}
	if meta["target_organization_id"] != actorOrg.String() {
		t.Errorf("target_organization_id = %v, want %s", meta["target_organization_id"], actorOrg)
	}
	if meta["actor_organization_id"] != actorOrg.String() {
		t.Errorf("actor_organization_id = %v, want %s (same-org PUT)", meta["actor_organization_id"], actorOrg)
	}
}

// TestOrgProtoAdmin_OrgAdminCrossOrgGetForbidden pins the
// cross-org enumeration block: an org_admin with `orgs:read`
// trying to read a DIFFERENT org's settings is rejected 403
// by the shared scope middleware BEFORE the handler runs.
// The 403 is the existing project convention (NOT 404) so
// the response shape matches every other org-scoped admin
// route.
func TestOrgProtoAdmin_OrgAdminCrossOrgGetForbidden(t *testing.T) {
	actorOrg := uuid.New()
	targetOrg := uuid.New()
	eng := newOrgProtoAdminEngine(t, orgAdminWithScope(actorOrg, domain.ScopeOrgsRead))
	eng.orgRepo.rows[targetOrg] = &domain.Organization{ID: targetOrg, Name: "Other", Domain: "other.test", Active: true}
	rec := adminJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+targetOrg.String()+"/protocol-settings", nil, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-org GET: status = %d, want 403", rec.Code)
	}
}

// TestOrgProtoAdmin_OrgAdminCrossOrgPutForbidden pins the
// cross-org write block + the "no DB mutation on a denied
// request" invariant.
func TestOrgProtoAdmin_OrgAdminCrossOrgPutForbidden(t *testing.T) {
	actorOrg := uuid.New()
	targetOrg := uuid.New()
	eng := newOrgProtoAdminEngine(t, orgAdminWithScope(actorOrg, domain.ScopeOrgsSettingsUpdate))
	eng.orgRepo.rows[targetOrg] = &domain.Organization{ID: targetOrg, Name: "Other", Domain: "other.test", Active: true}
	rec := adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+targetOrg.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-org PUT: status = %d, want 403", rec.Code)
	}
	if _, ok := eng.protoRepo.rows[targetOrg]; ok {
		t.Errorf("cross-org PUT must not write target row; got row %+v", eng.protoRepo.rows[targetOrg])
	}
	if len(eng.rec.Events()) != 0 {
		t.Errorf("cross-org denied PUT must not emit audit event; got %+v", eng.rec.Events())
	}
}

// TestOrgProtoAdmin_OrgAdminWrongScopeForbidden pins that an
// org_admin with `orgs:read` (only) cannot reach the PUT
// route — the per-verb scope mismatch is itself a denial even
// for a same-org actor.
func TestOrgProtoAdmin_OrgAdminWrongScopeForbidden(t *testing.T) {
	actorOrg := uuid.New()
	eng := newOrgProtoAdminEngine(t, orgAdminWithScope(actorOrg, domain.ScopeOrgsRead))
	eng.orgRepo.rows[actorOrg] = &domain.Organization{ID: actorOrg, Name: "T", Domain: "t.test", Active: true}
	rec := adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+actorOrg.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("PUT with read-only scope: status = %d, want 403", rec.Code)
	}
}

// TestOrgProtoAdmin_OrgAdminCannotPutDeletedOwnOrg pins that
// an org_admin acting on a soft-deleted org gets 404 (same
// shape as the site_admin path — the deleted-org guard runs
// inside the handler after the auth gate).
func TestOrgProtoAdmin_OrgAdminCannotPutDeletedOwnOrg(t *testing.T) {
	actorOrg := uuid.New()
	eng := newOrgProtoAdminEngine(t, orgAdminWithScope(actorOrg, domain.ScopeOrgsSettingsUpdate))
	deleted := time.Now()
	eng.orgRepo.rows[actorOrg] = &domain.Organization{
		ID: actorOrg, Name: "T", Domain: "t.test", Active: false, DeletedAt: &deleted,
	}
	rec := adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+actorOrg.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("deleted own-org PUT: status = %d, want 404", rec.Code)
	}
}

// TestOrgProtoAdmin_DCRRouteObservesOrgAdminPut pins the end-
// to-end: an org_admin same-org PUT actually unblocks the
// org's DCR routes via the per-org gate.
func TestOrgProtoAdmin_DCRRouteObservesOrgAdminPut(t *testing.T) {
	actorOrg := uuid.New()
	eng := newOrgProtoAdminEngine(t, orgAdminWithScope(actorOrg, domain.ScopeOrgsSettingsUpdate))
	eng.orgRepo.rows[actorOrg] = &domain.Organization{ID: actorOrg, Name: "T", Domain: "t.test", Active: true}
	// Mint an org-bound IAT via the service.
	res, err := eng.iatSvc.Issue(context.Background(), service.IssueOptions{
		TTL: time.Hour, MaxUses: 2, OrganizationID: &actorOrg,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// 1. Pre-PUT: per-org gate denies (default false).
	if rec := adminJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Pre",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, res.RawIAT); rec.Code != http.StatusForbidden {
		t.Fatalf("pre-PUT DCR: status = %d, want 403", rec.Code)
	}
	// 2. org_admin same-org PUT flips DCR on for their own org.
	if rec := adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+actorOrg.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        false,
	}, ""); rec.Code != http.StatusOK {
		t.Fatalf("org_admin PUT: status = %d", rec.Code)
	}
	// 3. Post-PUT: per-org gate now permits.
	if rec := adminJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Post",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, res.RawIAT); rec.Code != http.StatusCreated {
		t.Fatalf("post-PUT DCR: status = %d, want 201", rec.Code)
	}
}

// expectedSafeAuditKeys is the closed allow-list of metadata
// keys the org.protocol_settings_changed audit event may carry.
// The hardening test below pins both directions: every required
// key MUST be present on a same-org org_admin PUT (the densest
// metadata case), AND every emitted key MUST be a member of
// this set. A future field addition MUST land in BOTH this
// allow-list AND the handler — otherwise the audit consumer
// silently grows a field the security review never saw.
var expectedSafeAuditKeys = map[string]struct{}{
	"target_organization_id": {},
	"actor_kind":             {},
	"actor_role":             {},
	"actor_organization_id":  {},
	"old_dynamic_client_registration_enabled": {},
	"old_scim_enabled":                        {},
	"new_dynamic_client_registration_enabled": {},
	"new_scim_enabled":                        {},
}

// forbiddenAuditSubstrings is the closed deny-list of
// substrings the audit event MUST NEVER carry inside any
// string-typed metadata value. Mirrors the project-wide
// cleanliness scan: JWT prefix, PEM blocks, common DB URL
// prefixes, and a representative sample of credentialed
// shapes.
var forbiddenAuditSubstrings = []string{
	"eyJ",                                  // JWT
	"-----BEGIN ",                          // any PEM block
	"postgres://",                          // libpq URL
	"mysql://",                             // mysql URL
	"sk-live_", "sk_live_", "ghp_", "gho_", // common credentialed token prefixes
}

// TestOrgProtoAdmin_AuditSchemaIsClosed pins the audit
// metadata SCHEMA: every required key is present on a
// same-org org_admin PUT (the densest case, where
// actor_organization_id is set), AND no extra key has been
// silently added.
func TestOrgProtoAdmin_AuditSchemaIsClosed(t *testing.T) {
	actorOrg := uuid.New()
	eng := newOrgProtoAdminEngine(t, orgAdminWithScope(actorOrg, domain.ScopeOrgsSettingsUpdate))
	eng.orgRepo.rows[actorOrg] = &domain.Organization{ID: actorOrg, Name: "T", Domain: "t.test", Active: true}
	rec := adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+actorOrg.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d", rec.Code)
	}
	events := eng.rec.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	got := events[0].Metadata
	// Direction 1: every required key present.
	for k := range expectedSafeAuditKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("audit metadata MISSING required key %q (full payload: %+v)", k, got)
		}
	}
	// Direction 2: no extra key beyond the allow-list.
	for k := range got {
		if _, ok := expectedSafeAuditKeys[k]; !ok {
			t.Errorf("audit metadata carries UNEXPECTED key %q = %v — add to expectedSafeAuditKeys after security review", k, got[k])
		}
	}
}

// TestOrgProtoAdmin_AuditNoCredentialMaterial pins the no-
// secret-substring invariant across the FULL request shape: a
// PUT carrying a sentinel Bearer is asserted to NOT leak ANY
// of the project-wide forbidden substrings into ANY
// string-typed audit metadata value.
//
// The test is intentionally paranoid: it scans every string-
// typed metadata value against the deny-list AND against the
// caller-supplied bearer sentinel. A failure here means either
// the handler started emitting a sensitive substring OR a
// future code change widened the leakage surface.
func TestOrgProtoAdmin_AuditNoCredentialMaterial(t *testing.T) {
	eng, id := newProtoOrgAdminSeeded(t)
	const sentinelBearer = "SECRET-BEARER-MUST-NOT-LEAK"
	_ = adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id.String()+"/protocol-settings", map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}, sentinelBearer)
	events := eng.rec.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	for k, v := range events[0].Metadata {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if strings.Contains(s, sentinelBearer) {
			t.Errorf("audit metadata %q carries the sentinel bearer: %v", k, v)
		}
		for _, needle := range forbiddenAuditSubstrings {
			if strings.Contains(s, needle) {
				t.Errorf("audit metadata %q carries forbidden substring %q: %v", k, needle, v)
			}
		}
	}
}

// TestOrgProtoAdmin_GetNeverAudits pins that the GET route
// emits NO audit event. The org.protocol_settings_changed
// event is for state CHANGES only; read operations are not
// audited at the handler layer.
func TestOrgProtoAdmin_GetNeverAudits(t *testing.T) {
	eng, id := newProtoOrgAdminSeeded(t)
	_ = adminJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+id.String()+"/protocol-settings", nil, "")
	if got := len(eng.rec.Events()); got != 0 {
		t.Errorf("GET emitted %d audit event(s), want 0; events=%+v", got, eng.rec.Events())
	}
}

// TestOrgProtoAdmin_PutOnUnchangedRowStillAudits pins that an
// idempotent PUT (same values as already stored) STILL emits
// the audit event. The audit consumer should not have to
// reason about "did the row actually change" — every admin
// PUT is a recorded admin decision.
func TestOrgProtoAdmin_PutOnUnchangedRowStillAudits(t *testing.T) {
	eng, id := newProtoOrgAdminSeeded(t)
	body := map[string]any{
		"dynamic_client_registration_enabled": true,
		"scim_enabled":                        true,
	}
	_ = adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id.String()+"/protocol-settings", body, "")
	eng.rec.Reset()
	_ = adminJSON(t, eng, http.MethodPut, "/api/v1/organizations/"+id.String()+"/protocol-settings", body, "")
	if got := len(eng.rec.Events()); got != 1 {
		t.Errorf("idempotent PUT emitted %d audit event(s), want 1", got)
	}
	if got := eng.rec.Events()[0].Action; got != "org.protocol_settings_changed" {
		t.Errorf("action = %q, want org.protocol_settings_changed", got)
	}
	meta := eng.rec.Events()[0].Metadata
	if meta["old_dynamic_client_registration_enabled"] != true || meta["new_dynamic_client_registration_enabled"] != true {
		t.Errorf("idempotent PUT dcr old/new = %v/%v, want true/true", meta["old_dynamic_client_registration_enabled"], meta["new_dynamic_client_registration_enabled"])
	}
}
