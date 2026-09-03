package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// inMemorySARepoForHandlers is the handler-test view of the
// repository — same shape the service tests use, with the
// admin-method behaviors the handler exercises.
type inMemorySARepoForHandlers struct {
	byID map[uuid.UUID]*domain.ServiceAccount
	// getErr makes GetByID fail like a store outage (AUTH-503 tests).
	getErr error
}

func newSARepoForHandlers() *inMemorySARepoForHandlers {
	return &inMemorySARepoForHandlers{byID: map[uuid.UUID]*domain.ServiceAccount{}}
}

func (r *inMemorySARepoForHandlers) Create(_ context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	// Mirrors migration 0030's uq_service_accounts_org_name_live index: a
	// LIVE duplicate (organization_id, name) is refused with the same
	// sentinel the pgx repository maps the 23505 to (gap E). Deleted rows in
	// this fake are removed from the map, so presence == live.
	for _, existing := range r.byID {
		if existing.OrganizationID == sa.OrganizationID && existing.Name == sa.Name {
			return nil, domain.ErrServiceAccountNameTaken
		}
	}
	if sa.ID == uuid.Nil {
		sa.ID = uuid.New()
	}
	cp := *sa
	r.byID[sa.ID] = &cp
	return &cp, nil
}
func (r *inMemorySARepoForHandlers) GetByID(_ context.Context, id uuid.UUID) (*domain.ServiceAccount, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	sa, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *sa
	return &cp, nil
}
func (r *inMemorySARepoForHandlers) GetByName(context.Context, uuid.UUID, string) (*domain.ServiceAccount, error) {
	return nil, nil
}
func (r *inMemorySARepoForHandlers) ListByOrganization(_ context.Context, orgID uuid.UUID) ([]*domain.ServiceAccount, error) {
	out := make([]*domain.ServiceAccount, 0)
	for _, sa := range r.byID {
		if sa.OrganizationID == orgID {
			cp := *sa
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (r *inMemorySARepoForHandlers) Update(_ context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	// Same live-name uniqueness mirror as Create (gap E): renaming onto a
	// SIBLING's live name is refused with the repository's sentinel.
	for id, existing := range r.byID {
		if id != sa.ID && existing.OrganizationID == sa.OrganizationID && existing.Name == sa.Name {
			return nil, domain.ErrServiceAccountNameTaken
		}
	}
	cp := *sa
	r.byID[sa.ID] = &cp
	return &cp, nil
}
func (r *inMemorySARepoForHandlers) Delete(_ context.Context, id, orgID uuid.UUID) error {
	sa, ok := r.byID[id]
	if !ok || sa.OrganizationID != orgID {
		return errors.New("not found")
	}
	delete(r.byID, id)
	return nil
}
func (r *inMemorySARepoForHandlers) UpdateLastUsedAt(context.Context, uuid.UUID) error {
	return nil
}
func (r *inMemorySARepoForHandlers) UpdateActive(_ context.Context, id, orgID uuid.UUID, active bool) error {
	sa, ok := r.byID[id]
	if !ok || sa.OrganizationID != orgID {
		return errors.New("not found")
	}
	sa.Active = active
	return nil
}

// UpdateOwner + getErr back the owner-assignment and AUTH-503 tests
// (THE-OWNERLESS-ACCOUNT).
func (r *inMemorySARepoForHandlers) UpdateOwner(_ context.Context, id, orgID, ownerUserID uuid.UUID) error {
	sa, ok := r.byID[id]
	if !ok || sa.OrganizationID != orgID {
		return errors.New("not found")
	}
	owner := ownerUserID
	sa.OwnerUserID = &owner
	return nil
}

func newSAEngine(t *testing.T, principal *domain.Principal) (*gin.Engine, *inMemorySARepoForHandlers, *audit.Recorder) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	repo := newSARepoForHandlers()
	rec := &audit.Recorder{}
	RegisterServiceAccountsRoutes(r, ServiceAccountsHandlerDeps{
		ServiceAccountService: service.NewServiceAccountService(nil, repo),
		Audit:                 rec,
	})
	return r, repo, rec
}

// saSiteAdminPrincipal was removed by THE-REMAINING-FOUR (2026-08-30): every
// SA route test now drives as the org's own org_admin (site_admin is refused
// on tenant service accounts). The refusal itself is pinned by
// SA-ADMIN-SCOPE-1 and TestCreateForActor_SiteAdminRefused.

func saOrgAdminPrincipal(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgAdmin}
}

func saOrgUserPrincipal(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser}
}

// ---------- Route absence ----------

func TestSARoutes_AbsentWithoutService(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterServiceAccountsRoutes(r, ServiceAccountsHandlerDeps{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+uuid.NewString()+"/service-accounts", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------- Authentication ----------

func TestSARoutes_UnauthenticatedIs401(t *testing.T) {
	r, _, _ := newSAEngine(t, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/organizations/"+uuid.NewString()+"/service-accounts", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// ---------- Authorization ----------

func TestSARoutes_OrgUserForbiddenOnCreate(t *testing.T) {
	orgID := uuid.New()
	r, _, _ := newSAEngine(t, saOrgUserPrincipal(orgID))
	body := strings.NewReader(`{"name":"ci","role":"org_user"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgID.String()+"/service-accounts", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 404 (cross-org is NOT FOUND per AdminPermissionsModel — a 403 confirms the org exists)", w.Code)
	}
}

func TestSARoutes_CrossOrgOrgAdminNotFound(t *testing.T) {
	other := uuid.New()
	r, _, _ := newSAEngine(t, saOrgAdminPrincipal(uuid.New()))
	body := strings.NewReader(`{"name":"x","role":"org_user"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+other.String()+"/service-accounts", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (cross-org is NOT FOUND per AdminPermissionsModel — a 403 confirms the org exists)", w.Code)
	}
}

// ---------- Create / Get / List / Update / Disable / Delete happy paths ----------

// THE-REMAINING-FOUR (2026-08-30): the full lifecycle runs as the org's own
// org_admin now (site_admin is refused on tenant service accounts; that
// refusal is pinned by SA-ADMIN-SCOPE-1 and TestCreateForActor_SiteAdminRefused).
func TestSARoutes_OrgAdminFullLifecycle(t *testing.T) {
	orgID := uuid.New()
	r, repo, rec := newSAEngine(t, saOrgAdminPrincipal(orgID))

	// Create.
	createBody := strings.NewReader(`{"name":"deploy-bot","description":"d","role":"org_user"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgID.String()+"/service-accounts", createBody)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%q", w.Code, w.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	saID := created["id"].(string)
	saUUID, _ := uuid.Parse(saID)
	if created["organization_id"] != orgID.String() {
		t.Errorf("org id = %v", created["organization_id"])
	}
	// Audit must NOT leak SA name in metadata.
	for _, e := range rec.Events() {
		if e.Action == "service_account.created" {
			if _, ok := e.Metadata["name"]; ok {
				t.Errorf("audit leaked SA name: %+v", e.Metadata)
			}
		}
	}

	// List.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/organizations/"+orgID.String()+"/service-accounts", nil)
	listW := httptest.NewRecorder()
	r.ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("list status = %d", listW.Code)
	}
	var list []map[string]any
	_ = json.Unmarshal(listW.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Errorf("list = %d entries", len(list))
	}

	// Get.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/service-accounts/"+saID, nil)
	getW := httptest.NewRecorder()
	r.ServeHTTP(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("get status = %d", getW.Code)
	}

	// Update — toggle role.
	upd := strings.NewReader(`{"role":"org_admin","description":"d2"}`)
	updReq := httptest.NewRequest(http.MethodPut, "/api/v1/service-accounts/"+saID, upd)
	updReq.Header.Set("Content-Type", "application/json")
	updW := httptest.NewRecorder()
	r.ServeHTTP(updW, updReq)
	if updW.Code != http.StatusOK {
		t.Fatalf("update status = %d", updW.Code)
	}
	if string(repo.byID[saUUID].Role) != "org_admin" {
		t.Errorf("role not updated: %s", repo.byID[saUUID].Role)
	}

	// Disable.
	disReq := httptest.NewRequest(http.MethodPost, "/api/v1/service-accounts/"+saID+"/disable", nil)
	disW := httptest.NewRecorder()
	r.ServeHTTP(disW, disReq)
	if disW.Code != http.StatusNoContent {
		t.Fatalf("disable status = %d", disW.Code)
	}
	if repo.byID[saUUID].Active {
		t.Errorf("disable did not flip Active")
	}

	// Enable.
	enReq := httptest.NewRequest(http.MethodPost, "/api/v1/service-accounts/"+saID+"/enable", nil)
	enW := httptest.NewRecorder()
	r.ServeHTTP(enW, enReq)
	if enW.Code != http.StatusNoContent {
		t.Fatalf("enable status = %d", enW.Code)
	}
	if !repo.byID[saUUID].Active {
		t.Errorf("enable did not flip Active back")
	}

	// Delete.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/service-accounts/"+saID, nil)
	delW := httptest.NewRecorder()
	r.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", delW.Code)
	}
	if _, ok := repo.byID[saUUID]; ok {
		t.Errorf("delete left row behind")
	}
}

// ---------- DTO safety ----------

func TestSARoutes_DTODoesNotExposeOwnerOrSensitiveFields(t *testing.T) {
	orgID := uuid.New()
	r, repo, _ := newSAEngine(t, saOrgAdminPrincipal(orgID))
	owner := uuid.New()
	future := time.Now().Add(time.Hour)
	sa := &domain.ServiceAccount{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Name:           "ci",
		Active:         true,
		Role:           domain.RoleOrgUser,
		OwnerUserID:    &owner,
		ExpiresAt:      &future,
	}
	repo.byID[sa.ID] = sa

	req := httptest.NewRequest(http.MethodGet, "/api/v1/service-accounts/"+sa.ID.String(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	for _, banned := range []string{"owner_user_id", "client_id", "client_secret", "token", "secret", "metadata", "origin_peer_id", "origin_spiffe_id"} {
		if _, ok := body[banned]; ok {
			t.Errorf("DTO leaked banned field %q = %v", banned, body[banned])
		}
	}
	if body["expires_at"] == nil {
		t.Errorf("expires_at missing from DTO")
	}
}
