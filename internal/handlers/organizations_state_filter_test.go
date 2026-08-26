package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// stateFilterOrgRepo mirrors the PGX semantics THE-DEACTIVATED-ORG is about:
//   - List honors OrganizationFilter's Active/Deleted axes exactly like
//     organization_repository_pgx.go (nil + !Include* => the narrow default),
//     and records the filter it received so the handler's forwarding is
//     assertable.
//   - GetByID enforces active AND non-deleted (the pgx WHERE that makes a
//     deactivated org's detail 404 — the trap door).
//   - GetByIDAdmin returns any state (the pgx admin accessor).
type stateFilterOrgRepo struct {
	mu         sync.Mutex
	rows       map[uuid.UUID]*domain.Organization
	lastFilter *repository.OrganizationFilter
	listCalls  int
}

func newStateFilterOrgRepo() *stateFilterOrgRepo {
	return &stateFilterOrgRepo{rows: map[uuid.UUID]*domain.Organization{}}
}

func (r *stateFilterOrgRepo) seen() (int, *repository.OrganizationFilter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listCalls, r.lastFilter
}

func (r *stateFilterOrgRepo) Create(_ context.Context, o *domain.Organization) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[o.ID] = o
	return o, nil
}

func (r *stateFilterOrgRepo) CreateWithAdmin(_ context.Context, o *domain.Organization, u *domain.User) (*domain.Organization, *domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[o.ID] = o
	return o, u, nil
}

func (r *stateFilterOrgRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o := r.rows[id]; o != nil && o.Active && o.DeletedAt == nil {
		return o, nil
	}
	return nil, domain.ErrOrganizationNotFound
}

func (r *stateFilterOrgRepo) GetByIDAdmin(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o := r.rows[id]; o != nil {
		return o, nil
	}
	return nil, domain.ErrOrganizationNotFound
}

func (r *stateFilterOrgRepo) GetByDomain(_ context.Context, _ string) (*domain.Organization, error) {
	return nil, domain.ErrOrganizationNotFound
}

func (r *stateFilterOrgRepo) GetBySlug(_ context.Context, _ string) (*domain.Organization, error) {
	return nil, domain.ErrOrganizationNotFound
}

func (r *stateFilterOrgRepo) Update(_ context.Context, id uuid.UUID, _ repository.UpdateOrganizationOptions) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}

func (r *stateFilterOrgRepo) Delete(_ context.Context, _ uuid.UUID) error   { return nil }
func (r *stateFilterOrgRepo) Undelete(_ context.Context, _ uuid.UUID) error { return nil }

func (r *stateFilterOrgRepo) List(_ context.Context, filter repository.OrganizationFilter,
	_ repository.Pagination, _ repository.Sort) ([]*domain.Organization, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listCalls++
	f := filter
	r.lastFilter = &f
	out := []*domain.Organization{}
	for _, o := range r.rows {
		// Mirror of the pgx WHERE-building in organization_repository_pgx.List.
		if filter.Active != nil {
			if o.Active != *filter.Active {
				continue
			}
		} else if !filter.IncludeInactive && !o.Active {
			continue
		}
		if filter.Deleted != nil {
			if *filter.Deleted != (o.DeletedAt != nil) {
				continue
			}
		} else if !filter.IncludeDeleted && o.DeletedAt != nil {
			continue
		}
		out = append(out, o)
	}
	return out, len(out), nil
}

func (r *stateFilterOrgRepo) CountUsers(_ context.Context, _ uuid.UUID) (int, error) { return 0, nil }
func (r *stateFilterOrgRepo) CountSessions(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, nil
}

// Admin-interface remainder, so the service's AdminOrganizationRepository
// assertion holds and the admin read path is the one under test.
func (r *stateFilterOrgRepo) ListDeleted(_ context.Context, _ repository.Pagination) ([]*domain.Organization, int, error) {
	return nil, 0, nil
}

func (r *stateFilterOrgRepo) ListAll(_ context.Context, _ repository.OrganizationFilter, _ repository.Pagination, _ repository.Sort) ([]*domain.Organization, int, error) {
	return nil, 0, nil
}

func (r *stateFilterOrgRepo) GetDetailsAdmin(_ context.Context, id uuid.UUID) (*domain.Organization, map[string]int, error) {
	return r.rows[id], map[string]int{}, nil
}

func (r *stateFilterOrgRepo) HardDelete(_ context.Context, _ uuid.UUID) error  { return nil }
func (r *stateFilterOrgRepo) UpdateID(_ context.Context, _, _ uuid.UUID) error { return nil }

func (r *stateFilterOrgRepo) GetDetails(_ context.Context, id uuid.UUID) (*domain.Organization, map[string]int, error) {
	return r.rows[id], map[string]int{}, nil
}

func newStateFilterEngine(t *testing.T, principal *domain.Principal) (*gin.Engine, *stateFilterOrgRepo) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	repo := newStateFilterOrgRepo()
	RegisterOrganizationsRoutes(r, OrganizationsHandlerDeps{
		OrganizationService: service.NewOrganizationService(nil, repo),
		Audit:               &audit.Recorder{},
	})
	return r, repo
}

func seedStateOrg(repo *stateFilterOrgRepo, name string, active bool, deleted bool) *domain.Organization {
	now := time.Now().UTC()
	o := &domain.Organization{
		ID:                 uuid.New(),
		Name:               name,
		Domain:             name + ".state.test",
		OrgSlug:            name,
		Active:             active,
		MaxSessionsPerUser: 10,
		MFAPolicy:          "optional",
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if deleted {
		o.DeletedAt = &now
	}
	_, _ = repo.Create(context.Background(), o)
	return o
}

func stateReq(t *testing.T, r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func listIDs(t *testing.T, rec *httptest.ResponseRecorder) map[uuid.UUID]bool {
	t.Helper()
	var body struct {
		Organizations []safeOrganization `json:"organizations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v (body %s)", err, rec.Body.String())
	}
	ids := map[uuid.UUID]bool{}
	for _, o := range body.Organizations {
		ids[o.ID] = true
	}
	return ids
}

// D1: ?active=all must surface a deactivated organization to a site_admin.
// RULE: ORG-LIST-STATE-FILTER-1
func TestOrgList_ActiveAll_IncludesDeactivated(t *testing.T) {
	eng, repo := newStateFilterEngine(t, siteAdminPrincipal())
	a := seedStateOrg(repo, "alive", true, false)
	b := seedStateOrg(repo, "asleep", false, false)
	rec := stateReq(t, eng, http.MethodGet, "/api/v1/organizations?active=all")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	ids := listIDs(t, rec)
	if !ids[a.ID] || !ids[b.ID] {
		t.Errorf("?active=all must include the deactivated org: got %d orgs, deactivated present = %v", len(ids), ids[b.ID])
	}
}

// D2: ?deleted=true must be parsed and forwarded — soft-deleted orgs only.
func TestOrgList_DeletedTrue_ListsOnlyDeleted(t *testing.T) {
	eng, repo := newStateFilterEngine(t, siteAdminPrincipal())
	a := seedStateOrg(repo, "alive2", true, false)
	c := seedStateOrg(repo, "gone", true, true)
	rec := stateReq(t, eng, http.MethodGet, "/api/v1/organizations?deleted=true")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	ids := listIDs(t, rec)
	if !ids[c.ID] || ids[a.ID] {
		t.Errorf("?deleted=true must list exactly the soft-deleted org: deleted present = %v, live leaked = %v", ids[c.ID], ids[a.ID])
	}
}

// The DEFAULT is pinned: no params behaves exactly as before — the zero
// filter (active + non-deleted) reaches the repository unchanged.
func TestOrgList_DefaultFilterUnchanged(t *testing.T) {
	eng, repo := newStateFilterEngine(t, siteAdminPrincipal())
	a := seedStateOrg(repo, "alive3", true, false)
	seedStateOrg(repo, "asleep3", false, false)
	seedStateOrg(repo, "gone3", true, true)
	rec := stateReq(t, eng, http.MethodGet, "/api/v1/organizations")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	ids := listIDs(t, rec)
	if len(ids) != 1 || !ids[a.ID] {
		t.Errorf("default list must stay active+non-deleted only: got %d orgs", len(ids))
	}
	_, f := repo.seen()
	if f == nil || f.Active != nil || f.Deleted != nil || f.IncludeInactive || f.IncludeDeleted {
		t.Errorf("default must forward the ZERO filter (unchanged callers), got %+v", f)
	}
}

// A garbage filter value is refused, never silently the default.
func TestOrgList_InvalidFilterValueIs400(t *testing.T) {
	eng, repo := newStateFilterEngine(t, siteAdminPrincipal())
	seedStateOrg(repo, "alive4", true, false)
	rec := stateReq(t, eng, http.MethodGet, "/api/v1/organizations?active=bogus")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("?active=bogus = %d, want 400 (fail-closed, not the silent default)", rec.Code)
	}
}

// TRAP DOOR (blast radius): a deactivated org's DETAIL must be reachable —
// today the narrow GetByID 404s it, leaving no read path to recover from.
// A soft-DELETED org must keep 404ing (ORG-RESTORE-1's pinned contract).
func TestOrgDetail_DeactivatedReachable_DeletedStays404(t *testing.T) {
	eng, repo := newStateFilterEngine(t, siteAdminPrincipal())
	b := seedStateOrg(repo, "asleep5", false, false)
	c := seedStateOrg(repo, "gone5", true, true)
	rec := stateReq(t, eng, http.MethodGet, "/api/v1/organizations/"+b.ID.String())
	if rec.Code != http.StatusOK {
		t.Errorf("deactivated org detail = %d, want 200 (deactivation must not be a trap door)", rec.Code)
	}
	rec = stateReq(t, eng, http.MethodGet, "/api/v1/organizations/"+c.ID.String())
	if rec.Code != http.StatusNotFound {
		t.Errorf("soft-deleted org detail = %d, want 404 (ORG-RESTORE-1 contract)", rec.Code)
	}
}

// TENANT BOUNDARY: the widened filter is a site_admin affordance only. An
// org_admin sending the most permissive filter still gets exactly their own
// organization, and the cross-tenant List is never consulted for them.
func TestOrgList_OrgAdminIgnoresFilters(t *testing.T) {
	org := uuid.New()
	eng, repo := newStateFilterEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "orgs:read",
	})
	now := time.Now().UTC()
	own := &domain.Organization{ID: org, Name: "mine", Domain: "mine.state.test", OrgSlug: "mine",
		Active: true, MaxSessionsPerUser: 10, MFAPolicy: "optional", CreatedAt: now, UpdatedAt: now}
	_, _ = repo.Create(context.Background(), own)
	seedStateOrg(repo, "other", true, false)
	seedStateOrg(repo, "othergone", true, true)
	rec := stateReq(t, eng, http.MethodGet, "/api/v1/organizations?active=all&deleted=all")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	ids := listIDs(t, rec)
	if len(ids) != 1 || !ids[org] {
		t.Errorf("org_admin with permissive filters must still see ONLY their own org: got %d orgs", len(ids))
	}
	calls, _ := repo.seen()
	if calls != 0 {
		t.Errorf("the cross-tenant List must never be consulted for an org_admin: List called %d times", calls)
	}
}
