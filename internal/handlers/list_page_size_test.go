package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
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

// V3-039 (OSS-0913-PAGESIZE-FIX): repository.NewPagination serves at most 100
// rows a page, yet the list answers echoed the REQUESTED page_size. A console
// that asked for 200 and counted pages as ceil(total/200) showed the 100
// newest of 101..200 users and no next page. The answer must carry the page
// size actually used.

// pagedUserRepo is memUserRepo whose organization list pages like the pgx
// repository: newest first, LIMIT PageSize OFFSET Offset.
type pagedUserRepo struct{ *memUserRepo }

func (r pagedUserRepo) ListByOrganization(ctx context.Context, orgID uuid.UUID, opts repository.ListUserOptions) ([]*domain.User, int, error) {
	all, total, err := r.memUserRepo.ListByOrganization(ctx, orgID, opts)
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.After(all[j].CreatedAt)
		}
		return all[i].ID.String() < all[j].ID.String()
	})
	p := opts.Pagination
	if p.Offset >= len(all) {
		return []*domain.User{}, total, nil
	}
	return all[p.Offset:min(p.Offset+p.PageSize, len(all))], total, nil
}

type userListAnswer struct {
	Users    []safeUser `json:"users"`
	Total    int        `json:"total"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
}

func TestUserList_EchoesThePageSizeActuallyServed(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	org := uuid.New()
	mem := newMemUserRepo()
	base := time.Now().UTC().Add(-time.Hour)
	const total = 150
	for i := range total {
		u := &domain.User{ID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgUser,
			Email: uuid.NewString() + "@x.test", CreatedAt: base.Add(time.Duration(i) * time.Second)}
		if i == 0 {
			u.Role = domain.RoleOrgAdmin // created first, so listed last
		}
		if _, err := mem.Create(context.Background(), u); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(tenantAdminOf(org)))
	RegisterUsersRoutes(r, UsersHandlerDeps{
		Audit:               audit.NoopService{},
		UserService:         service.NewUserService(nil, pagedUserRepo{mem}),
		SessionRevoker:      service.NoopSessionRevoker{},
		RefreshTokenRevoker: service.NoopRefreshTokenRevoker{},
	})
	get := func(page int) userListAnswer {
		t.Helper()
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/users?page_size=200&page="+strconv.Itoa(page), nil))
		if w.Code != http.StatusOK {
			t.Fatalf("page %d = %d %s", page, w.Code, w.Body.String())
		}
		var a userListAnswer
		if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return a
	}

	first := get(1)
	if first.PageSize != 100 {
		t.Fatalf("page_size = %d for a request of 200; want 100, the size actually served", first.PageSize)
	}
	if len(first.Users) != first.PageSize || first.Total != total {
		t.Fatalf("page 1: %d users, total %d; want %d and %d", len(first.Users), first.Total, first.PageSize, total)
	}
	pages := (first.Total + first.PageSize - 1) / first.PageSize
	if pages != 2 {
		t.Fatalf("ceil(total/page_size) = %d; want 2", pages)
	}
	second := get(2)
	if len(second.Users) != total-first.PageSize {
		t.Fatalf("page 2: %d users; want %d", len(second.Users), total-first.PageSize)
	}
	seen := map[uuid.UUID]bool{}
	admin := false
	for _, u := range append(first.Users, second.Users...) {
		seen[u.ID] = true
		admin = admin || u.Role == domain.RoleOrgAdmin
	}
	if len(seen) != total || !admin {
		t.Fatalf("across both pages: %d distinct users, admin reached %v; want %d and true", len(seen), admin, total)
	}
}

func TestOrgLists_EchoThePageSizeActuallyServed(t *testing.T) {
	eng := newIdentityEngine(t, siteAdminPrincipal(), nil)
	seedExportOrg(t, eng, uuid.New(), "acme", true)
	for _, path := range []string{
		"/api/v1/organizations?page_size=200",
		"/api/v1/organizations/export-candidates?page_size=200",
	} {
		rec := doIdentityJSON(t, eng, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", path, rec.Code, rec.Body.String())
		}
		var body struct {
			PageSize int `json:"page_size"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.PageSize != 100 {
			t.Errorf("%s answered page_size %d; want 100, the size actually served", path, body.PageSize)
		}
	}
}
