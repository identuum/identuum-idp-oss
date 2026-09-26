//go:build integration

// Package e2e — OSS-GUARDS: an org_admin cannot act on itself (active state,
// roles, MFA), and an organization's last active org_admin can never be
// disabled, deleted or demoted, including by two admins acting at once.
//
// contracts/AdminPermissionsModel.md line 3: "These rules MUST be exact same
// in both identuum-idp-oss and identuum-idp-ce, it cannot vary between these
// products." identuum-idp-ce refuses these since CE-UI-3a with
// cannot_change_self, cannot_change_own_roles, cannot_reset_self (403) and
// last_org_admin (409); OSS takes the same names. The guards bind org_admin
// callers: the site_admin's line-18 recovery (disable a sole org_admin, then
// create the next) keeps working.
//
// The tests compose the real Gin routes, the real services and the real pgx
// repositories against the test database. The paths are literals, so this
// file runs red against the tree before the guards.
package e2e

import (
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

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/features"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// repositoryBan sets banned directly through the repository (fixture only).
func repositoryBan(banned bool) repository.UpdateUserOptions {
	return repository.UpdateUserOptions{Banned: &banned}
}

type guardWorld struct {
	t       *testing.T
	ctx     context.Context
	repos   *postgres.Repositories
	org     uuid.UUID
	a, b, c *domain.User
}

func guardSetup(t *testing.T) *guardWorld {
	t.Helper()
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	org := seedTestOrganization(t, ctx, repos)
	w := &guardWorld{t: t, ctx: ctx, repos: repos, org: org.ID}
	w.a = w.user("org_admin")
	w.b = w.user("org_admin")
	w.c = w.user("org_user")
	return w
}

func (w *guardWorld) user(role domain.UserRole) *domain.User {
	w.t.Helper()
	u, err := w.repos.User.Create(w.ctx, &domain.User{
		ID:             uuid.New(),
		OrganizationID: w.org,
		Email:          strings.ToLower("e2e-guard-" + uuid.NewString() + "@example.invalid"),
		PasswordHash:   "gd-" + uuid.NewString(),
		Role:           role,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		w.t.Fatalf("seed %s: %v", role, err)
	}
	return u
}

// engine mounts the users and RBAC routes behind principal p.
func (w *guardWorld) engine(p *domain.Principal) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(p))
	handlers.RegisterUsersRoutes(r, handlers.UsersHandlerDeps{
		UserService: service.NewUserService(nil, w.repos.User),
		UserRepo:    w.repos.User,
	})
	handlers.RegisterRBACRoutes(r, handlers.RBACHandlerDeps{
		OrgRoleService: service.NewOrgRoleService(nil, w.repos.OrgRole, w.repos.APIResource).WithUserRepository(w.repos.User),
		FeatureGate:    features.NewStaticGate(map[string]bool{features.AuthorizationServer: true}),
	})
	return r
}

// orgAdmin is u acting as the bearer middleware establishes an org_admin.
func (w *guardWorld) orgAdmin(u *domain.User) *gin.Engine {
	return w.engine(&domain.Principal{
		UserID:         u.ID,
		OrganizationID: w.org,
		Role:           domain.RoleOrgAdmin,
		Email:          u.Email,
		Scope: strings.Join([]string{
			domain.ScopeUsersRead, domain.ScopeUsersUpdate, domain.ScopeUsersDelete,
			domain.ScopeUsersMFARevoke, domain.ScopeOrgsRead, domain.ScopeOrgsUpdate,
		}, " "),
	})
}

func guardCall(e *gin.Engine, method, path, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func guardErr(body string) string {
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	s, _ := m["error"].(string)
	return s
}

func (w *guardWorld) reload(id uuid.UUID) *domain.User {
	w.t.Helper()
	u, err := w.repos.AdminUser.GetByIDAdmin(w.ctx, id)
	if err != nil || u == nil {
		w.t.Fatalf("reload %s: %v", id, err)
	}
	return u
}

func (w *guardWorld) activeOrgAdmins() int {
	w.t.Helper()
	n, err := w.repos.User.CountOrgAdminsByOrganization(w.ctx, w.org)
	if err != nil {
		w.t.Fatalf("count org_admins: %v", err)
	}
	return n
}

func (w *guardWorld) role(e *gin.Engine) string {
	w.t.Helper()
	st, body := guardCall(e, http.MethodPost, "/api/v1/organizations/"+w.org.String()+"/roles", `{"name":"auditor-`+uuid.NewString()[:8]+`"}`)
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	id, _ := m["id"].(string)
	if st != http.StatusCreated || id == "" {
		w.t.Fatalf("create org role = %d %s", st, body)
	}
	return id
}

// An org_admin cannot change its own active state, its own roles or its own
// MFA through the admin routes, and cannot delete itself. Its own name stays
// editable.
func TestE2E_OSS_OrgAdminCannotActOnItself(t *testing.T) {
	w := guardSetup(t)
	a := w.orgAdmin(w.a)
	self := "/api/v1/users/" + w.a.ID.String()
	roleID := w.role(a)
	for _, tc := range []struct {
		name, method, path, body, code string
		status                         int
	}{
		{"disable itself (active)", http.MethodPut, self, `{"active":false}`, "cannot_change_self", http.StatusForbidden},
		{"disable itself (banned)", http.MethodPut, self, `{"banned":true}`, "cannot_change_self", http.StatusForbidden},
		{"demote itself", http.MethodPut, self, `{"role":"org_user"}`, "cannot_change_self", http.StatusForbidden},
		{"delete itself", http.MethodDelete, self, "", "cannot_change_self", http.StatusForbidden},
		{"reset its own MFA", http.MethodPost, self + "/recovery/reset-mfa", "", "cannot_reset_self", http.StatusForbidden},
		{"assign itself a role", http.MethodPost, self + "/roles", `{"role_id":"` + roleID + `"}`, "cannot_change_own_roles", http.StatusForbidden},
		{"remove its own role", http.MethodDelete, self + "/roles/" + roleID, "", "cannot_change_own_roles", http.StatusForbidden},
	} {
		if st, body := guardCall(a, tc.method, tc.path, tc.body); st != tc.status || guardErr(body) != tc.code {
			t.Errorf("%s: %s %s = %d %s; want %d %q", tc.name, tc.method, tc.path, st, body, tc.status, tc.code)
		}
	}
	if u := w.reload(w.a.ID); u.Banned || u.Role != domain.RoleOrgAdmin || u.DeletedAt != nil {
		t.Errorf("after the refusals the org_admin is banned=%v role=%s deleted=%v; want it unchanged", u.Banned, u.Role, u.DeletedAt != nil)
	}
	if st, body := guardCall(a, http.MethodPut, self, `{"name":"Alice Admin"}`); st != http.StatusOK {
		t.Errorf("edit its own name = %d %s; want 200", st, body)
	}
	// The same actions on another user of the organization still work.
	if st, body := guardCall(a, http.MethodPost, "/api/v1/users/"+w.c.ID.String()+"/roles", `{"role_id":"`+roleID+`"}`); st != http.StatusOK {
		t.Errorf("assign a role to an org_user = %d %s; want 200", st, body)
	}
	if st, body := guardCall(a, http.MethodPut, "/api/v1/users/"+w.c.ID.String(), `{"active":false}`); st != http.StatusOK {
		t.Errorf("disable an org_user = %d %s; want 200", st, body)
	}
}

// The organization's last active org_admin is never disabled, demoted or
// deleted. The acting org_admin's own row is already banned here (a token
// issued before its ban), so the target is the last active one.
func TestE2E_OSS_TheLastActiveOrgAdminIsNeverRemoved(t *testing.T) {
	w := guardSetup(t)
	banned := true
	if _, err := w.repos.User.Update(w.ctx, w.a.ID, w.org, repositoryBan(banned)); err != nil {
		t.Fatalf("ban a: %v", err)
	}
	if n := w.activeOrgAdmins(); n != 1 {
		t.Fatalf("active org_admins before = %d; want 1 (b)", n)
	}
	a := w.orgAdmin(w.a)
	target := "/api/v1/users/" + w.b.ID.String()
	for _, tc := range []struct{ name, method, body string }{
		{"disable (active)", http.MethodPut, `{"active":false}`},
		{"disable (banned)", http.MethodPut, `{"banned":true}`},
		{"demote", http.MethodPut, `{"role":"org_user"}`},
		{"delete", http.MethodDelete, ""},
	} {
		if st, body := guardCall(a, tc.method, target, tc.body); st != http.StatusConflict || guardErr(body) != "last_org_admin" {
			t.Errorf("%s the last active org_admin = %d %s; want 409 last_org_admin", tc.name, st, body)
		}
	}
	if u := w.reload(w.b.ID); u.Banned || u.Role != domain.RoleOrgAdmin || u.DeletedAt != nil {
		t.Errorf("the last active org_admin is banned=%v role=%s deleted=%v; want it untouched", u.Banned, u.Role, u.DeletedAt != nil)
	}
	if n := w.activeOrgAdmins(); n != 1 {
		t.Errorf("active org_admins after = %d; want 1", n)
	}
}

// N parallel disables of the organization's two remaining org_admins, each
// disabling the other: exactly one stays active, every round.
func TestE2E_OSS_ConcurrentDisablesLeaveOneActiveOrgAdmin(t *testing.T) {
	w := guardSetup(t)
	a, b := w.orgAdmin(w.a), w.orgAdmin(w.b)
	const perSide = 4
	for round := 0; round < 5; round++ {
		var wg sync.WaitGroup
		codes := make(chan int, 2*perSide)
		for i := 0; i < perSide; i++ {
			for _, pair := range []struct {
				e      *gin.Engine
				target uuid.UUID
			}{{a, w.b.ID}, {b, w.a.ID}} {
				wg.Add(1)
				go func(e *gin.Engine, target uuid.UUID) {
					defer wg.Done()
					st, _ := guardCall(e, http.MethodPut, "/api/v1/users/"+target.String(), `{"active":false}`)
					codes <- st
				}(pair.e, pair.target)
			}
		}
		wg.Wait()
		close(codes)
		for st := range codes {
			if st != http.StatusOK && st != http.StatusConflict {
				t.Fatalf("round %d: a disable answered %d; want 200 or 409", round, st)
			}
		}
		if n := w.activeOrgAdmins(); n != 1 {
			t.Fatalf("round %d: %d active org_admin(s) after %d parallel disables; want exactly 1", round, n, 2*perSide)
		}
		for _, id := range []uuid.UUID{w.a.ID, w.b.ID} {
			if _, err := w.repos.User.Update(w.ctx, id, w.org, repositoryBan(false)); err != nil {
				t.Fatalf("round %d: re-enable: %v", round, err)
			}
		}
	}
}

// Model line 18: when an organization has lost its org_admins, the site_admin
// may assign another. The guards bind org_admin callers only, so the
// site_admin still disables a sole org_admin and then creates the next.
func TestE2E_OSS_SiteAdminRecoversAnOrganizationWithoutAnActiveAdmin(t *testing.T) {
	w := guardSetup(t)
	if _, err := w.repos.User.Update(w.ctx, w.a.ID, w.org, repositoryBan(true)); err != nil {
		t.Fatalf("ban a: %v", err)
	}
	site := w.engine(&domain.Principal{
		UserID:         uuid.MustParse(domain.SiteAdminID),
		OrganizationID: uuid.MustParse(domain.SystemOrgID),
		Role:           domain.RoleSiteAdmin,
		Email:          "site_admin@system.local",
	})
	if st, body := guardCall(site, http.MethodPut, "/api/v1/users/"+w.b.ID.String(), `{"active":false}`); st != http.StatusOK {
		t.Fatalf("site_admin disables the sole active org_admin = %d %s; want 200", st, body)
	}
	if n := w.activeOrgAdmins(); n != 0 {
		t.Fatalf("active org_admins = %d; want 0", n)
	}
	body := `{"organization_id":"` + w.org.String() + `","email":"e2e-next-` + uuid.NewString() + `@example.invalid","password":"Next-` + uuid.NewString() + `-9a!","role":"org_admin"}`
	if st, out := guardCall(site, http.MethodPost, "/api/v1/users", body); st != http.StatusCreated {
		t.Fatalf("site_admin creates the next org_admin = %d %s; want 201", st, out)
	}
	if n := w.activeOrgAdmins(); n != 1 {
		t.Errorf("active org_admins after recovery = %d; want 1", n)
	}
}
