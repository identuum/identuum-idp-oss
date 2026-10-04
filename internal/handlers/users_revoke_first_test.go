package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// switchableSessionRevoker fails while fail is set and counts every call.
type switchableSessionRevoker struct {
	fail  bool
	calls int
}

func (s *switchableSessionRevoker) RevokeUserSessions(context.Context, uuid.UUID, string, map[string]any) error {
	s.calls++
	if s.fail {
		return errors.New("simulated session-store outage")
	}
	return nil
}

func revokeFirstHarness(t *testing.T, actor *domain.Principal, target *domain.User, rev *switchableSessionRevoker) (*gin.Engine, *memUserRepo) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	mem := newMemUserRepo()
	if _, err := mem.Create(context.Background(), target); err != nil {
		t.Fatalf("seed: %v", err)
	}
	deps := UsersHandlerDeps{
		Audit:          audit.NoopService{},
		UserService:    service.NewUserService(nil, mem),
		SessionRevoker: rev,
	}
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(actor))
	r.PUT("/api/v1/users/:id", HandleUpdateUser(deps))
	return r, mem
}

func putUser(r *gin.Engine, id uuid.UUID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/"+id.String(), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// SMALL-FIXES-1 item 3: a role change or a disable whose revocation fails
// leaves NO change (the revocation runs first), and the retry of the same
// request revokes and applies it.
func TestUsersUpdate_AFailedRevocationLeavesNoChange(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		changed    func(u *domain.User) bool
	}{
		{"role", `{"role":"org_user"}`, func(u *domain.User) bool { return u.Role != domain.RoleOrgAdmin }},
		{"disable", `{"active":false}`, func(u *domain.User) bool { return u.Banned }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			org := uuid.New()
			target := &domain.User{ID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgAdmin, Email: "t@x.test"}
			rev := &switchableSessionRevoker{fail: true}
			r, mem := revokeFirstHarness(t, tenantAdminOf(org), target, rev)

			if w := putUser(r, target.ID, tc.body); w.Code != http.StatusServiceUnavailable {
				t.Fatalf("with an erroring revoker = %d %s; want 503", w.Code, w.Body.String())
			}
			stored, err := mem.GetByID(context.Background(), target.ID)
			if err != nil || stored == nil {
				t.Fatalf("read back: %v", err)
			}
			if tc.changed(stored) {
				t.Fatalf("a %s change whose revocation failed was persisted (role %s, banned %v); want no change", tc.name, stored.Role, stored.Banned)
			}

			rev.fail = false
			calls := rev.calls
			if w := putUser(r, target.ID, tc.body); w.Code != http.StatusOK {
				t.Fatalf("the retry with a working revoker = %d %s; want 200", w.Code, w.Body.String())
			}
			if rev.calls == calls {
				t.Fatalf("the retry of the same %s change did not revoke", tc.name)
			}
			stored, _ = mem.GetByID(context.Background(), target.ID)
			if !tc.changed(stored) {
				t.Fatalf("the retry did not apply the %s change", tc.name)
			}
		})
	}
}

// A refused change (an org_admin on itself) and a change that changes nothing
// revoke nothing: the revocation runs only for a write that is about to land.
func TestUsersUpdate_ARefusedOrNoOpChangeRevokesNothing(t *testing.T) {
	org := uuid.New()
	self := &domain.User{ID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgAdmin, Email: "self@x.test"}
	rev := &switchableSessionRevoker{}
	r, _ := revokeFirstHarness(t, &domain.Principal{UserID: self.ID, Role: domain.RoleOrgAdmin, OrganizationID: org}, self, rev)
	if w := putUser(r, self.ID, `{"active":false}`); w.Code != http.StatusForbidden {
		t.Fatalf("org_admin disabling itself = %d %s; want 403", w.Code, w.Body.String())
	}
	if rev.calls != 0 {
		t.Fatalf("a refused self-disable revoked the caller's sessions (%d calls); want 0", rev.calls)
	}

	target := &domain.User{ID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgUser, Email: "u@x.test"}
	rev2 := &switchableSessionRevoker{}
	r2, _ := revokeFirstHarness(t, tenantAdminOf(org), target, rev2)
	if w := putUser(r2, target.ID, `{"role":"org_user"}`); w.Code != http.StatusOK {
		t.Fatalf("same-role PUT = %d %s; want 200", w.Code, w.Body.String())
	}
	if rev2.calls != 0 {
		t.Fatalf("a PUT that changes no role revoked (%d calls); want 0", rev2.calls)
	}
}
