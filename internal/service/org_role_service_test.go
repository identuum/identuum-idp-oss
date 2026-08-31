package service

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// inMemoryOrgRoleRepo is the smallest OrgRoleRepository fake that
// exercises the OSS service. Methods not used by the service panic
// to surface accidental new deps as test failures.
type inMemoryOrgRoleRepo struct {
	mu        sync.Mutex
	roles     map[uuid.UUID]*domain.OrgRole
	userRoles map[uuid.UUID][]uuid.UUID // userID → roleIDs
}

func newOrgRoleRepo() *inMemoryOrgRoleRepo {
	return &inMemoryOrgRoleRepo{
		roles:     map[uuid.UUID]*domain.OrgRole{},
		userRoles: map[uuid.UUID][]uuid.UUID{},
	}
}

func (r *inMemoryOrgRoleRepo) Create(_ context.Context, role *domain.OrgRole) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	r.roles[role.ID] = role
	return nil
}
func (r *inMemoryOrgRoleRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.OrgRole, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.roles[id], nil
}
func (r *inMemoryOrgRoleRepo) ListByOrg(_ context.Context, orgID uuid.UUID) ([]*domain.OrgRole, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.OrgRole, 0)
	for _, v := range r.roles {
		if v.OrgID == orgID {
			out = append(out, v)
		}
	}
	return out, nil
}
func (r *inMemoryOrgRoleRepo) Update(_ context.Context, role *domain.OrgRole) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles[role.ID] = role
	return nil
}
func (r *inMemoryOrgRoleRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.roles, id)
	return nil
}
func (r *inMemoryOrgRoleRepo) AddScope(_ context.Context, roleID, _ uuid.UUID, scopeName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if role, ok := r.roles[roleID]; ok {
		role.Scopes = append(role.Scopes, scopeName)
	}
	return nil
}
func (r *inMemoryOrgRoleRepo) RemoveScope(_ context.Context, roleID uuid.UUID, scopeName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	role, ok := r.roles[roleID]
	if !ok {
		return nil
	}
	out := role.Scopes[:0]
	for _, s := range role.Scopes {
		if s != scopeName {
			out = append(out, s)
		}
	}
	role.Scopes = out
	return nil
}
func (r *inMemoryOrgRoleRepo) AssignRoleToUser(_ context.Context, userID, roleID, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.userRoles[userID] = append(r.userRoles[userID], roleID)
	return nil
}
func (r *inMemoryOrgRoleRepo) RemoveRoleFromUser(_ context.Context, userID, roleID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.userRoles[userID][:0]
	for _, rid := range r.userRoles[userID] {
		if rid != roleID {
			out = append(out, rid)
		}
	}
	r.userRoles[userID] = out
	return nil
}
func (r *inMemoryOrgRoleRepo) ListRolesForUser(_ context.Context, userID uuid.UUID) ([]*domain.OrgRole, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.OrgRole, 0)
	for _, rid := range r.userRoles[userID] {
		if role, ok := r.roles[rid]; ok {
			out = append(out, role)
		}
	}
	return out, nil
}
func (r *inMemoryOrgRoleRepo) ListUserIDsForRole(_ context.Context, _ uuid.UUID) ([]uuid.UUID, error) {
	panic("not used")
}
func (r *inMemoryOrgRoleRepo) GetScopesForUser(_ context.Context, _ uuid.UUID, _ *uuid.UUID) ([]string, error) {
	panic("not used")
}

// ---------- Create ----------

func TestOrgRole_CreateOrgAdminSameOrg(t *testing.T) {
	svc := NewOrgRoleService(nil, newOrgRoleRepo(), nil)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org}
	role, err := svc.CreateRoleForActor(context.Background(), actor, org, "Editors", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if role.OrgID != org || role.Name != "Editors" {
		t.Errorf("unexpected role: %+v", role)
	}
}

func TestOrgRole_CreateOrgAdminCrossOrgForbidden(t *testing.T) {
	svc := NewOrgRoleService(nil, newOrgRoleRepo(), nil)
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}
	_, err := svc.CreateRoleForActor(context.Background(), actor, uuid.New(), "X", "")
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("cross-org create = %v, want ErrForbidden", err)
	}
}

func TestOrgRole_CreateOrgUserForbidden(t *testing.T) {
	svc := NewOrgRoleService(nil, newOrgRoleRepo(), nil)
	actor := &domain.Principal{Role: domain.RoleOrgUser, OrganizationID: uuid.New()}
	_, err := svc.CreateRoleForActor(context.Background(), actor, actor.OrganizationID, "X", "")
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("org_user create = %v, want ErrForbidden", err)
	}
}

func TestOrgRole_CreateSiteAdminAnyOrg(t *testing.T) {
	svc := NewOrgRoleService(nil, newOrgRoleRepo(), nil)
	actor := &domain.Principal{Role: domain.RoleSiteAdmin}
	role, err := svc.CreateRoleForActor(context.Background(), actor, uuid.New(), "X", "")
	if err != nil {
		t.Errorf("site_admin Create: %v", err)
	}
	if role == nil {
		t.Errorf("site_admin Create returned nil role")
	}
}

func TestOrgRole_CreateBaselineNoActorUnauthorized(t *testing.T) {
	svc := NewOrgRoleService(nil, newOrgRoleRepo(), nil)
	_, err := svc.CreateRoleForActor(context.Background(), nil, uuid.New(), "X", "")
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("nil actor = %v, want ErrUnauthorized", err)
	}
}

// ---------- Get / List ----------

func TestOrgRole_GetOrgAdminCrossOrgForbidden(t *testing.T) {
	repo := newOrgRoleRepo()
	svc := NewOrgRoleService(nil, repo, nil)
	otherRole := &domain.OrgRole{ID: uuid.New(), OrgID: uuid.New(), Name: "Other"}
	_ = repo.Create(context.Background(), otherRole)
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}
	_, err := svc.GetRoleForActor(context.Background(), actor, otherRole.ID)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("cross-org Get = %v, want ErrForbidden", err)
	}
}

func TestOrgRole_ListOrgAdminScopedByOrg(t *testing.T) {
	repo := newOrgRoleRepo()
	svc := NewOrgRoleService(nil, repo, nil)
	org := uuid.New()
	_ = repo.Create(context.Background(), &domain.OrgRole{ID: uuid.New(), OrgID: org, Name: "A"})
	_ = repo.Create(context.Background(), &domain.OrgRole{ID: uuid.New(), OrgID: uuid.New(), Name: "B"})
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org}
	roles, err := svc.ListRolesForActor(context.Background(), actor, org)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(roles) != 1 || roles[0].Name != "A" {
		t.Errorf("expected only role A for org_admin, got %+v", roles)
	}
}

// ---------- Update / Delete ----------

func TestOrgRole_UpdateOrgAdminCrossOrgForbidden(t *testing.T) {
	repo := newOrgRoleRepo()
	svc := NewOrgRoleService(nil, repo, nil)
	other := &domain.OrgRole{ID: uuid.New(), OrgID: uuid.New(), Name: "Other"}
	_ = repo.Create(context.Background(), other)
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}
	name := "X"
	_, err := svc.UpdateRoleForActor(context.Background(), actor, other.ID, UpdateOrgRoleOptions{Name: &name})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("cross-org Update = %v, want ErrForbidden", err)
	}
}

func TestOrgRole_DeleteOrgAdminCrossOrgForbidden(t *testing.T) {
	repo := newOrgRoleRepo()
	svc := NewOrgRoleService(nil, repo, nil)
	other := &domain.OrgRole{ID: uuid.New(), OrgID: uuid.New(), Name: "Other"}
	_ = repo.Create(context.Background(), other)
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}
	err := svc.DeleteRoleForActor(context.Background(), actor, other.ID)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("cross-org Delete = %v, want ErrForbidden", err)
	}
}

// ---------- ListRolesForUser tenant filter ----------

func TestOrgRole_ListRolesForUserScoped(t *testing.T) {
	repo := newOrgRoleRepo()
	svc := NewOrgRoleService(nil, repo, nil)
	org := uuid.New()
	roleA := &domain.OrgRole{ID: uuid.New(), OrgID: org, Name: "A"}
	roleB := &domain.OrgRole{ID: uuid.New(), OrgID: uuid.New(), Name: "B"}
	_ = repo.Create(context.Background(), roleA)
	_ = repo.Create(context.Background(), roleB)
	target := uuid.New()
	_ = repo.AssignRoleToUser(context.Background(), target, roleA.ID, uuid.New())
	_ = repo.AssignRoleToUser(context.Background(), target, roleB.ID, uuid.New())
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org}
	roles, err := svc.ListRolesForUserForActor(context.Background(), actor, target)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(roles) != 1 || roles[0].Name != "A" {
		t.Errorf("expected only A for same-org actor, got %+v", roles)
	}
}

// ---------- ListMyRoles ----------

func TestOrgRole_ListMyRolesReturnsCallerBindings(t *testing.T) {
	repo := newOrgRoleRepo()
	svc := NewOrgRoleService(nil, repo, nil)
	org := uuid.New()
	role := &domain.OrgRole{ID: uuid.New(), OrgID: org, Name: "Mine"}
	_ = repo.Create(context.Background(), role)
	uid := uuid.New()
	_ = repo.AssignRoleToUser(context.Background(), uid, role.ID, uuid.New())
	actor := &domain.Principal{Role: domain.RoleOrgUser, OrganizationID: org, UserID: uid}
	roles, err := svc.ListMyRoles(context.Background(), actor)
	if err != nil || len(roles) != 1 {
		t.Errorf("ListMyRoles = %v, %v; want one role", roles, err)
	}
}

// ---------- AddScopeForActor without APIResourceRepo ----------

func TestOrgRole_AddScopeWithoutAPIResourceRepoFails(t *testing.T) {
	repo := newOrgRoleRepo()
	svc := NewOrgRoleService(nil, repo, nil)
	org := uuid.New()
	role := &domain.OrgRole{ID: uuid.New(), OrgID: org, Name: "X"}
	_ = repo.Create(context.Background(), role)
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org}
	err := svc.AddScopeForActor(context.Background(), actor, role.ID, uuid.New(), "billing:read")
	if !errors.Is(err, errOrgRoleAPIResourceRepoMissing) {
		t.Errorf("missing repo err = %v, want errOrgRoleAPIResourceRepoMissing", err)
	}
}

// ---------- AssignRoleToUserForActor tenant binding ----------

func TestOrgRole_AssignRoleCrossOrgForbidden(t *testing.T) {
	repo := newOrgRoleRepo()
	svc := NewOrgRoleService(nil, repo, nil)
	role := &domain.OrgRole{ID: uuid.New(), OrgID: uuid.New(), Name: "Other"}
	_ = repo.Create(context.Background(), role)
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}
	err := svc.AssignRoleToUserForActor(context.Background(), actor, uuid.New(), role.ID)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("cross-org Assign = %v, want ErrForbidden", err)
	}
}

func TestOrgRole_ErrOrgRoleNotFoundExposed(t *testing.T) {
	if !errors.Is(ErrOrgRoleNotFound(), errOrgRoleNotFound) {
		t.Error("ErrOrgRoleNotFound sentinel not exposed")
	}
}
