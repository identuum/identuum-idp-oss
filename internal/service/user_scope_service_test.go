package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// inMemoryUserScopeRepo is a tiny fake OrgRoleRepository that
// exposes only the GetScopesForUser hot path the UserScopeService
// touches. Other methods panic; only GetScopesForUser and the
// audience-filter pass-through are exercised here.
type inMemoryUserScopeRepo struct {
	*inMemoryOrgRoleRepo
	out          []string
	err          error
	lastUserID   uuid.UUID
	lastResource *uuid.UUID
}

func newUserScopeRepo() *inMemoryUserScopeRepo {
	return &inMemoryUserScopeRepo{inMemoryOrgRoleRepo: newOrgRoleRepo()}
}

func (r *inMemoryUserScopeRepo) GetScopesForUser(_ context.Context, userID uuid.UUID, resourceID *uuid.UUID) ([]string, error) {
	r.lastUserID = userID
	r.lastResource = resourceID
	if r.err != nil {
		return nil, r.err
	}
	out := append([]string(nil), r.out...)
	return out, nil
}

func (r *inMemoryUserScopeRepo) ListUserIDsForRole(_ context.Context, _ uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}

// ---------- AssignRoleToUserForActor revoke ----------

// seedTargetUser creates an org_user in `org` whose ID is `id`.
// Used by Assign tests so the new target-user tenant guard finds
// a valid same-org user before the revocation fan-out can fire.
func seedTargetUser(t *testing.T, userRepo *inMemoryUserRepo, id, org uuid.UUID, role domain.UserRole) {
	t.Helper()
	if _, err := userRepo.Create(context.Background(), &domain.User{
		ID:             id,
		OrganizationID: org,
		Email:          "u@test",
		Role:           role,
		PasswordHash:   "hashed",
	}); err != nil {
		t.Fatalf("seedTargetUser: %v", err)
	}
}

func TestOrgRoleService_AssignRoleFiresRevokeForTarget(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	userRepo := newUserRepo()
	rev := &RecorderSessionRevoker{}
	svc := NewOrgRoleService(nil, repo, nil).
		WithUserRepository(userRepo).
		WithSessionRevoker(rev)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	target := uuid.New()
	seedTargetUser(t, userRepo, target, org, domain.RoleOrgUser)
	if err := svc.AssignRoleToUserForActor(context.Background(), actor, target, role.ID); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	calls := rev.Calls()
	if len(calls) != 1 || calls[0].UserID != target || calls[0].Reason != "rbac_role_assigned" {
		t.Errorf("expected single revoke for target with rbac_role_assigned; got %+v", calls)
	}
	// Metadata must not contain tokens / session ids / secrets.
	for k := range calls[0].Metadata {
		switch k {
		case "token", "session_id", "client_secret", "password", "scope":
			t.Errorf("revoke metadata leaked banned key %q", k)
		}
	}
}

func TestOrgRoleService_AssignRoleRevokerErrorSwallowed(t *testing.T) {
	repo := newOrgRoleRepoForHooks()
	userRepo := newUserRepo()
	rev := &RecorderSessionRevoker{Err: errors.New("revoker down")}
	svc := NewOrgRoleService(nil, repo, nil).
		WithUserRepository(userRepo).
		WithSessionRevoker(rev)
	org := uuid.New()
	actor := &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org, UserID: uuid.New()}
	role, _ := svc.CreateRoleForActor(context.Background(), actor, org, "X", "")
	target := uuid.New()
	seedTargetUser(t, userRepo, target, org, domain.RoleOrgUser)
	if err := svc.AssignRoleToUserForActor(context.Background(), actor, target, role.ID); err != nil {
		t.Errorf("Assign returned err on revoker failure: %v", err)
	}
	if len(rev.Calls()) != 1 {
		t.Errorf("revoker not invoked despite error policy; calls=%d", len(rev.Calls()))
	}
}

// ---------- UserScopeService ----------

func TestUserScopeService_NewRequiresRepo(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewUserScopeService(nil, nil) did not panic")
		}
	}()
	_ = NewUserScopeService(nil, nil)
}

func TestUserScopeService_GetScopesForUserNilUserID(t *testing.T) {
	svc := NewUserScopeService(nil, newUserScopeRepo())
	_, err := svc.GetScopesForUser(context.Background(), uuid.Nil, nil)
	if !errors.Is(err, ErrInvalidUserID()) {
		t.Errorf("nil userID = %v, want ErrInvalidUserID", err)
	}
}

func TestUserScopeService_GetScopesForUserDedupesAndSorts(t *testing.T) {
	repo := newUserScopeRepo()
	repo.out = []string{"users:write", "users:read", "users:read", "billing:read", "users:write"}
	svc := NewUserScopeService(nil, repo)
	got, err := svc.GetScopesForUser(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	want := []string{"billing:read", "users:read", "users:write"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q (full got=%v)", i, got[i], want[i], got)
		}
	}
}

func TestUserScopeService_PassesResourceFilterThrough(t *testing.T) {
	repo := newUserScopeRepo()
	svc := NewUserScopeService(nil, repo)
	uid := uuid.New()
	resID := uuid.New()
	_, _ = svc.GetScopesForUser(context.Background(), uid, &resID)
	if repo.lastUserID != uid {
		t.Errorf("repo got userID = %s, want %s", repo.lastUserID, uid)
	}
	if repo.lastResource == nil || *repo.lastResource != resID {
		t.Errorf("repo got resource = %v, want %s", repo.lastResource, resID)
	}
}

func TestUserScopeService_GetScopesForUserPropagatesRepoErr(t *testing.T) {
	repo := newUserScopeRepo()
	want := errors.New("repo down")
	repo.err = want
	svc := NewUserScopeService(nil, repo)
	_, err := svc.GetScopesForUser(context.Background(), uuid.New(), nil)
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}

func TestUserScopeService_EmptyResultIsNonNilSlice(t *testing.T) {
	repo := newUserScopeRepo()
	svc := NewUserScopeService(nil, repo)
	got, err := svc.GetScopesForUser(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Errorf("empty result must be non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}

func TestUserScopeService_GetScopesForPrincipalNilPrincipal(t *testing.T) {
	svc := NewUserScopeService(nil, newUserScopeRepo())
	_, err := svc.GetScopesForPrincipal(context.Background(), nil, nil)
	if !errors.Is(err, ErrNilPrincipal()) {
		t.Errorf("nil principal = %v, want ErrNilPrincipal", err)
	}
}

func TestUserScopeService_GetScopesForPrincipalNilUserID(t *testing.T) {
	svc := NewUserScopeService(nil, newUserScopeRepo())
	p := &domain.Principal{Role: domain.RoleOrgUser}
	_, err := svc.GetScopesForPrincipal(context.Background(), p, nil)
	if !errors.Is(err, ErrInvalidUserID()) {
		t.Errorf("nil UserID = %v, want ErrInvalidUserID", err)
	}
}

func TestUserScopeService_GetScopesForPrincipalDelegatesToGet(t *testing.T) {
	repo := newUserScopeRepo()
	repo.out = []string{"profile:read"}
	svc := NewUserScopeService(nil, repo)
	uid := uuid.New()
	got, err := svc.GetScopesForPrincipal(context.Background(), &domain.Principal{UserID: uid, Role: domain.RoleOrgUser}, nil)
	if err != nil {
		t.Fatalf("GetForPrincipal: %v", err)
	}
	if len(got) != 1 || got[0] != "profile:read" {
		t.Errorf("scopes = %v", got)
	}
	if repo.lastUserID != uid {
		t.Errorf("delegated userID = %s, want %s", repo.lastUserID, uid)
	}
}
