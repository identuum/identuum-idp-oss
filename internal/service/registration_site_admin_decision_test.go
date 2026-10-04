package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// regDecisionRepo answers every user as held for approval and records state.
type regDecisionRepo struct {
	repository.RegistrationRepository
	state map[uuid.UUID]string
}

func (r *regDecisionRepo) UserState(_ context.Context, id uuid.UUID) (string, bool, error) {
	if s, ok := r.state[id]; ok {
		return s, false, nil
	}
	return domain.RegistrationStatePendingApproval, false, nil
}

func (r *regDecisionRepo) SetUserState(_ context.Context, id uuid.UUID, s string) error {
	r.state[id] = s
	return nil
}

type regDecisionUsers struct {
	user    *domain.User
	deleted bool
}

func (u *regDecisionUsers) FindUsersByEmail(context.Context, string) ([]*domain.User, error) {
	return nil, nil
}
func (u *regDecisionUsers) GetByID(context.Context, uuid.UUID) (*domain.User, error) {
	return u.user, nil
}
func (u *regDecisionUsers) Delete(context.Context, uuid.UUID, uuid.UUID) error {
	u.deleted = true
	return nil
}

// D-025: a held self-registrant is approved or rejected by the organization's
// own org_admin. A site_admin never decides it.
func TestRegistrationDecisions_SiteAdminRefusedOrgAdminDecides(t *testing.T) {
	ctx := context.Background()
	org := uuid.New()
	newSvc := func() (*RegistrationService, *regDecisionRepo, *regDecisionUsers, *domain.User) {
		user := &domain.User{ID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgUser, Email: "held@x.test"}
		repo := &regDecisionRepo{state: map[uuid.UUID]string{}}
		users := &regDecisionUsers{user: user}
		return NewRegistrationService(RegistrationServiceConfig{Repo: repo, Users: users}), repo, users, user
	}

	svc, repo, users, user := newSvc()
	if _, err := svc.Approve(ctx, siteAdminActor(), user.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("site_admin approve: err=%v, want ErrForbidden", err)
	}
	if err := svc.Reject(ctx, siteAdminActor(), user.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("site_admin reject: err=%v, want ErrForbidden", err)
	}
	if len(repo.state) != 0 || users.deleted {
		t.Error("a refused decision still changed the registration")
	}

	svc, repo, _, user = newSvc()
	if _, err := svc.Approve(ctx, orgAdminActor(org), user.ID); err != nil {
		t.Errorf("the organization's org_admin must approve: %v", err)
	}
	if repo.state[user.ID] != domain.RegistrationStateActive {
		t.Errorf("approval left state %q", repo.state[user.ID])
	}
	svc, _, users, user = newSvc()
	if err := svc.Reject(ctx, orgAdminActor(org), user.ID); err != nil || !users.deleted {
		t.Errorf("the organization's org_admin must reject: err=%v deleted=%v", err, users.deleted)
	}
}
