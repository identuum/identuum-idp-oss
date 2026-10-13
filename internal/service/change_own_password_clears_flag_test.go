package service

// Q-B2 brief item 3: "the member's own password change ... still clear the
// flag". Measured at f25841b: ChangeOwnPassword (POST
// /api/v1/auth/change-password) writes only the password hash
// (change_password_service.go:114-116), so a member who signs in by passkey
// or upstream after an admin set a password, then changes it at Account
// settings, is still asked for a change at the next password sign-in. Only
// ChangeRequiredAtSignIn (:138-176) clears it. RED today.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

type qb2OwnRepo struct {
	repository.UserRepository
	user *domain.User
	last *repository.UpdateUserOptions
}

func (r *qb2OwnRepo) GetByIDWithOrg(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if r.user == nil || r.user.ID != id {
		return nil, domain.ErrUserNotFound
	}
	cp := *r.user
	return &cp, nil
}

func (r *qb2OwnRepo) VerifyPassword(_ context.Context, pw, hash string) error {
	if hash != "h:"+pw {
		return errors.New("mismatch")
	}
	return nil
}

func (r *qb2OwnRepo) HashPassword(_ context.Context, pw string) (string, error) {
	return "h:" + pw, nil
}

func (r *qb2OwnRepo) Update(_ context.Context, _ uuid.UUID, _ uuid.UUID, o repository.UpdateUserOptions) (*domain.User, error) {
	cp := o
	r.last = &cp
	out := *r.user
	return &out, nil
}

// RULE: QB2-CHOSEN-CLEARS-1
func TestChangeOwnPassword_ClearsRequiredChange(t *testing.T) {
	u := &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Email: "m@example.test", Role: domain.RoleOrgUser,
		AuthSource: domain.AuthSourceLocal, EmailVerified: true, PasswordHash: "h:Admin-Set-2026!a", RequiresPasswordChange: true}
	repo := &qb2OwnRepo{user: u}
	svc := NewChangePasswordService(repo, 8)
	if err := svc.ChangeOwnPassword(context.Background(), u.ID, "Admin-Set-2026!a", "Member-Own-2026!b"); err != nil {
		t.Fatalf("ChangeOwnPassword: %v", err)
	}
	if repo.last == nil || repo.last.Password == nil {
		t.Fatalf("no password write")
	}
	if repo.last.RequiresPasswordChange == nil || *repo.last.RequiresPasswordChange {
		t.Errorf("the member's own change did not clear requires_password_change (got %v)", repo.last.RequiresPasswordChange)
	}
}
