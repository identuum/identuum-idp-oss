package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-FIN-1 (D-017): a user created with an admin-set password proves it and
// is answered the change step FIRST — before MFA enrolment or verification,
// before any session — whatever the MFA policy. Before this slice the flag
// collapsed to invalid_credentials, so such a user could never sign in.
func TestLogin_RequiredPasswordChangeComesFirst(t *testing.T) {
	required := "required"
	for _, tt := range []struct {
		name string
		user domain.User
	}{
		{"org_user, optional MFA", domain.User{Role: domain.RoleOrgUser}},
		{"org_user, MFA required, not enrolled", domain.User{Role: domain.RoleOrgUser, MFAPolicy: &required}},
		{"org_admin (MFA always required), not enrolled", domain.User{Role: domain.RoleOrgAdmin}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc, users := newLoginHarness(t)
			u := tt.user
			u.ID = uuid.New()
			u.Email = "set-by-admin@example.com"
			u.PasswordHash = hashPwd(t, "admin-set")
			u.EmailVerified = true
			u.RequiresPasswordChange = true
			users.byEmail[u.Email] = []*domain.User{&u}
			res, err := svc.Login(context.Background(), LoginInput{Email: u.Email, Password: "admin-set"})
			if !errors.Is(err, ErrLoginPasswordChangeRequired) {
				t.Fatalf("err = %v; want ErrLoginPasswordChangeRequired", err)
			}
			if res == nil || res.User == nil || res.User.ID != u.ID || res.Session != nil || res.RefreshToken != "" {
				t.Errorf("result = %+v; want the user and no session or token", res)
			}
		})
	}
}

// A wrong password never reaches the change step.
func TestLogin_RequiredPasswordChangeNeedsThePassword(t *testing.T) {
	svc, users := newLoginHarness(t)
	u := &domain.User{ID: uuid.New(), Email: "set-by-admin@example.com", PasswordHash: hashPwd(t, "admin-set"), EmailVerified: true, RequiresPasswordChange: true, Role: domain.RoleOrgUser}
	users.byEmail[u.Email] = []*domain.User{u}
	if _, err := svc.Login(context.Background(), LoginInput{Email: u.Email, Password: "wrong"}); !errors.Is(err, ErrLoginInvalidCredentials) {
		t.Errorf("err = %v; want ErrLoginInvalidCredentials", err)
	}
}
