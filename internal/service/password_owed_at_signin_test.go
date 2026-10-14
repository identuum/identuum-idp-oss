package service

import (
	"errors"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-0914-MUSTCHANGE: the gate a passkey or upstream sign-in applies answers
// what password sign-in answers for the same state, and never asks a member
// with no local password for one.
func TestPasswordOwedAtSignIn(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Hour)
	old := now.Add(-AdminSetPasswordTTL - time.Second)
	member := func(mod func(*domain.User)) *domain.User {
		u := &domain.User{Role: domain.RoleOrgUser, PasswordHash: "argon2id-hash", AuthSource: domain.AuthSourceLocal}
		mod(u)
		return u
	}
	cases := []struct {
		label  string
		user   *domain.User
		policy string
		want   error
	}{
		{"no user", nil, "", nil},
		{"chosen password", member(func(*domain.User) {}), "", nil},
		{"change requested", member(func(u *domain.User) { u.RequiresPasswordChange = true; u.AdminPasswordSetAt = &recent }), "", ErrLoginPasswordChangeRequired},
		{"change requested, row from before 0055", member(func(u *domain.User) { u.RequiresPasswordChange = true }), "", ErrLoginPasswordChangeRequired},
		{"empty auth source is local", member(func(u *domain.User) { u.AuthSource = ""; u.RequiresPasswordChange = true }), "", ErrLoginPasswordChangeRequired},
		{"expired", member(func(u *domain.User) { u.RequiresPasswordChange = true; u.AdminPasswordSetAt = &old }), "", ErrLoginPasswordExpired},
		{"old time without the flag", member(func(u *domain.User) { u.AdminPasswordSetAt = &old }), "", nil},
		{"no local password", member(func(u *domain.User) {
			u.PasswordHash = domain.NoPasswordSentinel
			u.RequiresPasswordChange = true
			u.AdminPasswordSetAt = &old
		}), "", nil},
		{"provider-owned account", member(func(u *domain.User) { u.AuthSource = domain.AuthSourceIDJag; u.RequiresPasswordChange = true }), "", nil},
		{"idp_only member", member(func(u *domain.User) { u.RequiresPasswordChange = true }), domain.AuthPolicyIDPOnly, nil},
		{"idp_only administrator", member(func(u *domain.User) { u.Role = domain.RoleOrgAdmin; u.RequiresPasswordChange = true }), domain.AuthPolicyIDPOnly, ErrLoginPasswordChangeRequired},
	}
	for _, tc := range cases {
		if got := PasswordOwedAtSignIn(tc.user, tc.policy, now); !errors.Is(got, tc.want) || (tc.want == nil && got != nil) {
			t.Errorf("%s: PasswordOwedAtSignIn = %v; want %v", tc.label, got, tc.want)
		}
	}
}
