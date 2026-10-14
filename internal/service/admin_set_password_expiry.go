package service

// admin_set_password_expiry.go — G2 (owner answers Q-G2 (a) and Q-G2b (a),
// 2026-10-13): a password an administrator sets with the must-change flag
// (create or PUT /api/v1/users/:id) is a one-time credential. It expires
// AdminSetPasswordTTL after the administrator set it; password sign-in and the
// sign-in change step then refuse it with ErrLoginPasswordExpired, and the
// member asks the administrator for a reset link. A NULL time (a lasting
// password, a chosen one, or a row from before migration 0055) never expires.

import (
	"errors"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AdminSetPasswordTTL is the lifetime of an administrator-set password that
// must be changed, and of the administrator's reset link (D9): one figure for
// both one-time credentials an administrator hands to a member.
const AdminSetPasswordTTL = 24 * time.Hour

// ErrLoginPasswordExpired → 401 password_expired: the correct admin-set
// password, past AdminSetPasswordTTL. No session, no change step.
var ErrLoginPasswordExpired = errors.New("service: login admin-set password expired")

// adminSetPasswordExpired reports whether u's password is an admin-set one
// still owed a change and set more than AdminSetPasswordTTL before now.
func adminSetPasswordExpired(u *domain.User, now time.Time) bool {
	return u != nil && u.RequiresPasswordChange && u.AdminPasswordSetAt != nil &&
		now.Sub(*u.AdminPasswordSetAt) > AdminSetPasswordTTL
}

// PasswordOwedAtSignIn is the D-017 / G2 gate of a sign-in that proves the
// member without the password: a passkey or an upstream provider
// (OSS-0914-MUSTCHANGE). It answers what password sign-in answers for the
// same state, ErrLoginPasswordExpired or ErrLoginPasswordChangeRequired, so
// no session exists before the member chooses a password. A member with no
// local password is never asked for one: no hash, an account the provider
// owns (the change step, ChangeRequiredAtSignIn, refuses it), or local
// credentials barred by the organization's policy (idp_only).
func PasswordOwedAtSignIn(u *domain.User, orgAuthPolicy string, now time.Time) error {
	if u == nil || u.PasswordHash == domain.NoPasswordSentinel ||
		(u.AuthSource != "" && u.AuthSource != domain.AuthSourceLocal) ||
		!IsLocalCredentialFlowAllowed(u, orgAuthPolicy).Allowed {
		return nil
	}
	if adminSetPasswordExpired(u, now) {
		return ErrLoginPasswordExpired
	}
	if u.RequiresPasswordChange {
		return ErrLoginPasswordChangeRequired
	}
	return nil
}
