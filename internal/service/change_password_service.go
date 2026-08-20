package service

// change_password_service.go — OSS self-service password change
// (THE-V036-PASSWORD). The service backs POST /api/v1/auth/change-password:
// the AUTHENTICATED user changes their OWN password — the target is always
// the caller's principal, never a wire-supplied user id, so cross-user
// changes are structurally impossible (AdminPermissionsModel: admins do not
// rotate other users' passwords through this surface).
//
// Contract:
//   - The CURRENT password must verify against the stored hash. Non-local
//     accounts (OIDC/LDAP AuthSource) and rows without a local hash are
//     refused through the SAME opaque error as a wrong password — the wire
//     never distinguishes "federated account" from "wrong current password"
//     (mirrors the /me/mfa/disable opaqueness contract).
//   - The NEW password is validated against the per-org password policy
//     (Decision D-015 §9): org PasswordComplexityEnabled, nil ⇒ strict; the
//     minimum-length floor mirrors the password-reset default (8).
//   - On success ONLY the password hash is updated.
//
// R2 — SESSION REVOCATION IS DELIBERATELY PARKED (owner ruling
// DECIDE-LATER, 2026-08-20): unlike ResetPassword (P0-9), this service
// touches NEITHER sessions NOR refresh tokens. When R2 is decided, the
// revocation fan-out (and its rule) lands as its own slice; nothing here
// pre-empts that decision.

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// ErrChangePasswordInvalidCurrent is the OPAQUE refusal for every
// current-password failure shape: wrong password, non-local AuthSource,
// or a row with no local hash. One error, one wire envelope.
var ErrChangePasswordInvalidCurrent = domainSentinel("change_password: invalid current password")

// ErrChangePasswordUnauthorized covers a missing, soft-deleted, or banned
// principal row — the caller's bearer outlived their account state.
var ErrChangePasswordUnauthorized = domainSentinel("change_password: unauthorized")

// ChangePasswordPolicyError carries the SAFE, displayable policy-violation
// text for the 400 envelope (the UI shows `message` verbatim on 400).
type ChangePasswordPolicyError struct{ Detail string }

func (e *ChangePasswordPolicyError) Error() string { return e.Detail }

// domainSentinel builds an error sentinel without importing errors.New at
// every declaration site.
func domainSentinel(msg string) error { return &sentinelError{msg} }

type sentinelError struct{ msg string }

func (e *sentinelError) Error() string { return e.msg }

// ChangePasswordService verifies the current password and rotates the hash.
type ChangePasswordService struct {
	users             repository.UserRepository
	minPasswordLength int
}

// NewChangePasswordService wires the repository. minPasswordLength <= 0
// falls back to 8 — the same floor the password-reset service defaults to.
func NewChangePasswordService(users repository.UserRepository, minPasswordLength int) *ChangePasswordService {
	if minPasswordLength <= 0 {
		minPasswordLength = 8
	}
	return &ChangePasswordService{users: users, minPasswordLength: minPasswordLength}
}

// ChangeOwnPassword performs the self-service rotation for userID.
// Sessions and refresh tokens are NOT touched (R2 parked — see file header).
func (s *ChangePasswordService) ChangeOwnPassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	if userID == uuid.Nil {
		return ErrChangePasswordUnauthorized
	}
	// GetByIDWithOrg carries OrgPasswordComplexityEnabled for the policy leg.
	user, err := s.users.GetByIDWithOrg(ctx, userID)
	if err != nil || user == nil {
		return ErrChangePasswordUnauthorized
	}
	if user.DeletedAt != nil || user.Banned {
		return ErrChangePasswordUnauthorized
	}
	// Current-password proof — opaque on every failure shape (see header).
	if strings.TrimSpace(currentPassword) == "" {
		return ErrChangePasswordInvalidCurrent
	}
	if user.AuthSource != "" && user.AuthSource != domain.AuthSourceLocal {
		return ErrChangePasswordInvalidCurrent
	}
	if strings.TrimSpace(user.PasswordHash) == "" {
		return ErrChangePasswordInvalidCurrent
	}
	if err := s.users.VerifyPassword(ctx, currentPassword, user.PasswordHash); err != nil {
		return ErrChangePasswordInvalidCurrent
	}
	// Per-org password policy (Decision D-015 §9). nil ⇒ strict mode.
	complexityEnabled := true
	if user.OrgPasswordComplexityEnabled != nil {
		complexityEnabled = *user.OrgPasswordComplexityEnabled
	}
	if err := domain.ValidatePasswordPolicy(newPassword, s.minPasswordLength, complexityEnabled); err != nil {
		return &ChangePasswordPolicyError{Detail: err.Error()}
	}
	hash, err := s.users.HashPassword(newPassword)
	if err != nil {
		return domainSentinel("change_password: hash failed")
	}
	updated, err := s.users.Update(ctx, user.ID, user.OrganizationID, repository.UpdateUserOptions{
		Password: &hash,
	})
	if err != nil {
		return err
	}
	if updated == nil {
		return ErrChangePasswordUnauthorized
	}
	// R2 parked: NO session revocation, NO refresh-token revocation here.
	return nil
}
