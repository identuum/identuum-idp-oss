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
// R2 — RULED 2026-08-21: a successful change revokes all the user's OTHER
// sessions and OAuth refresh tokens; the changing session stays valid. The
// fan-out lives in the HANDLER (HandleChangePassword), which owns the
// principal's SessionID — this service stays hash-only by design so the
// keep-current decision sits next to the identity that knows "current".

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
// Hash-only by design — the R2 revocation fan-out is the handler's (it
// holds the current-session identity); see the file header.
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

// ErrRequiredChangeUnavailable covers every reason the sign-in's required
// change cannot run: no such user, deleted, banned, non-local, or the flag
// already cleared (a second submit). One opaque answer.
var ErrRequiredChangeUnavailable = domainSentinel("change_password: no required change")

// ChangeRequiredAtSignIn (OSS-FIN-1, D-017) sets the password of a user who
// signed in with an admin-set password and must choose their own. The caller
// has already proven the current password (and holds the one-time pending
// handle that says so), so no current password is taken here. The new one
// must satisfy the organization's policy and differ from the admin-set one.
// The UPDATE clears requires_password_change only while it is still set, so
// the change wins once. Returns the user re-read with its organization
// projections, which the rest of the sign-in (MFA gate, session) needs.
func (s *ChangePasswordService) ChangeRequiredAtSignIn(ctx context.Context, userID uuid.UUID, newPassword string) (*domain.User, error) {
	user, err := s.users.GetByIDWithOrg(ctx, userID)
	if err != nil || user == nil || user.DeletedAt != nil || user.Banned || !user.RequiresPasswordChange {
		return nil, ErrRequiredChangeUnavailable
	}
	if user.AuthSource != "" && user.AuthSource != domain.AuthSourceLocal {
		return nil, ErrRequiredChangeUnavailable
	}
	complexityEnabled := true
	if user.OrgPasswordComplexityEnabled != nil {
		complexityEnabled = *user.OrgPasswordComplexityEnabled
	}
	if err := domain.ValidatePasswordPolicy(newPassword, s.minPasswordLength, complexityEnabled); err != nil {
		return nil, &ChangePasswordPolicyError{Detail: err.Error()}
	}
	if strings.TrimSpace(user.PasswordHash) != "" && s.users.VerifyPassword(ctx, newPassword, user.PasswordHash) == nil {
		return nil, &ChangePasswordPolicyError{Detail: "choose a password different from the one you were given"}
	}
	hash, err := s.users.HashPassword(newPassword)
	if err != nil {
		return nil, domainSentinel("change_password: hash failed")
	}
	cleared := false
	updated, err := s.users.Update(ctx, user.ID, user.OrganizationID, repository.UpdateUserOptions{
		Password:                     &hash,
		RequiresPasswordChange:       &cleared,
		RequirePasswordChangePending: true,
	})
	if err != nil || updated == nil {
		return nil, ErrRequiredChangeUnavailable
	}
	reloaded, err := s.users.GetByIDWithOrg(ctx, userID)
	if err != nil || reloaded == nil {
		return nil, ErrRequiredChangeUnavailable
	}
	return reloaded, nil
}
