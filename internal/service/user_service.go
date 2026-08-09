package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// UserService is the OSS-narrow user admin surface. It deliberately
// takes ONLY the user repository: tenant guards are enforced at the
// HTTP middleware layer (RequireSiteAdmin) and per-organization
// guards will be layered on in a later CE composition slice. Out of
// scope here: bulk-create job dispatch, MFA reset (AuthService),
// password reset, registration-approval flows, activation-token
// generation, and SCIM. Each of those routes through commercial
// services that are not in OSS yet.
type UserService struct {
	repo repository.UserRepository
}

// NewUserService constructs a UserService. repo must be non-nil.
func NewUserService(report *lifecycle.StartupReport, repo repository.UserRepository) *UserService {
	if repo == nil {
		report.Fatal("NewUserService", "service: NewUserService requires a non-nil UserRepository")
	}
	return &UserService{repo: repo}
}

// CreateUserOptions is the OSS create shape. Password is required
// (the OSS service does not yet wire OIDC-JIT or activation-link
// flows). The plaintext password is hashed by the repository's
// HashPassword helper and never stored or returned.
type CreateUserOptions struct {
	OrganizationID uuid.UUID
	Email          string
	Password       string
	Name           string
	Role           domain.UserRole

	// PasswordComplexityEnabled is the per-org policy resolved by the
	// caller (typically the handler reading the target org row). nil
	// ⇒ strict mode (complexity required). Wired by slice
	// agent-a-20260715-idp-oss-password-complexity-perorg-enforcement
	// (Decision D-015 §9).
	PasswordComplexityEnabled *bool
	// MinPasswordLength is the policy floor; 0 ⇒ safe default of 8.
	MinPasswordLength int
}

// UpdateUserOptions is forwarded verbatim to repository.UpdateUserOptions
// but with Password handled in-service (hashed before persistence) so
// the HTTP handler never sees the hash.
type UpdateUserOptions struct {
	Email         *string
	Password      *string
	Name          *string
	Role          *domain.UserRole
	Banned        *bool
	EmailVerified *bool

	// PasswordComplexityEnabled is the per-org policy resolved by the
	// caller. nil ⇒ strict mode. Only consulted when Password is non-nil.
	PasswordComplexityEnabled *bool
	// MinPasswordLength is the policy floor; 0 ⇒ safe default of 8.
	MinPasswordLength int
}

var errUserNotFound = errors.New("service: user not found")

// ErrUserNotFound exposes the OSS not-found sentinel.
func ErrUserNotFound() error { return errUserNotFound }

var errUserNotPendingApproval = errors.New("service: user is not a pending self-registration")

// ErrUserNotPendingApproval exposes the sentinel returned when an
// approval target is not in the public_registration hold state
// (banned=true AND role=org_user). The handler maps it to 409 so an
// approval can never silently succeed as a back-door un-ban.
func ErrUserNotPendingApproval() error { return errUserNotPendingApproval }

// Create persists a new user. It hashes the supplied password
// before insert and clears the field from the in-memory User
// before returning. The returned User is safe to project onto a
// safe DTO at the handler.
func (s *UserService) Create(ctx context.Context, opts CreateUserOptions) (*domain.User, error) {
	// AdminPermissionsModel.md: "Only site_admin user CAN be a member of System
	// organization." Creating an org_user or org_admin there answered 201.
	// The site_admin itself must still be writable, or bootstrap and
	// recover-site-admin could not run.
	if opts.OrganizationID.String() == domain.SystemOrgID && opts.Role != domain.RoleSiteAdmin {
		return nil, domain.ErrForbidden
	}
	if opts.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if opts.Password == "" {
		return nil, fmt.Errorf("password is required")
	}
	if !opts.Role.IsValid() {
		return nil, fmt.Errorf("invalid role")
	}
	// Per-org PasswordComplexityEnabled enforcement (Decision D-015 §9,
	// slice agent-a-20260715). nil ⇒ strict mode. Bootstrap/recovery
	// paths use ValidatePassword (strict) directly via a separate code
	// path and do NOT route through this service.
	complexityEnabled := true
	if opts.PasswordComplexityEnabled != nil {
		complexityEnabled = *opts.PasswordComplexityEnabled
	}
	minLen := opts.MinPasswordLength
	if minLen <= 0 {
		minLen = 8
	}
	if err := domain.ValidatePasswordPolicy(opts.Password, minLen, complexityEnabled); err != nil {
		return nil, err
	}
	hash, err := s.repo.HashPassword(opts.Password)
	if err != nil {
		return nil, fmt.Errorf("password hashing failed")
	}
	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, fmt.Errorf("user uuid generation failed: %w", err)
	}
	now := time.Now().UTC()
	user := &domain.User{
		ID:             id,
		OrganizationID: opts.OrganizationID,
		Email:          opts.Email,
		PasswordHash:   hash,
		Role:           opts.Role,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  false,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if opts.Name != "" {
		n := opts.Name
		user.Name = &n
	}
	if err := user.Validate(); err != nil {
		return nil, err
	}
	created, err := s.repo.Create(ctx, user)
	if err != nil {
		return nil, err
	}
	return created, nil
}

// ResetMFA clears the target user's MFA enrollment. It sets
// mfa_enabled=false, mfa_secret="", and mfa_recovery_codes=[]. No
// other field on the row is touched (password hash, role, org,
// email, banned/email-verified state, activation/verification tokens
// are all preserved). Idempotent: resetting a user that does not
// have MFA enabled still returns the updated row.
//
// orgID is forwarded to the repository so any future per-org scoping
// at the SQL layer continues to work; the handler resolves it via a
// GetByID lookup before calling.
func (s *UserService) ResetMFA(ctx context.Context, id, orgID uuid.UUID) (*domain.User, error) {
	mfaDisabled := false
	mfaSecretCleared := ""
	updated, err := s.repo.Update(ctx, id, orgID, repository.UpdateUserOptions{
		MFAEnabled:       &mfaDisabled,
		MFASecret:        &mfaSecretCleared,
		MFARecoveryCodes: []string{},
	})
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, errUserNotFound
	}
	return updated, nil
}

// ResetMFAForActor wraps ResetMFA with the same authority matrix
// UpdateUserForActor uses, so site_admin can reset MFA across
// tenants while org_admin is restricted to their own organization
// and may NOT reset MFA on site_admin / cross-org targets. Any
// other actor role is forbidden.
//
// On a forbidden combination the method returns domain.ErrForbidden
// so the handler can map to 403 without distinguishing
// "wrong org" from "not found" (cross-org probe defence). The
// handler treats domain.ErrUnauthorized as 401 and
// errUserNotFound as 404, mirroring HandleGetUser / HandleUpdateUser.
func (s *UserService) ResetMFAForActor(ctx context.Context, actor *domain.Principal, targetUserID uuid.UUID) (*domain.User, error) {
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, err
	}
	target, err := s.repo.GetByID(ctx, targetUserID)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, errUserNotFound
	}
	switch {
	case actor.IsSiteAdmin():
		// site_admin unrestricted — matches existing reset-mfa shape.
	case actor.IsOrgAdminOnly():
		// G10 — NOT FOUND, NOT FORBIDDEN. 403 says "that user EXISTS and you
		// may not touch it"; 404 says "no such user, as far as you are
		// concerned". An org_admin who can tell those apart can enumerate
		// every other tenant's user ids with their own legitimate
		// credentials, one probe at a time. GetUserForActor already
		// answers errUserNotFound here; these routes now agree with it.
		if actor.OrganizationID == uuid.Nil || target.OrganizationID != actor.OrganizationID {
			return nil, errUserNotFound
		}
		if target.Role == domain.RoleSiteAdmin {
			return nil, errUserNotFound
		}
	default:
		return nil, domain.ErrForbidden
	}
	return s.ResetMFA(ctx, target.ID, target.OrganizationID)
}

// Update mutates a user scoped to orgID. Password, when supplied,
// is hashed before persistence.
func (s *UserService) Update(ctx context.Context, id, orgID uuid.UUID, opts UpdateUserOptions) (*domain.User, error) {
	repoOpts := repository.UpdateUserOptions{
		Email:         opts.Email,
		Name:          opts.Name,
		Role:          opts.Role,
		Banned:        opts.Banned,
		EmailVerified: opts.EmailVerified,
	}
	if opts.Password != nil && *opts.Password != "" {
		// Per-org PasswordComplexityEnabled enforcement (Decision D-015
		// §9). Mirrors UserService.Create — nil ⇒ strict mode.
		complexityEnabled := true
		if opts.PasswordComplexityEnabled != nil {
			complexityEnabled = *opts.PasswordComplexityEnabled
		}
		minLen := opts.MinPasswordLength
		if minLen <= 0 {
			minLen = 8
		}
		if err := domain.ValidatePasswordPolicy(*opts.Password, minLen, complexityEnabled); err != nil {
			return nil, err
		}
		hash, err := s.repo.HashPassword(*opts.Password)
		if err != nil {
			return nil, fmt.Errorf("password hashing failed")
		}
		repoOpts.Password = &hash
	}
	updated, err := s.repo.Update(ctx, id, orgID, repoOpts)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, errUserNotFound
	}
	return updated, nil
}

// Delete soft-deletes a user scoped to orgID.
func (s *UserService) Delete(ctx context.Context, id, orgID uuid.UUID) error {
	// AdminPermissionsModel.md: "site_admin CANNOT be deleted and there can
	// only be site_admin user." This answered 200. Ordinary users — org_admins
	// included — stay deletable: the model's lost-all-org_admins clause
	// depends on that.
	if id.String() == domain.SiteAdminID {
		return domain.ErrForbidden
	}
	return s.repo.Delete(ctx, id, orgID)
}

// Restore un-deletes a user scoped to orgID.
func (s *UserService) Restore(ctx context.Context, id, orgID uuid.UUID) error {
	return s.repo.Undelete(ctx, id, orgID)
}

// GetByID returns a user by id.
func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	u, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, errUserNotFound
	}
	return u, nil
}

// List returns users with paging + filtering.
func (s *UserService) List(ctx context.Context, opts repository.ListUserOptions) ([]*domain.User, int, error) {
	return s.repo.List(ctx, opts)
}

// ListByOrganization returns users for a single organization.
func (s *UserService) ListByOrganization(ctx context.Context, orgID uuid.UUID, opts repository.ListUserOptions) ([]*domain.User, int, error) {
	return s.repo.ListByOrganization(ctx, orgID, opts)
}

// ============================================================
// Tenant-scoped (ForActor) variants.
//
// These methods enforce the Identuum admin authority model at the
// service layer so cross-org access is blocked even if a future
// caller forgets the HTTP guard. Behavior:
//
//   - actor == nil OR actor.Role == "" → domain.ErrUnauthorized
//   - actor.Role == site_admin         → unrestricted (existing semantics)
//   - actor.Role == org_admin          → restricted to own org;
//                                         cannot manage site_admin users;
//                                         cannot create/move users across orgs;
//                                         cannot promote to site_admin
//   - any other role                   → domain.ErrForbidden
//
// On an authorization failure the methods return
// domain.ErrForbidden so the handler can map to 403; the target
// row's existence is not revealed for cross-org probes when easy
// to avoid (404 is also acceptable per the brief — we document the
// chosen shape per method).
// ============================================================

// GetUserForActor returns the target user only when actor is
// allowed to read it. org_admin reads are restricted to their own
// org. The method does NOT distinguish "wrong org" from "not
// found" — both return domain.ErrForbidden — so a cross-org probe
// cannot enumerate.
func (s *UserService) GetUserForActor(ctx context.Context, actor *domain.Principal, targetUserID uuid.UUID) (*domain.User, error) {
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, err
	}
	u, err := s.repo.GetByID(ctx, targetUserID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, errUserNotFound
	}
	if actor.IsSiteAdmin() {
		return u, nil
	}
	// Only org_admin reaches the same-org check. Any other role
	// (org_user, unknown) is rejected outright.
	if !actor.IsOrgAdminOnly() {
		return nil, domain.ErrForbidden
	}
	// org_admin: must be same org. A target OUTSIDE the actor's visibility —
	// another organization, or the site_admin — is NOT FOUND, not forbidden.
	// AdminPermissionsModel.md says an org_admin "cannot read or modify
	// site_admin accounts", and 403 answers a question 404 refuses to: it
	// confirms the row exists, turning the admin API into a cross-tenant
	// existence oracle. The status is the difference between "you may not
	// have this" and saying nothing at all.
	if u.Role == domain.RoleSiteAdmin || u.OrganizationID != actor.OrganizationID {
		return nil, errUserNotFound
	}
	return u, nil
}

// ListUsersForActor returns the user list scoped to the actor.
// site_admin gets every row matching opts; org_admin gets only
// users whose organization_id matches their own. opts.Filter.Role
// is honored for both actors. org_user is forbidden.
func (s *UserService) ListUsersForActor(ctx context.Context, actor *domain.Principal, opts repository.ListUserOptions) ([]*domain.User, int, error) {
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, 0, err
	}
	if actor.IsSiteAdmin() {
		return s.repo.List(ctx, opts)
	}
	if !actor.IsOrgAdminOnly() {
		return nil, 0, domain.ErrForbidden
	}
	if actor.OrganizationID == uuid.Nil {
		return nil, 0, domain.ErrForbidden
	}
	return s.repo.ListByOrganization(ctx, actor.OrganizationID, opts)
}

// CreateUserForActor wraps Create with the create-side authority
// rules. org_admin actors:
//
//   - target org is FORCED to actor.OrganizationID; any opts value
//     other than uuid.Nil that disagrees is rejected with
//     ErrForbidden to surface client confusion early
//   - cannot create site_admin
//
// site_admin actors must supply opts.OrganizationID explicitly so
// the System Org is never accidentally chosen.
func (s *UserService) CreateUserForActor(ctx context.Context, actor *domain.Principal, opts CreateUserOptions) (*domain.User, error) {
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, err
	}
	switch {
	case actor.IsSiteAdmin():
		if opts.OrganizationID == uuid.Nil {
			return nil, fmt.Errorf("organization id is required for site_admin create")
		}
		// SITE-ADMIN-TENANT-WRITE (owner ruling: THE MODEL WINS). site_admin is
		// INFRASTRUCTURE authority, not a tenant super-admin. The authority
		// model permits exactly one tenant write — seeding an organization's
		// FIRST org_admin — and this permitted every role in every org.
		//
		// Narrowest reading of the model text:
		//   "delegate/create an org_admin only when the target organization has
		//    zero active org_admin users"
		//   "cannot create regular org_user accounts in tenant organizations"
		//   "cannot create extra org_admin accounts if the organization already
		//    has at least one active org_admin"
		// → the exception covers org_admin ONLY, and closes the moment a live
		// org_admin exists. Recovery (an org that LOST its last admin) is the
		// same predicate, so it keeps working without a separate path.
		//
		// The system organization is exempt: it is infrastructure, not a
		// tenant, and bootstrap / recover-site-admin write into it.
		if err := s.guardSiteAdminTenantWrite(ctx, opts); err != nil {
			return nil, err
		}
	case actor.IsOrgAdminOnly():
		if actor.OrganizationID == uuid.Nil {
			return nil, domain.ErrForbidden
		}
		if opts.OrganizationID != uuid.Nil && opts.OrganizationID != actor.OrganizationID {
			return nil, domain.ErrForbidden
		}
		opts.OrganizationID = actor.OrganizationID
		if opts.Role == domain.RoleSiteAdmin {
			return nil, domain.ErrForbidden
		}
	default:
		return nil, domain.ErrForbidden
	}
	return s.Create(ctx, opts)
}

// guardSiteAdminTenantWrite enforces the authority model's limit on what
// site_admin may write INTO a tenant organization. See CreateUserForActor.
func (s *UserService) guardSiteAdminTenantWrite(ctx context.Context, opts CreateUserOptions) error {
	if opts.OrganizationID.String() == domain.SystemOrgID {
		return nil // infrastructure, not a tenant
	}
	if opts.Role != domain.RoleOrgAdmin {
		// org_user (and anything else) inside a tenant is the tenant's own
		// business — an org_admin creates those.
		return domain.ErrForbidden
	}
	if s.repo == nil {
		// Fail closed: without a repository the "zero active org_admins"
		// predicate cannot be evaluated, and an unevaluated predicate must
		// not read as permission.
		return domain.ErrForbidden
	}
	existing, err := s.repo.CountOrgAdminsByOrganization(ctx, opts.OrganizationID)
	if err != nil {
		return domain.ErrForbidden
	}
	if existing > 0 {
		return domain.ErrForbidden
	}
	return nil
}

// UpdateUserForActor wraps Update with same-org authority. org_admin:
//
//   - target user must already live in actor.OrganizationID
//   - target user must not be a site_admin
//   - opts cannot promote target to site_admin
//   - opts.Email and opts.Name may change; password is hashed in
//     UserService.Update; banned/email-verified toggles are allowed
//
// site_admin actors are unrestricted.
func (s *UserService) UpdateUserForActor(ctx context.Context, actor *domain.Principal, targetUserID uuid.UUID, opts UpdateUserOptions) (*domain.User, error) {
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, err
	}
	target, err := s.repo.GetByID(ctx, targetUserID)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, errUserNotFound
	}
	var scopedOrgID uuid.UUID
	switch {
	case actor.IsSiteAdmin():
		scopedOrgID = target.OrganizationID
	case actor.IsOrgAdminOnly():
		// Outside the actor's visibility → NOT FOUND, matching the read path.
		// A 403 confirms the row exists across a tenant boundary; 404 says
		// nothing. Promotion to site_admin below stays 403 — that refusal is
		// about the REQUEST, not about a row the caller cannot see.
		if actor.OrganizationID == uuid.Nil || target.OrganizationID != actor.OrganizationID {
			return nil, errUserNotFound
		}
		if target.Role == domain.RoleSiteAdmin {
			return nil, errUserNotFound
		}
		if opts.Role != nil && *opts.Role == domain.RoleSiteAdmin {
			return nil, domain.ErrForbidden
		}
		scopedOrgID = actor.OrganizationID
	default:
		return nil, domain.ErrForbidden
	}
	return s.Update(ctx, targetUserID, scopedOrgID, opts)
}

// ApproveRegistrationForActor approves a pending self-registered user by
// clearing the public_registration hold: it sets banned=false so the
// login path (which rejects banned users) accepts the account. The user
// stays an org_user.
//
// This is specifically the registration-hold clear, NOT a general
// un-ban. Preconditions (fail-closed):
//
//   - actor authority mirrors UpdateUserForActor: a site_admin may
//     approve any target; an org_admin may approve only a same-org,
//     non-site_admin target; anyone else is ErrForbidden.
//   - the target MUST be in the pending state — role == org_user AND
//     banned == true. Any other state (already-active org_user, an
//     org_admin, a site_admin) returns ErrUserNotPendingApproval so an
//     approval can never silently succeed as a back-door un-ban.
//
// A missing target returns the not-found sentinel. No IDs are generated
// (the user already exists), so no UUIDv7 mint occurs on this path.
func (s *UserService) ApproveRegistrationForActor(ctx context.Context, actor *domain.Principal, targetUserID uuid.UUID) (*domain.User, error) {
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, err
	}
	target, err := s.repo.GetByID(ctx, targetUserID)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, errUserNotFound
	}
	var scopedOrgID uuid.UUID
	switch {
	case actor.IsSiteAdmin():
		scopedOrgID = target.OrganizationID
	case actor.IsOrgAdminOnly():
		// G10 — NOT FOUND, NOT FORBIDDEN. 403 says "that user EXISTS and you
		// may not touch it"; 404 says "no such user, as far as you are
		// concerned". An org_admin who can tell those apart can enumerate
		// every other tenant's user ids with their own legitimate
		// credentials, one probe at a time. GetUserForActor already
		// answers errUserNotFound here; these routes now agree with it.
		if actor.OrganizationID == uuid.Nil || target.OrganizationID != actor.OrganizationID {
			return nil, errUserNotFound
		}
		if target.Role == domain.RoleSiteAdmin {
			return nil, errUserNotFound
		}
		scopedOrgID = actor.OrganizationID
	default:
		return nil, domain.ErrForbidden
	}
	// Pending-registration guard: only a held self-registrant may be
	// approved. Require the exact pending shape (org_user + banned) so
	// approval cannot be used as a general un-ban of an admin or of an
	// already-active user.
	if target.Role != domain.RoleOrgUser || !target.Banned {
		return nil, errUserNotPendingApproval
	}
	notBanned := false
	return s.Update(ctx, target.ID, scopedOrgID, UpdateUserOptions{Banned: &notBanned})
}

// DeleteUserForActor enforces same-org authority and forbids
// org_admin from deleting site_admin or other-org users.
func (s *UserService) DeleteUserForActor(ctx context.Context, actor *domain.Principal, targetUserID uuid.UUID) error {
	if err := s.guardActorBaseline(actor); err != nil {
		return err
	}
	target, err := s.repo.GetByID(ctx, targetUserID)
	if err != nil {
		return err
	}
	if target == nil {
		return errUserNotFound
	}
	// AdminPermissionsModel.md: "site_admin CANNOT be deleted." This path
	// reached s.repo.Delete DIRECTLY, so the guard on UserService.Delete never
	// saw it, and the comment below promised "last-site-admin invariants are
	// enforced by higher-tier code" — there was no such code. Measured live:
	// DELETE the sentinel id → HTTP 200, and the caller's own session died
	// with it. The check is FIRST so it holds for every actor.
	if targetUserID.String() == domain.SiteAdminID || target.Role == domain.RoleSiteAdmin {
		return domain.ErrForbidden
	}
	switch {
	case actor.IsSiteAdmin():
		// site_admin may delete any ordinary user. org_admins included — the
		// model's lost-all-org_admins clause depends on that.
	case actor.IsOrgAdminOnly():
		// Outside the actor's visibility → NOT FOUND, matching the read and
		// update paths: a 403 confirms the row exists across a tenant boundary.
		if actor.OrganizationID == uuid.Nil || target.OrganizationID != actor.OrganizationID {
			return errUserNotFound
		}
	default:
		return domain.ErrForbidden
	}
	return s.repo.Delete(ctx, targetUserID, target.OrganizationID)
}

// RestoreUserForActor mirrors DeleteUserForActor.
func (s *UserService) RestoreUserForActor(ctx context.Context, actor *domain.Principal, targetUserID uuid.UUID) error {
	if err := s.guardActorBaseline(actor); err != nil {
		return err
	}
	target, err := s.repo.GetByID(ctx, targetUserID)
	if err != nil {
		return err
	}
	if target == nil {
		return errUserNotFound
	}
	switch {
	case actor.IsSiteAdmin():
	case actor.IsOrgAdminOnly():
		// G10 — NOT FOUND, NOT FORBIDDEN. See the note on ResetMFAForActor:
		// 403 confirms the id exists in another tenant, which turns an
		// org_admin's own credentials into an enumeration oracle.
		if actor.OrganizationID == uuid.Nil || target.OrganizationID != actor.OrganizationID {
			return errUserNotFound
		}
		if target.Role == domain.RoleSiteAdmin {
			return errUserNotFound
		}
	default:
		return domain.ErrForbidden
	}
	return s.repo.Undelete(ctx, targetUserID, target.OrganizationID)
}

func (s *UserService) guardActorBaseline(actor *domain.Principal) error {
	if actor == nil || actor.Role == "" {
		return domain.ErrUnauthorized
	}
	return nil
}

// ensure error sentinels remain referenced from external packages.
var _ = errors.New
