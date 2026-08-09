package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// OrgRoleService is the OSS-narrow service for org-defined RBAC
// roles. It enforces tenant authority at the service layer so a
// cross-tenant probe is blocked even if a future HTTP layer
// forgets to mount the same-org guard.
//
// Authority model:
//
//   - site_admin can act across tenants.
//   - org_admin can act only inside actor.OrganizationID.
//   - org_admin cannot operate against the System Org.
//   - org_user / unknown roles are forbidden.
//
// Out of scope for this slice:
//
//   - synchronous session revocation on privilege demotion
//     (monolith §2.8). The OSS service deletes/updates the
//     role row but does NOT invalidate active sessions. CE
//     composition can wrap each mutation with a session-revoke
//     hook.
//   - cross-feature cascades (anomaly, audit ledger, etc.).
//   - billing / tier-limit checks (handled by features.FeatureGate).
type OrgRoleService struct {
	repo            repository.OrgRoleRepository
	apiResourceRepo repository.APIResourceRepository
	userRepo        repository.UserRepository
	revoker         SessionRevoker
}

// NewOrgRoleService constructs an OrgRoleService. repo is
// required; apiResourceRepo is required only for AddScopeForActor
// because the AddScope SQL needs an api-resource id. The
// SessionRevoker defaults to NoopSessionRevoker; CE composition
// supplies a real implementation via WithSessionRevoker. The
// UserRepository is optional at construction time but is required
// at runtime by AssignRoleToUserForActor — install it via
// WithUserRepository. When absent, AssignRoleToUserForActor fails
// closed with ErrUserRepositoryUnavailable so a misconfigured
// deployment cannot silently skip target-user tenant validation.
func NewOrgRoleService(report *lifecycle.StartupReport, repo repository.OrgRoleRepository, apiResourceRepo repository.APIResourceRepository) *OrgRoleService {
	if repo == nil {
		report.Fatal("NewOrgRoleService", "service: NewOrgRoleService requires a non-nil OrgRoleRepository")
	}
	return &OrgRoleService{repo: repo, apiResourceRepo: apiResourceRepo, revoker: NoopSessionRevoker{}}
}

// WithSessionRevoker installs the supplied revoker. nil is
// replaced with NoopSessionRevoker so callers cannot accidentally
// turn off revocation by passing nil. Returns the service so
// callers can chain on the constructor:
//
//	svc := service.NewOrgRoleService(repos.OrgRole, repos.APIResource).
//	    WithSessionRevoker(ce.NewSessionRevoker(...))
func (s *OrgRoleService) WithSessionRevoker(r SessionRevoker) *OrgRoleService {
	if r == nil {
		r = NoopSessionRevoker{}
	}
	s.revoker = r
	return s
}

// WithUserRepository installs the user repository consumed by
// AssignRoleToUserForActor for target-user tenant validation.
// nil is a programmer error — accidentally passing nil here would
// disable the safety net the option exists to provide, so the
// option panics on nil rather than silently no-op'ing. Returns
// the service so callers can chain:
//
//	svc := service.NewOrgRoleService(repos.OrgRole, repos.APIResource).
//	    WithUserRepository(repos.User).
//	    WithSessionRevoker(ce.NewSessionRevoker(...))
func (s *OrgRoleService) WithUserRepository(repo repository.UserRepository) *OrgRoleService {
	if repo == nil {
		// P-018: a nil repo here is a wiring error. Do not panic — leave
		// the target-user validation hook unset so AssignRoleToUserForActor
		// fails closed (rejects) rather than crashing the process.
		return s
	}
	s.userRepo = repo
	return s
}

// CreateRoleForActor creates a new role inside orgID. org_admin
// actors are forced to act inside their own organization; site_admin
// may target any org explicitly.
func (s *OrgRoleService) CreateRoleForActor(ctx context.Context, actor *domain.Principal, orgID uuid.UUID, name, description string) (*domain.OrgRole, error) {
	if err := s.guardActorTenant(actor, orgID); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("role name is required")
	}
	role := &domain.OrgRole{
		OrgID:       orgID,
		Name:        name,
		Description: strings.TrimSpace(description),
	}
	if err := s.repo.Create(ctx, role); err != nil {
		return nil, err
	}
	return role, nil
}

// ListRolesForActor returns all roles in orgID.
func (s *OrgRoleService) ListRolesForActor(ctx context.Context, actor *domain.Principal, orgID uuid.UUID) ([]*domain.OrgRole, error) {
	if err := s.guardActorTenant(actor, orgID); err != nil {
		return nil, err
	}
	return s.repo.ListByOrg(ctx, orgID)
}

// GetRoleForActor returns the role only when the actor is allowed.
// Cross-tenant and unknown-id both return ErrForbidden so a probe
// cannot enumerate.
func (s *OrgRoleService) GetRoleForActor(ctx context.Context, actor *domain.Principal, roleID uuid.UUID) (*domain.OrgRole, error) {
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, err
	}
	role, err := s.repo.GetByID(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, errOrgRoleNotFound
	}
	if !actor.IsSiteAdmin() {
		if !actor.IsOrgAdminOnly() || role.OrgID != actor.OrganizationID {
			return nil, domain.ErrForbidden
		}
	}
	return role, nil
}

// UpdateRoleForActor updates name + description for a role in the
// actor's tenant. site_admin may act across tenants.
func (s *OrgRoleService) UpdateRoleForActor(ctx context.Context, actor *domain.Principal, roleID uuid.UUID, name, description string) (*domain.OrgRole, error) {
	role, err := s.GetRoleForActor(ctx, actor, roleID)
	if err != nil {
		return nil, err
	}
	if n := strings.TrimSpace(name); n != "" {
		role.Name = n
	}
	if d := strings.TrimSpace(description); d != "" {
		role.Description = d
	}
	if err := s.repo.Update(ctx, role); err != nil {
		return nil, err
	}
	return role, nil
}

// DeleteRoleForActor removes a role from the actor's tenant. Fires
// the SessionRevoker for every user who currently holds the role
// so a CE-side session store can invalidate stale scopes. Per the
// monolith §2.8 policy, both the user-id enumeration and the
// revoker calls are best-effort: an enumeration error proceeds
// with an empty list (stale scopes expire at token TTL) and a
// revoker error is swallowed (the mutation always succeeds).
func (s *OrgRoleService) DeleteRoleForActor(ctx context.Context, actor *domain.Principal, roleID uuid.UUID) error {
	role, err := s.GetRoleForActor(ctx, actor, roleID)
	if err != nil {
		return err
	}
	// Capture affected user IDs BEFORE the delete so we are not
	// racing the DB cascade on user_roles.
	affected, listErr := s.repo.ListUserIDsForRole(ctx, roleID)
	if listErr != nil {
		affected = nil
	}
	if err := s.repo.Delete(ctx, roleID); err != nil {
		return err
	}
	s.fanOutRevoke(ctx, affected, "rbac_role_deleted", map[string]any{
		"role_id":         roleID,
		"organization_id": role.OrgID,
	})
	return nil
}

// AddScopeForActor links scopeName (under resourceID's api-resource)
// to roleID. resourceID's organization is checked against the
// actor's tenant.
func (s *OrgRoleService) AddScopeForActor(ctx context.Context, actor *domain.Principal, roleID uuid.UUID, resourceID uuid.UUID, scopeName string) error {
	role, err := s.GetRoleForActor(ctx, actor, roleID)
	if err != nil {
		return err
	}
	if s.apiResourceRepo == nil {
		return errOrgRoleAPIResourceRepoMissing
	}
	res, err := s.apiResourceRepo.GetByID(ctx, resourceID, nil)
	if err != nil {
		return err
	}
	if res == nil {
		return domain.ErrForbidden
	}
	// Resource and role must share an org. site_admin may bypass.
	if !actor.IsSiteAdmin() && res.OrganizationID != role.OrgID {
		return domain.ErrForbidden
	}
	if strings.TrimSpace(scopeName) == "" {
		return fmt.Errorf("scope name is required")
	}
	return s.repo.AddScope(ctx, roleID, resourceID, scopeName)
}

// RemoveScopeForActor removes scopeName from roleID. Fires the
// SessionRevoker for every role-holder so a CE session store can
// invalidate scope caches. Revocation policy mirrors DeleteRole:
// best-effort, non-fatal.
func (s *OrgRoleService) RemoveScopeForActor(ctx context.Context, actor *domain.Principal, roleID uuid.UUID, scopeName string) error {
	role, err := s.GetRoleForActor(ctx, actor, roleID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(scopeName) == "" {
		return fmt.Errorf("scope name is required")
	}
	if err := s.repo.RemoveScope(ctx, roleID, scopeName); err != nil {
		return err
	}
	affected, listErr := s.repo.ListUserIDsForRole(ctx, roleID)
	if listErr != nil {
		affected = nil
	}
	s.fanOutRevoke(ctx, affected, "rbac_role_scope_removed", map[string]any{
		"role_id":         roleID,
		"organization_id": role.OrgID,
		"scope_name":      scopeName,
	})
	return nil
}

// AssignRoleToUserForActor binds roleID to userID. Authorization
// is layered:
//
//  1. Actor authorization: the actor must share the role's tenant
//     (site_admin can cross tenants; org_admin only inside their
//     own org). Enforced by GetRoleForActor.
//  2. UserRepository availability: the service must have a
//     UserRepository wired (via WithUserRepository) so target-user
//     tenant validation can run. Missing repo → fail-closed with
//     ErrUserRepositoryUnavailable. A deployment that skips this
//     wiring is misconfigured, not "allowed to bypass safety".
//  3. Target-user tenant validation: the assigned user MUST exist
//     AND MUST belong to role.OrgID. Cross-tenant or missing target
//     is rejected with domain.ErrForbidden indistinguishably so a
//     direct service caller cannot probe for cross-org user
//     existence.
//  4. Target-user role guard: org_admin actors cannot assign a role
//     TO a site_admin user. site_admin actors may. This matches the
//     OSS UserService.UpdateUserForActor / DeleteUserForActor
//     pattern — org_admins do not touch site_admin records.
//
// On successful assignment, fires the SessionRevoker for the
// assigned user with reason "rbac_role_assigned" (matches
// monolith) and safe metadata {role_id, organization_id}. The
// revoker error is swallowed per the existing warn-and-continue
// policy from the prior slice.
//
// Revocation never fires on a forbidden / cross-org / missing-user
// failure — the fan-out is gated on the assignment having
// persisted. A failed assignment is a non-event for session state.
func (s *OrgRoleService) AssignRoleToUserForActor(ctx context.Context, actor *domain.Principal, userID, roleID uuid.UUID) error {
	role, err := s.GetRoleForActor(ctx, actor, roleID)
	if err != nil {
		return err
	}
	if s.userRepo == nil {
		return ErrUserRepositoryUnavailable
	}
	target, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if target == nil {
		return domain.ErrForbidden
	}
	if target.OrganizationID != role.OrgID {
		return domain.ErrForbidden
	}
	// org_admin actors are not allowed to attach roles TO a
	// site_admin user, even when the org column technically matches.
	// site_admin actors may.
	if actor.IsOrgAdminOnly() && target.Role == domain.RoleSiteAdmin {
		return domain.ErrForbidden
	}
	if err := s.repo.AssignRoleToUser(ctx, userID, roleID, actor.UserID); err != nil {
		return err
	}
	s.fanOutRevoke(ctx, []uuid.UUID{userID}, "rbac_role_assigned", map[string]any{
		"role_id":         roleID,
		"organization_id": role.OrgID,
	})
	return nil
}

// RemoveRoleFromUserForActor unbinds roleID from userID. Fires the
// SessionRevoker for the target user only (not for other role
// holders). Best-effort, non-fatal.
func (s *OrgRoleService) RemoveRoleFromUserForActor(ctx context.Context, actor *domain.Principal, userID, roleID uuid.UUID) error {
	role, err := s.GetRoleForActor(ctx, actor, roleID)
	if err != nil {
		return err
	}
	if err := s.repo.RemoveRoleFromUser(ctx, userID, roleID); err != nil {
		return err
	}
	s.fanOutRevoke(ctx, []uuid.UUID{userID}, "rbac_role_unassigned", map[string]any{
		"role_id":         roleID,
		"organization_id": role.OrgID,
	})
	return nil
}

// ListRolesForUserForActor returns roles bound to userID. Tenant
// scoping is enforced by filtering: org_admin sees only same-tenant
// roles.
func (s *OrgRoleService) ListRolesForUserForActor(ctx context.Context, actor *domain.Principal, userID uuid.UUID) ([]*domain.OrgRole, error) {
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, err
	}
	roles, err := s.repo.ListRolesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if actor.IsSiteAdmin() {
		return roles, nil
	}
	if !actor.IsOrgAdminOnly() {
		return nil, domain.ErrForbidden
	}
	out := make([]*domain.OrgRole, 0, len(roles))
	for _, r := range roles {
		if r.OrgID == actor.OrganizationID {
			out = append(out, r)
		}
	}
	return out, nil
}

// ListMyRoles returns the caller's own role assignments.
func (s *OrgRoleService) ListMyRoles(ctx context.Context, actor *domain.Principal) ([]*domain.OrgRole, error) {
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, err
	}
	if actor.UserID == uuid.Nil {
		return nil, domain.ErrForbidden
	}
	return s.repo.ListRolesForUser(ctx, actor.UserID)
}

func (s *OrgRoleService) guardActorBaseline(actor *domain.Principal) error {
	if actor == nil || actor.Role == "" {
		return domain.ErrUnauthorized
	}
	return nil
}

// guardActorTenant enforces both baseline auth and the tenant
// boundary. For site_admin, any org is allowed. For org_admin, the
// target orgID must match actor.OrganizationID and be non-Nil.
func (s *OrgRoleService) guardActorTenant(actor *domain.Principal, orgID uuid.UUID) error {
	if err := s.guardActorBaseline(actor); err != nil {
		return err
	}
	if orgID == uuid.Nil {
		return fmt.Errorf("organization id is required")
	}
	if actor.IsSiteAdmin() {
		return nil
	}
	if !actor.IsOrgAdminOnly() {
		return domain.ErrForbidden
	}
	if actor.OrganizationID == uuid.Nil || actor.OrganizationID != orgID {
		return domain.ErrForbidden
	}
	return nil
}

// fanOutRevoke fires the SessionRevoker for every uid. Errors are
// swallowed per the documented warn-and-continue policy (the
// mutation has already succeeded; revoker failures are best-effort
// and the worst case is stale scopes that expire at token TTL).
// nil revoker is treated as NoopSessionRevoker.
func (s *OrgRoleService) fanOutRevoke(ctx context.Context, userIDs []uuid.UUID, reason string, metadata map[string]any) {
	revoker := s.revoker
	if revoker == nil {
		revoker = NoopSessionRevoker{}
	}
	for _, uid := range userIDs {
		_ = revoker.RevokeUserSessions(ctx, uid, reason, metadata)
	}
}

// GetScopesForUserForActor returns the deduplicated union of scope
// names bound to targetUserID's roles. Authority:
//
//   - site_admin can query any user.
//   - org_admin can query users in their own org only. Tenant check
//     uses ListRolesForUser → first role's OrgID (org_admin can't
//     enumerate cross-tenant scopes; an empty result for an
//     unreachable user looks identical to a no-roles user, which
//     is the intended privacy posture).
//   - any authenticated principal can query their own UserID
//     (self-lookup so a future token-introspection path can map
//     a bearer to its current scopes).
//   - anyone else: ErrForbidden.
//
// The OSS service does NOT mount an HTTP route on this method —
// the monolith exposes no equivalent. The method exists as a
// hook seam for a future token-issuance / introspection path.
func (s *OrgRoleService) GetScopesForUserForActor(ctx context.Context, actor *domain.Principal, targetUserID uuid.UUID) ([]string, error) {
	if err := s.guardActorBaseline(actor); err != nil {
		return nil, err
	}
	// Self-lookup is always allowed for authenticated principals.
	if actor.UserID != uuid.Nil && targetUserID == actor.UserID {
		return s.repo.GetScopesForUser(ctx, targetUserID, nil)
	}
	if actor.IsSiteAdmin() {
		return s.repo.GetScopesForUser(ctx, targetUserID, nil)
	}
	if !actor.IsOrgAdminOnly() {
		return nil, domain.ErrForbidden
	}
	if actor.OrganizationID == uuid.Nil {
		return nil, domain.ErrForbidden
	}
	// Tenant probe: use the target's role bindings to confirm same
	// org. If the target has no roles at all, ListRolesForUser
	// returns an empty list — treat as "no observable cross-tenant
	// state" and return an empty scope list (NOT an enumeration
	// signal).
	roles, err := s.repo.ListRolesForUser(ctx, targetUserID)
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return []string{}, nil
	}
	for _, r := range roles {
		if r.OrgID != actor.OrganizationID {
			return nil, domain.ErrForbidden
		}
	}
	return s.repo.GetScopesForUser(ctx, targetUserID, nil)
}

var (
	errOrgRoleNotFound               = errors.New("service: org role not found")
	errOrgRoleAPIResourceRepoMissing = errors.New("service: AddScope requires an APIResourceRepository")

	// ErrUserRepositoryUnavailable is returned by
	// AssignRoleToUserForActor when no UserRepository has been
	// installed via WithUserRepository. This is a deliberate
	// fail-closed signal — a service that cannot validate target-
	// user tenant membership MUST NOT proceed with the assignment.
	ErrUserRepositoryUnavailable = errors.New("service: OrgRoleService requires a UserRepository (install via WithUserRepository)")
)

// ErrOrgRoleNotFound exposes the OSS not-found sentinel.
func ErrOrgRoleNotFound() error { return errOrgRoleNotFound }
