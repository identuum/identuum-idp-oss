package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// Admin-path methods on ServiceAccountService. These mirror the
// monolith's create / list / read / update / enable / disable /
// delete surface but scope every method through actor RBAC:
//
//   - site_admin may act across organizations.
//   - org_admin may act only within actor.OrganizationID.
//   - any other role is forbidden.
//
// The methods deliberately do NOT issue or return service-account
// secrets — credential issuance for service accounts is out of
// scope for this slice and would require additional OSS surfaces
// (a separate oauth_clients link path). Operators still bind an
// existing OAuth client to a service account via the clients
// admin handler.

// ServiceAccountAdminInput drives Create and Update. Fields the
// caller wants to leave unchanged on Update should be left zero —
// the service applies update semantics where Name/Description
// non-empty overwrite, Role non-empty overwrites, ExpiresAt
// non-nil overwrites.
type ServiceAccountAdminInput struct {
	Name        string
	Description string
	Role        domain.UserRole
	ExpiresAt   *time.Time
}

// Sentinel errors. Wire-layer mappings:
//
//   - ErrSAForbidden     → 403
//   - ErrSAInvalidInput  → 400
//   - ErrSANotFound      → 404
//   - ErrSARoleInvalid   → 400
//   - ErrSAExpiryInvalid → 400
var (
	ErrSAForbidden     = errors.New("service: service-account action forbidden for actor")
	ErrSAInvalidInput  = errors.New("service: invalid service-account input")
	ErrSANotFound      = errors.New("service: service account not found")
	ErrSARoleInvalid   = errors.New("service: service-account role not allowed")
	ErrSAExpiryInvalid = errors.New("service: service-account expiry must be in the future")
)

// CreateForActor creates a new SA in the supplied organization.
//
//   - site_admin may target any organization.
//   - org_admin may target only their own organization.
//   - Other roles → ErrSAForbidden.
//   - Empty Name → ErrSAInvalidInput.
//   - Role MUST be one of AllowedServiceAccountRoles.
//   - When ExpiresAt is supplied, it MUST be in the future.
//
// The returned ServiceAccount is the persisted row.
func (s *ServiceAccountService) CreateForActor(ctx context.Context, actor *domain.Principal, orgID uuid.UUID, in ServiceAccountAdminInput) (*domain.ServiceAccount, error) {
	sa, err := s.buildForActor(actor, orgID, in)
	if err != nil {
		return nil, err
	}
	return s.repo.Create(ctx, sa)
}

// buildForActor is the PURE prepare step for CreateForActor: it runs the
// actor RBAC gate + name/role/expiry validation and assembles the
// domain.ServiceAccount, performing NO database write. CreateForActor =
// buildForActor + s.repo.Create (standalone behavior identical). The
// bundle service calls buildForActor directly and persists the SA inside
// its atomic SA+client transaction (P2-16b).
func (s *ServiceAccountService) buildForActor(actor *domain.Principal, orgID uuid.UUID, in ServiceAccountAdminInput) (*domain.ServiceAccount, error) {
	if err := s.requireOrgAdmin(actor, orgID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, ErrSAInvalidInput
	}
	role := in.Role
	if role == "" {
		role = domain.RoleOrgUser
	}
	if !domain.IsAllowedSARole(role) {
		return nil, ErrSARoleInvalid
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(s.now()) {
		return nil, ErrSAExpiryInvalid
	}
	now := s.now().UTC()
	sa := &domain.ServiceAccount{
		OrganizationID: orgID,
		Name:           strings.TrimSpace(in.Name),
		Description:    in.Description,
		Role:           role,
		Active:         true,
		ExpiresAt:      in.ExpiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	return sa, nil
}

// ListForActor returns the SAs in orgID. Authorization mirrors
// CreateForActor: site_admin may target any org, org_admin only
// their own.
func (s *ServiceAccountService) ListForActor(ctx context.Context, actor *domain.Principal, orgID uuid.UUID) ([]*domain.ServiceAccount, error) {
	if err := s.requireOrgAdmin(actor, orgID); err != nil {
		return nil, err
	}
	return s.repo.ListByOrganization(ctx, orgID)
}

// GetForActor returns a single SA by ID. Tenant scoping applies:
// org_admin may read only SAs in their own org. site_admin may
// read any SA. Unknown ID → ErrSANotFound.
func (s *ServiceAccountService) GetForActor(ctx context.Context, actor *domain.Principal, saID uuid.UUID) (*domain.ServiceAccount, error) {
	sa, err := s.repo.GetByID(ctx, saID)
	if err != nil {
		return nil, ErrSANotFound
	}
	if sa == nil {
		return nil, ErrSANotFound
	}
	if err := s.requireOrgAdmin(actor, sa.OrganizationID); err != nil {
		return nil, err
	}
	return sa, nil
}

// UpdateForActor mutates Name / Description / Role / ExpiresAt.
// Empty Name / Description / Role are interpreted as "leave
// unchanged". ExpiresAt update is applied verbatim when non-nil.
// ServiceAccountUpdateInput carries a service-account update. THE-SILENT-DROP:
// separate from ServiceAccountAdminInput (which create still uses) because
// an update needs to tell "not supplied" from "supplied blank" and the shared
// plain-string form could not — PUT {"name":"   "} and PUT {"name":""} were
// both MEASURED answering 200 with an unchanged row.
type ServiceAccountUpdateInput struct {
	// Name is REQUIRED when supplied: blank is refused, never ignored.
	Name *string
	// Description is OPTIONAL: a supplied empty value clears it.
	Description *string
	Role        *domain.UserRole
	ExpiresAt   *time.Time
}

func (s *ServiceAccountService) UpdateForActor(ctx context.Context, actor *domain.Principal, saID uuid.UUID, in ServiceAccountUpdateInput) (*domain.ServiceAccount, error) {
	sa, err := s.GetForActor(ctx, actor, saID)
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		// The same rule buildForActor applies at create, on a supplied value.
		n := strings.TrimSpace(*in.Name)
		if n == "" {
			return nil, ErrSAInvalidInput
		}
		sa.Name = n
	}
	if in.Description != nil {
		sa.Description = *in.Description
	}
	if in.Role != nil {
		if !domain.IsAllowedSARole(*in.Role) {
			return nil, ErrSARoleInvalid
		}
		sa.Role = *in.Role
	}
	if in.ExpiresAt != nil {
		if !in.ExpiresAt.After(s.now()) {
			return nil, ErrSAExpiryInvalid
		}
		sa.ExpiresAt = in.ExpiresAt
	}
	sa.UpdatedAt = s.now().UTC()
	return s.repo.Update(ctx, sa)
}

// SetActiveForActor flips the active flag via the dedicated
// repository UpdateActive method so unrelated columns cannot be
// clobbered.
func (s *ServiceAccountService) SetActiveForActor(ctx context.Context, actor *domain.Principal, saID uuid.UUID, active bool) error {
	sa, err := s.GetForActor(ctx, actor, saID)
	if err != nil {
		return err
	}
	if sa.Active == active {
		return nil
	}
	return s.repo.UpdateActive(ctx, sa.ID, sa.OrganizationID, active)
}

// DeleteForActor removes the SA. Authorization mirrors
// GetForActor — site_admin may delete any SA, org_admin only own
// org. The repository's Delete is the load-bearing path; it is
// expected to be a soft-delete (sets deleted_at) per the OSS
// schema's deleted_at column.
func (s *ServiceAccountService) DeleteForActor(ctx context.Context, actor *domain.Principal, saID uuid.UUID) error {
	sa, err := s.GetForActor(ctx, actor, saID)
	if err != nil {
		return err
	}
	return s.repo.Delete(ctx, sa.ID, sa.OrganizationID)
}

// ValidateBindingForClient checks that an SA UUID is suitable to
// bind to an OAuth client at create/update time. The check runs
// the same lifecycle gates as LookupForClient minus the (client.
// ServiceAccountID == supplied SA ID) sanity check.
//
// Used by ClientService.RegisterClient / UpdateClient to fail
// closed at bind time so an operator cannot wire a client to a
// dead / cross-org / expired SA.
//
//   - clientOrgID nil means "system / cross-tenant client" — the
//     SA's own organization governs.
//   - clientOrgID non-nil MUST match SA.OrganizationID.
//
// Returns one of ErrServiceAccountNotFound / ErrServiceAccountInactive
// / ErrServiceAccountExpired / ErrServiceAccountOrgMismatch.
func (s *ServiceAccountService) ValidateBindingForClient(ctx context.Context, saID uuid.UUID, clientOrgID *uuid.UUID) error {
	if saID == uuid.Nil {
		return ErrServiceAccountUnbound
	}
	sa, err := s.repo.GetByID(ctx, saID)
	if err != nil || sa == nil {
		return ErrServiceAccountNotFound
	}
	if !sa.Active {
		return ErrServiceAccountInactive
	}
	if sa.ExpiresAt != nil && !sa.ExpiresAt.After(s.now()) {
		return ErrServiceAccountExpired
	}
	if clientOrgID != nil && *clientOrgID != sa.OrganizationID {
		return ErrServiceAccountOrgMismatch
	}
	return nil
}

// requireOrgAdmin is the shared RBAC chokepoint. site_admin
// passes unconditionally. org_admin passes only when their
// OrganizationID matches the supplied orgID. Any other role is
// forbidden.
func (s *ServiceAccountService) requireOrgAdmin(actor *domain.Principal, orgID uuid.UUID) error {
	if actor == nil {
		return ErrSAForbidden
	}
	// THE-REMAINING-FOUR (2026-08-30): the `if actor.IsSiteAdmin() { return nil }`
	// admission that stood here WAS the defect — service accounts are a
	// tenant's own resource, and AdminPermissionsModel.md forbids site_admin
	// from managing them. site_admin now falls through to ErrSAForbidden (403)
	// like any non-org-admin. org_admin-own (nil), org_admin-cross (ErrSANotFound
	// 404), and every other actor (ErrSAForbidden) are unchanged.
	if actor.IsOrgAdminOnly() {
		if actor.OrganizationID == orgID {
			return nil
		}
		// ANOTHER organization → NOT FOUND. A 403 confirms the organization
		// exists, which lets one tenant's admin probe the id space of others;
		// 404 says nothing. Same shape as the users read/update/delete paths
		// (AdminPermissionsModel.md, THE-MODEL-IS-LAW order C).
		return ErrSANotFound
	}
	return ErrSAForbidden
}
