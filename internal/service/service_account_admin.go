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
	// AYGHU-2 (measured live): owner_user_id existed since migration 0001 but
	// NOTHING in OSS ever wrote it, so every service account was ownerless
	// and the agent-communication same-owner rule refused all of them. The
	// creating org_admin (requireOrgAdmin admits nobody else) is the owner:
	// a service account is that person's agent identity.
	owner := actor.UserID
	sa := &domain.ServiceAccount{
		OrganizationID: orgID,
		Name:           strings.TrimSpace(in.Name),
		Description:    strings.TrimSpace(in.Description),
		Role:           role,
		Active:         true,
		ExpiresAt:      in.ExpiresAt,
		OwnerUserID:    &owner,
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
//
// THE-OWNERLESS-ACCOUNT: a STORE failure is not the verdict "no such
// account". It answers AUTH-503 (503 + correlation id) so the caller
// retries, exactly as every other auth-store read does; a genuine absence
// still answers ErrSANotFound.
func (s *ServiceAccountService) GetForActor(ctx context.Context, actor *domain.Principal, saID uuid.UUID) (*domain.ServiceAccount, error) {
	sa, err := s.repo.GetByID(ctx, saID)
	if err != nil {
		// The store's TYPED verdict for "no such live row" stays not-found;
		// anything else is an outage, not an answer (MEASURED on the live
		// appliance: the pgx repository returns domain.ErrServiceAccountNotFound
		// for pgx.ErrNoRows, so this distinction is load-bearing).
		if errors.Is(err, domain.ErrServiceAccountNotFound) {
			return nil, ErrSANotFound
		}
		return nil, domain.AuthStoreUnavailable("service_account.get", err)
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
		// THE-SILENT-DROP-2: TRIMMED, matching OrgRoleService. The previous
		// slice left this assigning the raw value, so a whitespace-only
		// description CLEARED an org role and was STORED as "   " on a
		// service account — one convention, two answers. Trimming makes ""
		// and "   " both mean "cleared" on every surface. buildForActor
		// trims too, so create and update stay aligned.
		sa.Description = strings.TrimSpace(*in.Description)
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

// ── Owner assignment (THE-OWNERLESS-ACCOUNT) ─────────────────────────────
//
// A service account is a person's agent identity: the agent-communication
// same-owner rule refuses two participants that do not share one owner, and
// issuance re-checks the binding. Accounts created before AYGHU-2 carry no
// owner at all and can never participate. This is the owner's own repair and
// hand-over path — assign where there is none, transfer where there is.

// ServiceAccountOwnerUserLookup reads the candidate owner. Narrow on
// purpose: the service needs to know that the user is a live org_admin of
// the service account's organization and nothing else.
type ServiceAccountOwnerUserLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// AgentCommunicationLiveParticipantLookup answers whether a LIVE
// authorization names the account. Ownership cannot move while one stands.
type AgentCommunicationLiveParticipantLookup interface {
	HasLiveParticipant(ctx context.Context, organizationID, serviceAccountID uuid.UUID, now time.Time) (bool, error)
}

// Owner-assignment sentinels. Wire mappings:
//
//   - ErrSAOwnerNotEligible    → 400 (reason owner_not_eligible)
//   - ErrSAOwnerTransferBlocked → 409 (reason agent_communication_authorization_active)
var (
	ErrSAOwnerNotEligible      = errors.New("service: owner candidate is not an eligible owner of this service account")
	ErrSAOwnerTransferBlocked  = errors.New("service: service-account ownership cannot be transferred while a live agent communication authorization names it")
	errSAOwnerGuardUnavailable = errors.New("owner-transfer guard is not wired")
)

// AssignServiceAccountOwnerInput carries the requested owner. A nil
// OwnerUserID means "the acting org_admin claims it".
type AssignServiceAccountOwnerInput struct {
	OwnerUserID *uuid.UUID
}

// ServiceAccountOwnerAssignment is the before/after record the audit trail
// and the wire response are built from.
type ServiceAccountOwnerAssignment struct {
	ServiceAccount      *domain.ServiceAccount
	PreviousOwnerUserID *uuid.UUID
	OwnerUserID         uuid.UUID
	// Result is one of "assigned" (there was no owner), "transferred" (there
	// was a different one) or "unchanged" (already that owner).
	Result string
}

// WithOwnerAssignment wires the two reads the assignment path needs: the
// candidate-owner lookup and the live-authorization guard. Both are
// optional at construction so existing callers keep compiling; a transfer
// refuses to answer at all when the guard is missing (503, not a verdict),
// and a candidate other than the actor is refused when the user lookup is
// missing.
func (s *ServiceAccountService) WithOwnerAssignment(users ServiceAccountOwnerUserLookup, live AgentCommunicationLiveParticipantLookup) *ServiceAccountService {
	s.ownerUsers = users
	s.liveAuthorizations = live
	return s
}

// AssignOwnerForActor sets the service account's owner.
//
//   - org_admin of the account's OWN organization only; every other actor
//     gets the same answer the rest of this surface gives (403, or 404 for
//     another organization's id — no existence oracle).
//   - The new owner defaults to the acting org_admin. A supplied owner must
//     be a live, non-banned org_admin of the SAME organization.
//   - Assigning where there is no owner always proceeds. TRANSFERRING away
//     from an existing owner is refused while a live agent-communication
//     authorization names the account.
//   - Re-assigning the current owner writes nothing and reports "unchanged".
//   - Every store failure answers AUTH-503, never a verdict.
func (s *ServiceAccountService) AssignOwnerForActor(ctx context.Context, actor *domain.Principal, saID uuid.UUID, in AssignServiceAccountOwnerInput) (*ServiceAccountOwnerAssignment, error) {
	sa, err := s.GetForActor(ctx, actor, saID)
	if err != nil {
		return nil, err
	}
	target := actor.UserID
	if in.OwnerUserID != nil && *in.OwnerUserID != actor.UserID {
		if s.ownerUsers == nil {
			return nil, ErrSAOwnerNotEligible
		}
		u, uerr := s.ownerUsers.GetByID(ctx, *in.OwnerUserID)
		if uerr != nil {
			// The user store reports an unknown, deleted or banned id as its
			// TYPED not-found (MEASURED: the pgx repository maps pgx.ErrNoRows
			// to domain.ErrUserNotFound and its query already excludes banned
			// and soft-deleted rows). That is a verdict about the candidate,
			// not an outage — it joins every other ineligible candidate.
			if errors.Is(uerr, domain.ErrUserNotFound) {
				return nil, ErrSAOwnerNotEligible
			}
			return nil, domain.AuthStoreUnavailable("service_account.owner_candidate", uerr)
		}
		if !isEligibleServiceAccountOwner(u, sa.OrganizationID) {
			return nil, ErrSAOwnerNotEligible
		}
		target = u.ID
	}
	if target == uuid.Nil {
		return nil, ErrSAOwnerNotEligible
	}

	previous := sa.OwnerUserID
	if previous != nil && *previous == target {
		return &ServiceAccountOwnerAssignment{
			ServiceAccount: sa, PreviousOwnerUserID: previous, OwnerUserID: target, Result: "unchanged",
		}, nil
	}
	result := "assigned"
	if previous != nil {
		result = "transferred"
		// A live authorization was judged against the owner of record and
		// issuance re-checks it: moving the owner underneath it would strand
		// a running session. The owner revokes first, then transfers.
		if s.liveAuthorizations == nil {
			return nil, domain.AuthStoreUnavailable("service_account.owner_transfer_guard", errSAOwnerGuardUnavailable)
		}
		live, lerr := s.liveAuthorizations.HasLiveParticipant(ctx, sa.OrganizationID, sa.ID, s.now().UTC())
		if lerr != nil {
			return nil, domain.AuthStoreUnavailable("service_account.owner_transfer_guard", lerr)
		}
		if live {
			return nil, ErrSAOwnerTransferBlocked
		}
	}
	if err := s.repo.UpdateOwner(ctx, sa.ID, sa.OrganizationID, target); err != nil {
		return nil, domain.AuthStoreUnavailable("service_account.owner_write", err)
	}
	owner := target
	sa.OwnerUserID = &owner
	sa.UpdatedAt = s.now().UTC()
	return &ServiceAccountOwnerAssignment{
		ServiceAccount: sa, PreviousOwnerUserID: previous, OwnerUserID: target, Result: result,
	}, nil
}

// isEligibleServiceAccountOwner: a live, non-banned org_admin of the
// service account's own organization. Anyone else — a deleted or banned
// user, an org_user, a site_admin, another tenant's admin — is refused
// identically, so the endpoint is no directory of who exists.
func isEligibleServiceAccountOwner(u *domain.User, orgID uuid.UUID) bool {
	if u == nil || u.ID == uuid.Nil {
		return false
	}
	if u.DeletedAt != nil || u.Banned {
		return false
	}
	if u.OrganizationID != orgID {
		return false
	}
	return u.IsOrgAdminOnly()
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
	if err != nil {
		// THE-SILENT-EXPIRY: the third instance of the collapse
		// THE-OWNERLESS-ACCOUNT closed on the other two readers. The store's
		// TYPED verdict is still "no such account"; anything else is an
		// outage, and the client register/update handlers answer 503 for it
		// rather than telling the operator their request was invalid.
		if errors.Is(err, domain.ErrServiceAccountNotFound) {
			return ErrServiceAccountNotFound
		}
		return domain.AuthStoreUnavailable("service_account.binding_validation", err)
	}
	if sa == nil {
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
