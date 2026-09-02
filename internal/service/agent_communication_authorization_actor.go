package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ErrAgentCommunicationForbidden — the principal may not act on the
// agent-communication surface at all: not an org_admin, no organization
// context, no user identity, or an explicit organization that is not the
// principal's own. It is CALLER-dependent, never TARGET-dependent, so it
// carries no information about whether anything exists.
var ErrAgentCommunicationForbidden = errors.New("service: agent communication authorization forbidden for this principal")

// agentCommunicationActor resolves the acting owner: the repository's
// tenant authority model (see ServiceAccountService.requireOrgAdmin) —
// an org_admin acts ONLY inside their own organization; site_admin is
// refused (platform administration never silently becomes tenant
// ownership); org_user is refused. Returns the organization and the acting
// user id.
func agentCommunicationActor(actor *domain.Principal) (uuid.UUID, uuid.UUID, error) {
	if actor == nil || !actor.IsOrgAdminOnly() {
		return uuid.Nil, uuid.Nil, ErrAgentCommunicationForbidden
	}
	if actor.OrganizationID == uuid.Nil || actor.UserID == uuid.Nil {
		return uuid.Nil, uuid.Nil, ErrAgentCommunicationForbidden
	}
	return actor.OrganizationID, actor.UserID, nil
}

// Now exposes the service clock so the wire layer derives the response
// status from the same clock the aggregate was created and validated with.
func (s *AgentCommunicationAuthorizationService) Now() time.Time {
	return s.now()
}

// CreateForActor creates an authorization owned by the acting org_admin
// inside their own organization. Any OrganizationID / OwnerID in the
// input is not trusted: an explicit organization that differs from the
// actor's is refused; the owner is ALWAYS the actor.
func (s *AgentCommunicationAuthorizationService) CreateForActor(ctx context.Context, actor *domain.Principal, in CreateAgentCommunicationAuthorizationInput) (*domain.AgentCommunicationAuthorization, error) {
	org, owner, err := agentCommunicationActor(actor)
	if err != nil {
		return nil, err
	}
	if in.OrganizationID != uuid.Nil && in.OrganizationID != org {
		return nil, ErrAgentCommunicationForbidden
	}
	in.OrganizationID = org
	in.OwnerID = owner
	return s.Create(ctx, in)
}

// GetForActor reads one authorization of the actor's organization. A
// foreign or absent id answers domain.ErrAgentCommunicationAuthorizationNotFound
// identically (no cross-organization existence oracle).
func (s *AgentCommunicationAuthorizationService) GetForActor(ctx context.Context, actor *domain.Principal, id uuid.UUID) (*domain.AgentCommunicationAuthorization, error) {
	org, _, err := agentCommunicationActor(actor)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, org, id)
}

// ListForActor lists the actor's organization's authorizations.
func (s *AgentCommunicationAuthorizationService) ListForActor(ctx context.Context, actor *domain.Principal) ([]*domain.AgentCommunicationAuthorization, error) {
	org, _, err := agentCommunicationActor(actor)
	if err != nil {
		return nil, err
	}
	return s.List(ctx, org)
}

// RevokeForActor revokes one authorization of the actor's organization
// (same-organization emergency revocation by any org_admin is allowed and
// must be audited by the caller). The second value reports whether THIS
// call performed the revocation (false = already revoked: idempotent, the
// first stamp is returned unchanged). A foreign or absent id answers
// not-found identically.
func (s *AgentCommunicationAuthorizationService) RevokeForActor(ctx context.Context, actor *domain.Principal, id uuid.UUID, reason string) (*domain.AgentCommunicationAuthorization, bool, error) {
	org, by, err := agentCommunicationActor(actor)
	if err != nil {
		return nil, false, err
	}
	current, err := s.Get(ctx, org, id)
	if err != nil {
		return nil, false, err
	}
	if current.RevokedAt != nil {
		return current, false, nil
	}
	revoked, err := s.Revoke(ctx, org, id, by, reason)
	if err != nil {
		return nil, false, err
	}
	return revoked, true, nil
}
