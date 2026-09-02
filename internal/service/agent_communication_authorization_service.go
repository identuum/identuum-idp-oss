package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// AgentCommunicationServiceAccountLookup is the slice of the service-account
// store the authorization service needs. The store answers
// domain.ErrServiceAccountNotFound for an absent or soft-deleted row; any
// other error is a store failure.
type AgentCommunicationServiceAccountLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.ServiceAccount, error)
}

// AgentCommunicationClientLookup is the slice of the client store the
// authorization service needs. The store answers domain.ErrClientNotFound
// for an absent row (or a row of a non-live organization); any other error
// is a store failure.
type AgentCommunicationClientLookup interface {
	GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// AgentCommunicationParticipantInput names one participant by the
// identifiers the owner knows: their service account, the OAuth client
// (installation) of that service account, the role, the proof key
// thumbprint the participant will later bind DPoP proofs to, and the
// capabilities requested for it.
type AgentCommunicationParticipantInput struct {
	ServiceAccountID   uuid.UUID
	ClientID           string
	Role               domain.AgentCommunicationParticipantRole
	ProofKeyThumbprint string
	Capabilities       []string
}

// CreateAgentCommunicationAuthorizationInput is the creation request.
// The IdP allocates every identifier of the result; none is accepted here.
type CreateAgentCommunicationAuthorizationInput struct {
	OrganizationID      uuid.UUID
	OwnerID             uuid.UUID
	RelayAudience       string
	ExpiresAt           time.Time
	MaxMessages         int
	MaxMessageSizeBytes int64
	Participants        []AgentCommunicationParticipantInput
}

// AgentCommunicationAuthorizationServiceOptions carries test seams.
type AgentCommunicationAuthorizationServiceOptions struct {
	// Now defaults to time.Now.
	Now func() time.Time
	// NewID defaults to uuidgen.NewV7 — every identifier the service
	// allocates (authorization, session, participant ids, ACIs) is a
	// UUIDv7.
	NewID func() (uuid.UUID, error)
}

// AgentCommunicationAuthorizationService owns the AYGHU-1 invariants that
// need the store: the same-owner rule, participant liveness, client
// binding and asymmetric authentication, plus the structural invariants
// re-checked through domain.Validate before the atomic write. Store errors
// on every path surface as domain.AuthStoreUnavailable (AUTH-503), never
// as a verdict.
type AgentCommunicationAuthorizationService struct {
	repo    repository.AgentCommunicationAuthorizationRepository
	sas     AgentCommunicationServiceAccountLookup
	clients AgentCommunicationClientLookup
	now     func() time.Time
	newID   func() (uuid.UUID, error)
}

// NewAgentCommunicationAuthorizationService wires the service. A nil
// dependency is a startup fault reported through report (P-018), never a
// panic.
func NewAgentCommunicationAuthorizationService(
	report *lifecycle.StartupReport,
	repo repository.AgentCommunicationAuthorizationRepository,
	sas AgentCommunicationServiceAccountLookup,
	clients AgentCommunicationClientLookup,
	opts AgentCommunicationAuthorizationServiceOptions,
) *AgentCommunicationAuthorizationService {
	if repo == nil {
		report.Fatal("NewAgentCommunicationAuthorizationService", "service: NewAgentCommunicationAuthorizationService requires a non-nil AgentCommunicationAuthorizationRepository")
	}
	if sas == nil {
		report.Fatal("NewAgentCommunicationAuthorizationService", "service: NewAgentCommunicationAuthorizationService requires a non-nil service-account lookup")
	}
	if clients == nil {
		report.Fatal("NewAgentCommunicationAuthorizationService", "service: NewAgentCommunicationAuthorizationService requires a non-nil client lookup")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	newID := opts.NewID
	if newID == nil {
		newID = uuidgen.NewV7
	}
	return &AgentCommunicationAuthorizationService{repo: repo, sas: sas, clients: clients, now: now, newID: newID}
}

// resolvedParticipant is a participant after its rows were loaded and
// checked.
type resolvedParticipant struct {
	input        AgentCommunicationParticipantInput
	sa           *domain.ServiceAccount
	client       *domain.Client
	capabilities []domain.AgentCommunicationCapability
}

// Create builds, validates and atomically persists a new authorization.
//
// Order of refusal: structural input checks first (two participants,
// closed role set, closed capability vocabulary, audience, limits,
// expiry) — nothing is loaded for a malformed request; then each
// participant's service account and client are loaded and checked
// (same-owner, liveness, binding, private_key_jwt); then identifiers are
// allocated, the digest computed, the aggregate validated once more and
// written in one transaction.
func (s *AgentCommunicationAuthorizationService) Create(ctx context.Context, in CreateAgentCommunicationAuthorizationInput) (*domain.AgentCommunicationAuthorization, error) {
	now := s.now()
	if in.OrganizationID == uuid.Nil {
		return nil, fmt.Errorf("%w: organization", domain.ErrAgentCommunicationIdentifierRequired)
	}
	if in.OwnerID == uuid.Nil {
		return nil, fmt.Errorf("%w: owner", domain.ErrAgentCommunicationIdentifierRequired)
	}
	// Two-participant exactness — refused before any lookup.
	if len(in.Participants) != 2 {
		return nil, fmt.Errorf("%w: got %d", domain.ErrAgentCommunicationParticipantCount, len(in.Participants))
	}
	audience, err := domain.NormalizeAgentCommunicationRelayAudience(in.RelayAudience)
	if err != nil {
		return nil, err
	}
	if in.MaxMessages <= 0 || in.MaxMessageSizeBytes <= 0 {
		return nil, domain.ErrAgentCommunicationLimitNotPositive
	}
	if !in.ExpiresAt.After(now) {
		return nil, domain.ErrAgentCommunicationExpiryNotFuture
	}

	resolved := make([]resolvedParticipant, 0, 2)
	roles := make(map[domain.AgentCommunicationParticipantRole]struct{}, 2)
	saIDs := make(map[uuid.UUID]struct{}, 2)
	clientIDs := make(map[string]struct{}, 2)
	for _, p := range in.Participants {
		if !p.Role.Valid() {
			return nil, fmt.Errorf("%w: %q", domain.ErrAgentCommunicationInvalidRole, p.Role)
		}
		if _, dup := roles[p.Role]; dup {
			return nil, domain.ErrAgentCommunicationDuplicateRole
		}
		roles[p.Role] = struct{}{}
		if p.ServiceAccountID == uuid.Nil {
			return nil, fmt.Errorf("%w: participant service account", domain.ErrAgentCommunicationIdentifierRequired)
		}
		if _, dup := saIDs[p.ServiceAccountID]; dup {
			return nil, domain.ErrAgentCommunicationDuplicateServiceAccount
		}
		saIDs[p.ServiceAccountID] = struct{}{}
		clientID := strings.TrimSpace(p.ClientID)
		if clientID == "" {
			return nil, fmt.Errorf("%w: participant client", domain.ErrAgentCommunicationIdentifierRequired)
		}
		if _, dup := clientIDs[clientID]; dup {
			return nil, domain.ErrAgentCommunicationDuplicateClient
		}
		clientIDs[clientID] = struct{}{}
		if err := domain.ValidateAgentCommunicationProofKeyThumbprint(p.ProofKeyThumbprint); err != nil {
			return nil, err
		}
		raw := make([]domain.AgentCommunicationCapability, 0, len(p.Capabilities))
		for _, c := range p.Capabilities {
			raw = append(raw, domain.AgentCommunicationCapability(c))
		}
		caps, err := domain.CanonicalizeAgentCommunicationCapabilities(raw)
		if err != nil {
			return nil, err
		}
		p.ClientID = clientID
		resolved = append(resolved, resolvedParticipant{input: p, capabilities: caps})
	}

	// Load and check each participant against the store.
	sas := make([]*domain.ServiceAccount, 0, 2)
	for i := range resolved {
		rp := &resolved[i]
		sa, err := s.sas.GetByID(ctx, rp.input.ServiceAccountID)
		if err != nil {
			if errors.Is(err, domain.ErrServiceAccountNotFound) {
				return nil, fmt.Errorf("%w: %s", domain.ErrServiceAccountNotFound, rp.input.ServiceAccountID)
			}
			return nil, domain.AuthStoreUnavailable("agent_communication.create.service_account", err)
		}
		if sa == nil || sa.OrganizationID != in.OrganizationID {
			// Another organization's service account is indistinguishable
			// from an absent one — no cross-org existence oracle.
			return nil, fmt.Errorf("%w: %s", domain.ErrServiceAccountNotFound, rp.input.ServiceAccountID)
		}
		if !sa.Active || (sa.ExpiresAt != nil && !sa.ExpiresAt.After(now)) {
			return nil, fmt.Errorf("%w: %s", domain.ErrAgentCommunicationParticipantNotUsable, sa.ID)
		}
		rp.sa = sa
		sas = append(sas, sa)
	}
	// Same-owner rule: both participants owned by the creating owner;
	// ownerless refused; cross-owner refused (deferred, not built).
	if err := domain.CheckAgentCommunicationSameOwner(in.OwnerID, sas...); err != nil {
		return nil, err
	}
	for i := range resolved {
		rp := &resolved[i]
		client, err := s.clients.GetClientByClientID(ctx, rp.input.ClientID)
		if err != nil {
			if errors.Is(err, domain.ErrClientNotFound) {
				return nil, fmt.Errorf("%w: %s", domain.ErrClientNotFound, rp.input.ClientID)
			}
			return nil, domain.AuthStoreUnavailable("agent_communication.create.client", err)
		}
		if client == nil {
			return nil, fmt.Errorf("%w: %s", domain.ErrClientNotFound, rp.input.ClientID)
		}
		if err := domain.CheckAgentCommunicationParticipantClient(rp.sa, client); err != nil {
			return nil, err
		}
		rp.client = client
	}

	// Allocate every identifier (UUIDv7) and assemble the aggregate.
	authID, err := s.newID()
	if err != nil {
		return nil, fmt.Errorf("agent communication: allocate authorization id: %w", err)
	}
	sessionID, err := s.newID()
	if err != nil {
		return nil, fmt.Errorf("agent communication: allocate session id: %w", err)
	}
	a := &domain.AgentCommunicationAuthorization{
		ID:                  authID,
		OrganizationID:      in.OrganizationID,
		OwnerID:             in.OwnerID,
		SessionID:           sessionID,
		RelayAudience:       audience,
		MaxMessages:         in.MaxMessages,
		MaxMessageSizeBytes: in.MaxMessageSizeBytes,
		ExpiresAt:           in.ExpiresAt.UTC(),
		CreatedAt:           now.UTC(),
		PolicyVersion:       domain.AgentCommunicationPolicyVersion,
		Participants:        make([]domain.AgentCommunicationParticipant, 0, 2),
	}
	for _, rp := range resolved {
		pid, err := s.newID()
		if err != nil {
			return nil, fmt.Errorf("agent communication: allocate participant id: %w", err)
		}
		aci, err := s.newID()
		if err != nil {
			return nil, fmt.Errorf("agent communication: allocate aci: %w", err)
		}
		a.Participants = append(a.Participants, domain.AgentCommunicationParticipant{
			ID:                 pid,
			AuthorizationID:    authID,
			ACI:                aci,
			ServiceAccountID:   rp.sa.ID,
			OAuthClientID:      rp.client.ID,
			Role:               rp.input.Role,
			ProofKeyThumbprint: rp.input.ProofKeyThumbprint,
			Capabilities:       rp.capabilities,
			CreatedAt:          now.UTC(),
		})
	}
	digest, err := a.ComputePolicyDigest()
	if err != nil {
		return nil, fmt.Errorf("agent communication: policy digest: %w", err)
	}
	a.PolicyDigest = digest
	if err := a.Validate(now); err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, a); err != nil {
		return nil, domain.AuthStoreUnavailable("agent_communication.create", err)
	}
	return a, nil
}

// Get returns one authorization of the organization; a foreign or absent
// id answers domain.ErrAgentCommunicationAuthorizationNotFound.
func (s *AgentCommunicationAuthorizationService) Get(ctx context.Context, organizationID, id uuid.UUID) (*domain.AgentCommunicationAuthorization, error) {
	if organizationID == uuid.Nil || id == uuid.Nil {
		return nil, domain.ErrAgentCommunicationAuthorizationNotFound
	}
	a, err := s.repo.GetByID(ctx, organizationID, id)
	if err != nil {
		if errors.Is(err, domain.ErrAgentCommunicationAuthorizationNotFound) {
			return nil, err
		}
		return nil, domain.AuthStoreUnavailable("agent_communication.get", err)
	}
	return a, nil
}

// List returns every authorization of the organization, newest first.
func (s *AgentCommunicationAuthorizationService) List(ctx context.Context, organizationID uuid.UUID) ([]*domain.AgentCommunicationAuthorization, error) {
	if organizationID == uuid.Nil {
		return nil, fmt.Errorf("%w: organization", domain.ErrAgentCommunicationIdentifierRequired)
	}
	out, err := s.repo.ListByOrganization(ctx, organizationID)
	if err != nil {
		return nil, domain.AuthStoreUnavailable("agent_communication.list", err)
	}
	if out == nil {
		out = []*domain.AgentCommunicationAuthorization{}
	}
	return out, nil
}

// Revoke stamps the authorization revoked (terminal). A second call is an
// idempotent no-op that returns the already-revoked row; a foreign or
// absent id answers domain.ErrAgentCommunicationAuthorizationNotFound.
func (s *AgentCommunicationAuthorizationService) Revoke(ctx context.Context, organizationID, id, revokedBy uuid.UUID, reason string) (*domain.AgentCommunicationAuthorization, error) {
	if revokedBy == uuid.Nil {
		return nil, fmt.Errorf("%w: revoked_by", domain.ErrAgentCommunicationIdentifierRequired)
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > domain.AgentCommunicationRevocationReasonMaxLen {
		return nil, domain.ErrAgentCommunicationRevocationReasonTooLong
	}
	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}
	current, err := s.Get(ctx, organizationID, id)
	if err != nil {
		return nil, err
	}
	if current.RevokedAt != nil {
		return current, nil
	}
	if _, err := s.repo.Revoke(ctx, organizationID, id, revokedBy, reasonPtr, s.now().UTC()); err != nil {
		return nil, domain.AuthStoreUnavailable("agent_communication.revoke", err)
	}
	// Re-read: the first stamp wins even when a concurrent revoke raced us.
	return s.Get(ctx, organizationID, id)
}
