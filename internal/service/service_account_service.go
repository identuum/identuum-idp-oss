package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// ServiceAccountService is the OSS facade in front of the
// existing service_accounts table. It is intentionally narrow:
// only the lookup-by-ID path that backs the OAuth client-
// credentials grant lives here. CRUD admin paths remain handler-
// driven via the repository, matching the prior-slice pattern
// for ScopeTemplate / APIResource.
//
// Lifecycle gates (active + not-deleted + not-expired) live in
// this service so the TokenService's ServiceAccountLookup seam
// can stay a tiny pure-function contract.
type ServiceAccountService struct {
	repo repository.ServiceAccountRepository
	now  func() time.Time
	// Owner-assignment seams (THE-OWNERLESS-ACCOUNT), both optional at
	// construction and wired by the runtime. See WithOwnerAssignment.
	ownerUsers         ServiceAccountOwnerUserLookup
	liveAuthorizations AgentCommunicationLiveParticipantLookup
}

// NewServiceAccountService constructs the service.
// repo is required; a nil repo panics so a misconfigured
// deployment cannot silently accept the client-credentials path
// without the lifecycle gates.
func NewServiceAccountService(report *lifecycle.StartupReport, repo repository.ServiceAccountRepository) *ServiceAccountService {
	if repo == nil {
		report.Fatal("NewServiceAccountService", "service: NewServiceAccountService requires a non-nil ServiceAccountRepository")
	}
	return &ServiceAccountService{repo: repo, now: time.Now}
}

// ServiceAccountTokenSubject is the safe projection returned by
// LookupForClient. It carries only the fields the token-issuance
// path needs (Subject, OrganizationID, Role) plus an ActorType
// marker that flows into the access-token's claims for downstream
// introspection / userinfo to distinguish from human user tokens.
//
// The struct deliberately omits Name, Description, OwnerUserID,
// ExpiresAt — those fields are operator-only and must not appear
// in claims, audit metadata, or wire responses.
type ServiceAccountTokenSubject struct {
	Subject        string
	OrganizationID uuid.UUID
	Role           string
	ActorType      string
}

// Sentinel errors returned by LookupForClient. The wire layer
// maps every one of them to RFC 6749 §5.2 `unauthorized_client`
// so the response is opaque — operators cannot enumerate which
// gate failed via the wire envelope.
var (
	// ErrServiceAccountUnbound — the OAuth client has no
	// ServiceAccountID configured. Without strict binding the
	// client cannot mint a client-credentials token under this
	// service.
	ErrServiceAccountUnbound = errors.New("service: oauth client is not bound to a service account")

	// ErrServiceAccountNotFound — the configured ServiceAccountID
	// does not resolve to a row. Likely the row was deleted out
	// from under the client.
	ErrServiceAccountNotFound = errors.New("service: service account not found")

	// ErrServiceAccountInactive — the SA row exists but `active`
	// is false.
	ErrServiceAccountInactive = errors.New("service: service account is inactive")

	// ErrServiceAccountExpired — the SA carries an ExpiresAt and
	// it has passed.
	ErrServiceAccountExpired = errors.New("service: service account has expired")

	// ErrServiceAccountOrgMismatch — the client's OrganizationID
	// (when set) does not match the SA's OrganizationID. A
	// mismatch is treated as a configuration error, not as a
	// privilege escalation — the wire layer still maps it to
	// unauthorized_client.
	ErrServiceAccountOrgMismatch = errors.New("service: oauth client / service account organization mismatch")
)

// LookupForClient resolves the supplied OAuth client to a safe
// ServiceAccountTokenSubject projection. Behavior:
//
//   - The client MUST carry a non-nil ServiceAccountID. An unbound
//     client returns ErrServiceAccountUnbound.
//   - The SA row MUST exist (ErrServiceAccountNotFound).
//   - The SA row MUST have Active == true (ErrServiceAccountInactive).
//   - When ExpiresAt is set, it MUST be in the future
//     (ErrServiceAccountExpired).
//   - When the client carries OrganizationID, it MUST equal the
//     SA's OrganizationID (ErrServiceAccountOrgMismatch).
//
// On success the returned projection populates:
//
//   - Subject     = SA.ID.String()  (UUID — matches monolith policy)
//   - Organization = SA.OrganizationID
//   - Role         = string(SA.Role)
//   - ActorType    = "service_account"
//
// The raw SA struct, its OwnerUserID, Description, ExpiresAt, and
// Name are NEVER returned by this function.
func (s *ServiceAccountService) LookupForClient(ctx context.Context, client *domain.Client) (*ServiceAccountTokenSubject, error) {
	if client == nil || client.ServiceAccountID == nil {
		return nil, ErrServiceAccountUnbound
	}
	sa, err := s.repo.GetByID(ctx, *client.ServiceAccountID)
	if err != nil {
		// THE-OWNERLESS-ACCOUNT: a store outage is not "this client has no
		// service account". AUTH-503 travels up to the token endpoint, which
		// answers 503 + correlation id instead of unauthorized_client. The
		// store's TYPED not-found is still the ordinary verdict.
		if errors.Is(err, domain.ErrServiceAccountNotFound) {
			return nil, ErrServiceAccountNotFound
		}
		return nil, domain.AuthStoreUnavailable("service_account.lookup", err)
	}
	if sa == nil {
		return nil, ErrServiceAccountNotFound
	}
	if !sa.Active {
		return nil, ErrServiceAccountInactive
	}
	if sa.ExpiresAt != nil && !sa.ExpiresAt.After(s.now()) {
		return nil, ErrServiceAccountExpired
	}
	if client.OrganizationID != nil && *client.OrganizationID != sa.OrganizationID {
		return nil, ErrServiceAccountOrgMismatch
	}
	return &ServiceAccountTokenSubject{
		Subject:        sa.ID.String(),
		OrganizationID: sa.OrganizationID,
		Role:           string(sa.Role),
		ActorType:      ActorTypeServiceAccount,
	}, nil
}

// ActorTypeServiceAccount is the canonical value the OSS
// IntrospectionClaims and userinfo handler use to distinguish
// service-account tokens from human-user tokens. Lives on the
// service-account service so the TokenService and downstream
// handlers share one source of truth.
const ActorTypeServiceAccount = "service_account"
