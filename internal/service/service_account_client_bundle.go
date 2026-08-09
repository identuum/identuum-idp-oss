package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// ServiceAccountClientBundleService stitches the OSS
// ServiceAccountService + ClientService together so operators can
// create a service account, a confidential OAuth client, and the
// SA → client binding in one call. This mirrors the workflow the
// monolith requires by chaining HandleCreateServiceAccount +
// HandleCreateClient + an explicit bind, condensed into a single
// OSS admin endpoint.
//
// Every gate (RBAC, org-scope, SA lifecycle, public-client rejection,
// input validation) is delegated to the underlying services via their
// PURE prepare helpers (ServiceAccountService.buildForActor +
// ClientService.prepareClient), so there is no validation/generation
// logic duplicated here. The two prepared rows are then handed to
// bundleRepo.CreateWithClient, which persists BOTH in a SINGLE
// transaction. Either both rows commit or neither does — there is no
// orphan-SA window (the P2-16b hazard the prior best-effort
// compensating-delete flow left open on a double failure / crash).
type ServiceAccountClientBundleService struct {
	saService     *ServiceAccountService
	clientService *ClientService
	bundleRepo    repository.ServiceAccountClientBundleRepository
}

// NewServiceAccountClientBundleService constructs the bundle. Both
// services and the atomic bundle repository are required; nil panics so a
// misconfigured deployment cannot silently expose an endpoint that
// half-creates rows.
func NewServiceAccountClientBundleService(report *lifecycle.StartupReport, saService *ServiceAccountService, clientService *ClientService, bundleRepo repository.ServiceAccountClientBundleRepository) *ServiceAccountClientBundleService {
	if saService == nil {
		report.Fatal("NewServiceAccountClientBundleService", "service: NewServiceAccountClientBundleService requires a non-nil ServiceAccountService")
	}
	if clientService == nil {
		report.Fatal("NewServiceAccountClientBundleService", "service: NewServiceAccountClientBundleService requires a non-nil ClientService")
	}
	if bundleRepo == nil {
		report.Fatal("NewServiceAccountClientBundleService", "service: NewServiceAccountClientBundleService requires a non-nil ServiceAccountClientBundleRepository")
	}
	return &ServiceAccountClientBundleService{
		saService:     saService,
		clientService: clientService,
		bundleRepo:    bundleRepo,
	}
}

// BundleInput is the parameter object accepted by
// CreateServiceAccountWithClientForActor. The SA portion drives
// ServiceAccountService.buildForActor; the client portion drives
// ClientService.prepareClient. The bundle defaults the client's
// Name to the SA's Name when ClientName is empty so operators do
// not have to repeat themselves.
type BundleInput struct {
	// Service-account input.
	SAName        string
	SADescription string
	SARole        domain.UserRole
	SAExpiresAt   *time.Time

	// OAuth client input. ClientName defaults to SAName.
	// RedirectURIs defaults to a single placeholder ("https://localhost")
	// when empty — the monolith requires at least one URI for the
	// client to be persistable, but a client_credentials-only
	// client does not actually use the redirect URI on the wire.
	ClientName       string
	RedirectURIs     []string
	AllowedAudiences []string
	Scope            string
}

// BundleResult carries the persisted SA, the persisted Client,
// and the one-time plaintext client secret. The plaintext is the
// SAME value prepareClient generated and is shown to the operator
// EXACTLY ONCE — list/get on the client admin endpoint will never
// echo it again.
type BundleResult struct {
	ServiceAccount *domain.ServiceAccount
	Client         *domain.Client
	ClientSecret   string
}

// Sentinel errors. The wire layer maps these to:
//   - ErrBundleInvalidInput → 400
//   - ErrBundleSACreate     → mapped via the SA-error chain when the
//     underlying RBAC/validation sentinels surface directly.
//   - ErrBundleClientCreate → 400. Now wraps ANY failure of the
//     client-prepare step OR the atomic SA+client write — on a write
//     failure the transaction rolls back and NOTHING is persisted, so
//     there is no orphan SA and no separate rollback-failure mode.
var (
	ErrBundleInvalidInput = errors.New("service: bundle requires SAName")
	ErrBundleSACreate     = errors.New("service: bundle service-account create failed")
	ErrBundleClientCreate = errors.New("service: bundle client create failed")
)

// CreateServiceAccountWithClientForActor runs the bundle flow.
// The actor RBAC checks are delegated to ServiceAccountService —
// the same site_admin / same-org org_admin gates that govern the
// standalone /api/v1/organizations/:id/service-accounts route
// govern this combined route too.
//
// Flow: buildForActor (RBAC + validate + SA struct) → prepareClient
// (validate + generate + client struct) → bundleRepo.CreateWithClient
// (persist BOTH in one transaction).
//
// Failure semantics:
//   - RBAC / SA validation fails → no rows persisted; the underlying
//     ErrSA* sentinel surfaces directly for the handler to map.
//   - Client prepare fails → no rows persisted; wrapped in
//     ErrBundleClientCreate.
//   - Atomic write fails (SA insert, client insert, or commit) → the
//     transaction rolls back so NOTHING persists (no orphan SA);
//     wrapped in ErrBundleClientCreate.
//
// The one-time plaintext client secret is returned via
// BundleResult.ClientSecret. The bundle service itself NEVER
// logs the secret and NEVER writes it to audit metadata.
func (s *ServiceAccountClientBundleService) CreateServiceAccountWithClientForActor(ctx context.Context, actor *domain.Principal, orgID uuid.UUID, in BundleInput) (*BundleResult, error) {
	if strings.TrimSpace(in.SAName) == "" {
		return nil, ErrBundleInvalidInput
	}

	// 1. Build (do NOT persist) the service account: actor RBAC gate +
	//    name/role/expiry validation + struct assembly.
	sa, err := s.saService.buildForActor(actor, orgID, ServiceAccountAdminInput{
		Name:        in.SAName,
		Description: in.SADescription,
		Role:        in.SARole,
		ExpiresAt:   in.SAExpiresAt,
	})
	if err != nil {
		return nil, err
	}

	// 2. Prepare (do NOT persist) the confidential OAuth client. The SA
	//    binding is left nil here — the repo binds it to the SA created in
	//    the SAME transaction (valid by construction), so no not-yet-
	//    committed SA is ever read.
	clientName := strings.TrimSpace(in.ClientName)
	if clientName == "" {
		clientName = sa.Name
	}
	redirectURIs := in.RedirectURIs
	if len(redirectURIs) == 0 {
		// client_credentials-only clients still need at least one
		// redirect URI per domain.Client.Validate(). A localhost
		// placeholder is the conventional opt-out; operators can
		// later overwrite via the standalone UpdateClient route.
		redirectURIs = []string{"https://localhost"}
	}
	clientOrgID := sa.OrganizationID
	client, plaintextSecret, err := s.clientService.prepareClient(RegisterClientOptions{
		Name:             clientName,
		OrganizationID:   &clientOrgID,
		IsPublic:         false,
		RedirectURIs:     redirectURIs,
		AllowedAudiences: in.AllowedAudiences,
		Scope:            in.Scope,
	})
	if err != nil {
		return nil, errors.Join(ErrBundleClientCreate, err)
	}

	// 3. Persist BOTH rows atomically. Any failure rolls the whole
	//    transaction back — no orphan SA is ever left behind.
	createdSA, createdClient, err := s.bundleRepo.CreateWithClient(ctx, sa, client)
	if err != nil {
		return nil, errors.Join(ErrBundleClientCreate, err)
	}

	return &BundleResult{
		ServiceAccount: createdSA,
		Client:         createdClient,
		ClientSecret:   plaintextSecret,
	}, nil
}
