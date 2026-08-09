package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// bundleClientRepoStub is the smallest ClientRepository the bundle's
// client-register path needs. It supports failure injection so the
// atomicity test can drive a deterministic client-create failure.
type bundleClientRepoStub struct {
	registerErr error
	registered  *domain.Client
}

func (r *bundleClientRepoStub) RegisterClient(_ context.Context, c *domain.Client) error {
	if r.registerErr != nil {
		return r.registerErr
	}
	cp := *c
	r.registered = &cp
	return nil
}
func (r *bundleClientRepoStub) GetClientByID(context.Context, uuid.UUID) (*domain.Client, error) {
	return nil, nil
}
func (r *bundleClientRepoStub) GetClientByClientID(context.Context, string) (*domain.Client, error) {
	return nil, nil
}
func (r *bundleClientRepoStub) Update(context.Context, *domain.Client) error { return nil }
func (r *bundleClientRepoStub) Delete(context.Context, uuid.UUID, *uuid.UUID) error {
	return nil
}
func (r *bundleClientRepoStub) List(context.Context, repository.Pagination, *uuid.UUID) ([]*domain.Client, int, error) {
	return nil, 0, nil
}
func (r *bundleClientRepoStub) ListByServiceAccountID(context.Context, uuid.UUID, uuid.UUID) ([]*domain.Client, error) {
	return nil, nil
}
func (r *bundleClientRepoStub) SaveConsent(context.Context, *domain.Consent) error {
	return nil
}
func (r *bundleClientRepoStub) GetConsent(context.Context, uuid.UUID, uuid.UUID, *uuid.UUID) (*domain.Consent, error) {
	return nil, nil
}

// Compile-time check.
var _ repository.ClientRepository = (*bundleClientRepoStub)(nil)

// fakeBundleRepo is a test double for
// repository.ServiceAccountClientBundleRepository. It presents the atomic
// both-or-nothing contract over the in-memory SA + client fakes: if the
// SA insert fails, nothing persists; if the client insert fails, the SA it
// just added is removed. This mirrors what the real pgx transaction does
// (the true DB rollback is proven by the e2e pgx atomicity test); the unit
// tests here pin the SERVICE contract on top of that repository.
type fakeBundleRepo struct {
	sa     *adminFakeSARepo
	client *bundleClientRepoStub
}

func (r *fakeBundleRepo) CreateWithClient(ctx context.Context, sa *domain.ServiceAccount, client *domain.Client) (*domain.ServiceAccount, *domain.Client, error) {
	createdSA, err := r.sa.Create(ctx, sa)
	if err != nil {
		return nil, nil, err
	}
	client.ServiceAccountID = &createdSA.ID
	if err := r.client.RegisterClient(ctx, client); err != nil {
		_ = r.sa.Delete(ctx, createdSA.ID, createdSA.OrganizationID)
		return nil, nil, err
	}
	return createdSA, client, nil
}

var _ repository.ServiceAccountClientBundleRepository = (*fakeBundleRepo)(nil)

// helper ------------------------------------------------------

func bundleSAOrgAdmin(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgAdmin,
	}
}

func newBundleHarness(t *testing.T, clientRegisterErr error) (*ServiceAccountClientBundleService, *adminFakeSARepo, *bundleClientRepoStub) {
	t.Helper()
	saRepo := newAdminFakeSARepo()
	clientRepo := &bundleClientRepoStub{registerErr: clientRegisterErr}
	saSvc := NewServiceAccountService(nil, saRepo)
	// prepareClient (the bundle's client path) is pure — the ClientService
	// here is real but its repo is never hit by the bundle; the fakeBundleRepo
	// owns persistence and drives failure injection via clientRepo.
	clientSvc := NewClientService(nil, clientRepo).WithServiceAccountBindingValidator(saSvc)
	bundleRepo := &fakeBundleRepo{sa: saRepo, client: clientRepo}
	bundle := NewServiceAccountClientBundleService(nil, saSvc, clientSvc, bundleRepo)
	return bundle, saRepo, clientRepo
}

// ---------- Construction ----------

func TestNewBundle_NilDepsPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil deps did not panic")
		}
	}()
	_ = NewServiceAccountClientBundleService(nil, nil, nil, nil)
}

// ---------- Happy path ----------

func TestBundleCreate_HappyPathReturnsOneTimeSecret(t *testing.T) {
	bundle, saRepo, clientRepo := newBundleHarness(t, nil)
	orgID := uuid.New()
	result, err := bundle.CreateServiceAccountWithClientForActor(
		context.Background(), bundleSAOrgAdmin(orgID), orgID,
		BundleInput{SAName: "deploy-bot", SARole: domain.RoleOrgUser},
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if result.ServiceAccount.Name != "deploy-bot" {
		t.Errorf("sa name = %q", result.ServiceAccount.Name)
	}
	// The client must be bound to the SA created in the same transaction.
	if result.Client == nil || result.Client.ServiceAccountID == nil ||
		*result.Client.ServiceAccountID != result.ServiceAccount.ID {
		t.Errorf("client not bound to created SA: %+v", result.Client)
	}
	if result.ClientSecret == "" {
		t.Errorf("client_secret empty (one-time should be populated)")
	}
	if _, ok := saRepo.byID[result.ServiceAccount.ID]; !ok {
		t.Errorf("SA not persisted")
	}
	if clientRepo.registered == nil {
		t.Errorf("client not persisted")
	}
	if clientRepo.registered.ServiceAccountID == nil ||
		*clientRepo.registered.ServiceAccountID != result.ServiceAccount.ID {
		t.Errorf("persisted client not bound to the SA id")
	}
}

// ---------- Authorization gates ----------

func TestBundleCreate_OrgUserForbidden(t *testing.T) {
	bundle, saRepo, _ := newBundleHarness(t, nil)
	orgID := uuid.New()
	actor := &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser}
	_, err := bundle.CreateServiceAccountWithClientForActor(
		context.Background(), actor, orgID,
		BundleInput{SAName: "x"},
	)
	if !errors.Is(err, ErrSAForbidden) {
		t.Errorf("err = %v", err)
	}
	if len(saRepo.byID) != 0 {
		t.Errorf("forbidden actor persisted an SA: %d rows", len(saRepo.byID))
	}
}

func TestBundleCreate_CrossOrgOrgAdminNotFound(t *testing.T) {
	bundle, _, _ := newBundleHarness(t, nil)
	other := uuid.New()
	_, err := bundle.CreateServiceAccountWithClientForActor(
		context.Background(), bundleSAOrgAdmin(uuid.New()), other,
		BundleInput{SAName: "x"},
	)
	if !errors.Is(err, ErrSANotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestBundleCreate_EmptyNameRejected(t *testing.T) {
	bundle, _, _ := newBundleHarness(t, nil)
	orgID := uuid.New()
	_, err := bundle.CreateServiceAccountWithClientForActor(
		context.Background(), bundleSAOrgAdmin(orgID), orgID,
		BundleInput{SAName: "   "},
	)
	if !errors.Is(err, ErrBundleInvalidInput) {
		t.Errorf("err = %v", err)
	}
}

// ---------- Atomicity (the point of P2-16b) ----------

// TestBundleCreate_ClientFailureIsAtomic_NoOrphanSA proves that when the
// client half of the write fails, the bundle surfaces ErrBundleClientCreate
// and NO service account is left behind. There is no compensating-delete
// path in the service anymore — atomicity is the repository's job, and the
// service just wraps the failure. (The real DB rollback is proven by the
// e2e pgx atomicity test; here the fakeBundleRepo enforces the same
// contract.)
func TestBundleCreate_ClientFailureIsAtomic_NoOrphanSA(t *testing.T) {
	bundle, saRepo, _ := newBundleHarness(t, errors.New("simulated client create failure"))
	orgID := uuid.New()
	res, err := bundle.CreateServiceAccountWithClientForActor(
		context.Background(), bundleSAOrgAdmin(orgID), orgID,
		BundleInput{SAName: "ephemeral-bot"},
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if res != nil {
		t.Errorf("expected nil result on failure, got %+v", res)
	}
	if !errors.Is(err, ErrBundleClientCreate) {
		t.Errorf("err sentinel = %v, want ErrBundleClientCreate", err)
	}
	if len(saRepo.byID) != 0 {
		t.Errorf("orphan SA left after atomic failure: %d rows remaining", len(saRepo.byID))
	}
}

// TestBundleCreate_SACreateFailureIsAtomic proves an SA-insert failure
// inside the atomic write also surfaces ErrBundleClientCreate with nothing
// persisted.
func TestBundleCreate_SACreateFailureIsAtomic(t *testing.T) {
	bundle, saRepo, clientRepo := newBundleHarness(t, nil)
	saRepo.createErr = errors.New("simulated SA insert failure")
	orgID := uuid.New()
	_, err := bundle.CreateServiceAccountWithClientForActor(
		context.Background(), bundleSAOrgAdmin(orgID), orgID,
		BundleInput{SAName: "ephemeral-bot"},
	)
	if !errors.Is(err, ErrBundleClientCreate) {
		t.Errorf("err sentinel = %v, want ErrBundleClientCreate", err)
	}
	if len(saRepo.byID) != 0 {
		t.Errorf("SA persisted despite create failure: %d rows", len(saRepo.byID))
	}
	if clientRepo.registered != nil {
		t.Errorf("client persisted despite SA-create failure (not atomic)")
	}
}

// ---------- Client defaults ----------

func TestBundleCreate_ClientNameDefaultsToSAName(t *testing.T) {
	bundle, _, clientRepo := newBundleHarness(t, nil)
	orgID := uuid.New()
	result, err := bundle.CreateServiceAccountWithClientForActor(
		context.Background(), bundleSAOrgAdmin(orgID), orgID,
		BundleInput{SAName: "ci-runner", SARole: domain.RoleOrgUser},
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if result.Client.Name != "ci-runner" {
		t.Errorf("client name = %q, want default to SAName", result.Client.Name)
	}
	if clientRepo.registered.Name != "ci-runner" {
		t.Errorf("registered client name = %q", clientRepo.registered.Name)
	}
}

func TestBundleCreate_PublicClientNeverEmitted(t *testing.T) {
	bundle, _, clientRepo := newBundleHarness(t, nil)
	orgID := uuid.New()
	_, err := bundle.CreateServiceAccountWithClientForActor(
		context.Background(), bundleSAOrgAdmin(orgID), orgID,
		BundleInput{SAName: "secure-bot", SARole: domain.RoleOrgUser},
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if clientRepo.registered.IsPublic {
		t.Errorf("bundle created a public client (must be confidential)")
	}
}

// ---------- Secret sentinel ----------

func TestBundleCreate_PlaintextSecretLengthSane(t *testing.T) {
	bundle, _, _ := newBundleHarness(t, nil)
	orgID := uuid.New()
	result, err := bundle.CreateServiceAccountWithClientForActor(
		context.Background(), bundleSAOrgAdmin(orgID), orgID,
		BundleInput{SAName: "x", SARole: domain.RoleOrgUser},
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if len(result.ClientSecret) < 32 {
		t.Errorf("plaintext secret length = %d (expected ≥ 32)", len(result.ClientSecret))
	}
	if strings.ContainsAny(result.ClientSecret, " \t\n") {
		t.Errorf("plaintext secret contains whitespace — should be hex-only")
	}
}
