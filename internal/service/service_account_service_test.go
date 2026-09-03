package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// inMemoryServiceAccountRepo implements the parts of
// repository.ServiceAccountRepository the lookup path touches.
// Unused methods panic so a future code-path drift is caught
// instantly.
type inMemoryServiceAccountRepo struct {
	byID     map[uuid.UUID]*domain.ServiceAccount
	getErr   error
	ownerErr error
}

func newInMemorySARepo() *inMemoryServiceAccountRepo {
	return &inMemoryServiceAccountRepo{byID: map[uuid.UUID]*domain.ServiceAccount{}}
}

func (r *inMemoryServiceAccountRepo) Create(context.Context, *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	panic("not used")
}
func (r *inMemoryServiceAccountRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.ServiceAccount, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	sa, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *sa
	return &cp, nil
}
func (r *inMemoryServiceAccountRepo) GetByName(context.Context, uuid.UUID, string) (*domain.ServiceAccount, error) {
	panic("not used")
}
func (r *inMemoryServiceAccountRepo) ListByOrganization(context.Context, uuid.UUID) ([]*domain.ServiceAccount, error) {
	panic("not used")
}
func (r *inMemoryServiceAccountRepo) Update(context.Context, *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	panic("not used")
}
func (r *inMemoryServiceAccountRepo) Delete(context.Context, uuid.UUID, uuid.UUID) error {
	panic("not used")
}
func (r *inMemoryServiceAccountRepo) UpdateLastUsedAt(context.Context, uuid.UUID) error {
	panic("not used")
}
func (r *inMemoryServiceAccountRepo) UpdateActive(context.Context, uuid.UUID, uuid.UUID, bool) error {
	panic("not used")
}

// UpdateOwner backs the owner-assignment tests (THE-OWNERLESS-ACCOUNT).
// ownerErr lets a test make the write fail like a store outage.
func (r *inMemoryServiceAccountRepo) UpdateOwner(_ context.Context, id, orgID, ownerUserID uuid.UUID) error {
	if r.ownerErr != nil {
		return r.ownerErr
	}
	sa, ok := r.byID[id]
	if !ok || sa.OrganizationID != orgID {
		return errors.New("service account not found")
	}
	owner := ownerUserID
	sa.OwnerUserID = &owner
	return nil
}

// Compile-time check that the fake satisfies the interface.
var _ repository.ServiceAccountRepository = (*inMemoryServiceAccountRepo)(nil)

// ---------- Construction ----------

func TestNewServiceAccountService_NilRepoPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil repo did not panic")
		}
	}()
	_ = NewServiceAccountService(nil, nil)
}

// ---------- LookupForClient guards ----------

func TestLookup_UnboundClientRejected(t *testing.T) {
	svc := NewServiceAccountService(nil, newInMemorySARepo())
	client := &domain.Client{ClientID: "cli", ServiceAccountID: nil}
	_, err := svc.LookupForClient(context.Background(), client)
	if !errors.Is(err, ErrServiceAccountUnbound) {
		t.Errorf("err = %v", err)
	}
}

func TestLookup_NilClientRejected(t *testing.T) {
	svc := NewServiceAccountService(nil, newInMemorySARepo())
	_, err := svc.LookupForClient(context.Background(), nil)
	if !errors.Is(err, ErrServiceAccountUnbound) {
		t.Errorf("err = %v", err)
	}
}

func TestLookup_MissingSARejected(t *testing.T) {
	svc := NewServiceAccountService(nil, newInMemorySARepo())
	saID := uuid.New()
	client := &domain.Client{ClientID: "cli", ServiceAccountID: &saID}
	_, err := svc.LookupForClient(context.Background(), client)
	if !errors.Is(err, ErrServiceAccountNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestLookup_InactiveSARejected(t *testing.T) {
	repo := newInMemorySARepo()
	saID := uuid.New()
	repo.byID[saID] = &domain.ServiceAccount{
		ID: saID, OrganizationID: uuid.New(), Active: false, Role: domain.RoleOrgUser,
	}
	svc := NewServiceAccountService(nil, repo)
	client := &domain.Client{ClientID: "cli", ServiceAccountID: &saID}
	_, err := svc.LookupForClient(context.Background(), client)
	if !errors.Is(err, ErrServiceAccountInactive) {
		t.Errorf("err = %v", err)
	}
}

func TestLookup_ExpiredSARejected(t *testing.T) {
	repo := newInMemorySARepo()
	saID := uuid.New()
	past := time.Now().Add(-time.Hour)
	repo.byID[saID] = &domain.ServiceAccount{
		ID: saID, OrganizationID: uuid.New(), Active: true,
		ExpiresAt: &past, Role: domain.RoleOrgUser,
	}
	svc := NewServiceAccountService(nil, repo)
	client := &domain.Client{ClientID: "cli", ServiceAccountID: &saID}
	_, err := svc.LookupForClient(context.Background(), client)
	if !errors.Is(err, ErrServiceAccountExpired) {
		t.Errorf("err = %v", err)
	}
}

func TestLookup_OrgMismatchRejected(t *testing.T) {
	repo := newInMemorySARepo()
	saID := uuid.New()
	clientOrg := uuid.New()
	saOrg := uuid.New()
	repo.byID[saID] = &domain.ServiceAccount{
		ID: saID, OrganizationID: saOrg, Active: true, Role: domain.RoleOrgUser,
	}
	svc := NewServiceAccountService(nil, repo)
	client := &domain.Client{ClientID: "cli", ServiceAccountID: &saID, OrganizationID: &clientOrg}
	_, err := svc.LookupForClient(context.Background(), client)
	if !errors.Is(err, ErrServiceAccountOrgMismatch) {
		t.Errorf("err = %v", err)
	}
}

// THE-OWNERLESS-ACCOUNT replaced TestLookup_RepoErrorMapsToNotFound: a store
// outage was answering "this client has no service account", which the token
// endpoint then reported as unauthorized_client — a verdict the server had
// not reached. A repository error is now AUTH-503; an ABSENT row is still
// not-found (TestLookup_MissingSARejected pins that side).
func TestLookup_RepoErrorIsStoreUnavailable(t *testing.T) {
	repo := newInMemorySARepo()
	repo.getErr = errors.New("db down")
	svc := NewServiceAccountService(nil, repo)
	saID := uuid.New()
	client := &domain.Client{ClientID: "cli", ServiceAccountID: &saID}
	_, err := svc.LookupForClient(context.Background(), client)
	if !domain.IsAuthStoreUnavailable(err) {
		t.Errorf("err = %v (a store outage must be AUTH-503, not a verdict)", err)
	}
	if errors.Is(err, ErrServiceAccountNotFound) {
		t.Errorf("err = %v (a store outage must not read as not-found)", err)
	}
}

// ---------- happy path ----------

func TestLookup_HappyPathReturnsSafeProjection(t *testing.T) {
	repo := newInMemorySARepo()
	saID := uuid.New()
	orgID := uuid.New()
	future := time.Now().Add(2 * time.Hour)
	repo.byID[saID] = &domain.ServiceAccount{
		ID:             saID,
		OrganizationID: orgID,
		Active:         true,
		ExpiresAt:      &future,
		Role:           domain.RoleOrgAdmin,
		Name:           "internal-secret-name-must-not-leak",
		Description:    "internal-description-must-not-leak",
	}
	svc := NewServiceAccountService(nil, repo)
	client := &domain.Client{ClientID: "cli", ServiceAccountID: &saID, OrganizationID: &orgID}
	out, err := svc.LookupForClient(context.Background(), client)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if out.Subject != saID.String() {
		t.Errorf("subject = %q, want %s", out.Subject, saID)
	}
	if out.OrganizationID != orgID {
		t.Errorf("org id = %s, want %s", out.OrganizationID, orgID)
	}
	if out.Role != string(domain.RoleOrgAdmin) {
		t.Errorf("role = %q", out.Role)
	}
	if out.ActorType != ActorTypeServiceAccount {
		t.Errorf("actor_type = %q", out.ActorType)
	}
}

func TestLookup_NoExpiryAcceptsForever(t *testing.T) {
	repo := newInMemorySARepo()
	saID := uuid.New()
	orgID := uuid.New()
	repo.byID[saID] = &domain.ServiceAccount{
		ID:             saID,
		OrganizationID: orgID,
		Active:         true,
		ExpiresAt:      nil, // no expiry — accept indefinitely
		Role:           domain.RoleOrgUser,
	}
	svc := NewServiceAccountService(nil, repo)
	client := &domain.Client{ClientID: "cli", ServiceAccountID: &saID}
	if _, err := svc.LookupForClient(context.Background(), client); err != nil {
		t.Errorf("no-expiry SA rejected: %v", err)
	}
}
