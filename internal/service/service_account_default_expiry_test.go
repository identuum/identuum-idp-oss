package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-SA-EXPIRY (owner rulings P-069..P-072, 2026-10-05): a service account
// created without expires_at gets creation + N days, N the organization's
// service_account_expiry_days; N = 0 means no default; an explicit future
// expires_at is kept; existing accounts never change.

// saOrgExpiry is the organization read the create path needs.
type saOrgExpiry struct {
	days map[uuid.UUID]int
	err  error
}

func (f *saOrgExpiry) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	if f.err != nil {
		return nil, f.err
	}
	n, ok := f.days[id]
	if !ok {
		return nil, nil
	}
	return &domain.Organization{ID: id, ServiceAccountExpiryDays: n}, nil
}

// saOrgNoDefault answers N = 0 for every organization: the behaviour the
// tests written before the default expiry existed were built on.
type saOrgNoDefault struct{}

func (saOrgNoDefault) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	return &domain.Organization{ID: id}, nil
}

var saExpiryT0 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func newDefaultExpirySAService(orgID uuid.UUID, days int) (*ServiceAccountService, *adminFakeSARepo, *saOrgExpiry) {
	repo := newAdminFakeSARepo()
	orgs := &saOrgExpiry{days: map[uuid.UUID]int{orgID: days}}
	svc := NewServiceAccountService(nil, repo).WithOrganizationExpiry(orgs)
	svc.now = func() time.Time { return saExpiryT0 }
	return svc, repo, orgs
}

func TestCreateForActor_DefaultExpiryIsCreationPlusOrgDays(t *testing.T) {
	org := uuid.New()
	svc, repo, _ := newDefaultExpirySAService(org, 30)
	sa, err := svc.CreateForActor(context.Background(), newOrgAdmin(org), org, ServiceAccountAdminInput{Name: "ci"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	want := saExpiryT0.Add(30 * 24 * time.Hour)
	if sa.ExpiresAt == nil || !sa.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want %v (creation + 30 days)", sa.ExpiresAt, want)
	}
	if got := repo.byID[sa.ID].ExpiresAt; got == nil || !got.Equal(want) {
		t.Fatalf("persisted expires_at = %v, want %v", got, want)
	}
}

func TestCreateForActor_ZeroOrgDaysMeansNoDefault(t *testing.T) {
	org := uuid.New()
	svc, _, _ := newDefaultExpirySAService(org, 0)
	sa, err := svc.CreateForActor(context.Background(), newOrgAdmin(org), org, ServiceAccountAdminInput{Name: "ci"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sa.ExpiresAt != nil {
		t.Fatalf("N = 0 must mean no default expiry, got %v", sa.ExpiresAt)
	}
}

func TestCreateForActor_ExplicitFutureExpiryKept(t *testing.T) {
	org := uuid.New()
	svc, _, _ := newDefaultExpirySAService(org, 30)
	explicit := saExpiryT0.Add(5 * 24 * time.Hour)
	sa, err := svc.CreateForActor(context.Background(), newOrgAdmin(org), org, ServiceAccountAdminInput{Name: "ci", ExpiresAt: &explicit})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sa.ExpiresAt == nil || !sa.ExpiresAt.Equal(explicit) {
		t.Fatalf("explicit expires_at = %v, want %v kept", sa.ExpiresAt, explicit)
	}
}

func TestCreateForActor_DefaultExpiryFailsClosed(t *testing.T) {
	org := uuid.New()
	// The organization read fails: nothing is created, never a non-expiring account.
	svc, repo, orgs := newDefaultExpirySAService(org, 30)
	orgs.err = errors.New("store down")
	if _, err := svc.CreateForActor(context.Background(), newOrgAdmin(org), org, ServiceAccountAdminInput{Name: "ci"}); !errors.Is(err, ErrSAExpiryPolicyUnavailable) {
		t.Fatalf("err = %v, want ErrSAExpiryPolicyUnavailable", err)
	}
	// The organization is not there.
	orgs.err = nil
	delete(orgs.days, org)
	if _, err := svc.CreateForActor(context.Background(), newOrgAdmin(org), org, ServiceAccountAdminInput{Name: "ci"}); !errors.Is(err, ErrSAExpiryPolicyUnavailable) {
		t.Fatalf("err = %v, want ErrSAExpiryPolicyUnavailable", err)
	}
	// The seam is not wired.
	unwired := NewServiceAccountService(nil, repo)
	if _, err := unwired.CreateForActor(context.Background(), newOrgAdmin(org), org, ServiceAccountAdminInput{Name: "ci"}); !errors.Is(err, ErrSAExpiryPolicyUnavailable) {
		t.Fatalf("err = %v, want ErrSAExpiryPolicyUnavailable", err)
	}
	if len(repo.byID) != 0 {
		t.Fatalf("a refused create persisted %d account(s)", len(repo.byID))
	}
}

func TestBundleCreate_DefaultExpiryFromOrganization(t *testing.T) {
	for _, tc := range []struct {
		days int
		want *time.Time
	}{
		{days: 30, want: func() *time.Time { v := saExpiryT0.Add(30 * 24 * time.Hour); return &v }()},
		{days: 0, want: nil},
	} {
		bundle, saRepo, _ := newBundleHarness(t, nil)
		org := uuid.New()
		bundle.saService.WithOrganizationExpiry(&saOrgExpiry{days: map[uuid.UUID]int{org: tc.days}})
		bundle.saService.now = func() time.Time { return saExpiryT0 }
		res, err := bundle.CreateServiceAccountWithClientForActor(context.Background(), bundleSAOrgAdmin(org), org, BundleInput{SAName: "bot"})
		if err != nil {
			t.Fatalf("N=%d bundle: %v", tc.days, err)
		}
		got := saRepo.byID[res.ServiceAccount.ID].ExpiresAt
		if (got == nil) != (tc.want == nil) || (got != nil && !got.Equal(*tc.want)) {
			t.Fatalf("N=%d persisted expires_at = %v, want %v", tc.days, got, tc.want)
		}
	}
}

// End to end through the token service: N = 1, created with no expires_at at
// T0. A client_credentials request one second before T0 + 1 day gets a token;
// one second after, it is refused exactly as an expired account is today.
func TestDefaultExpiry_ClientCredentialsRefusedAfterNDays(t *testing.T) {
	org := uuid.New()
	saSvc, _, _ := newDefaultExpirySAService(org, 1)
	sa, err := saSvc.CreateForActor(context.Background(), newOrgAdmin(org), org, ServiceAccountAdminInput{Name: "ci"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ed := genEdDSAKey(t, "kid-eddsa")
	provider := &inMemoryKeyProvider{keys: []domain.SigningKey{ed}}
	bound := &domain.Client{ClientID: "cli-1", ServiceAccountID: &sa.ID}
	tokens := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).
		WithServiceAccountLookup(saSvc, &stubClientLookup{client: bound})
	issue := func() error {
		_, err := tokens.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{GrantType: "client_credentials"})
		return err
	}

	saSvc.now = func() time.Time { return saExpiryT0.Add(24*time.Hour - time.Second) }
	if err := issue(); err != nil {
		t.Fatalf("one second before creation + 1 day: %v, want a token", err)
	}
	saSvc.now = func() time.Time { return saExpiryT0.Add(24*time.Hour + time.Second) }
	if err := issue(); !errors.Is(err, ErrTokenServiceUnauthorizedClient) {
		t.Fatalf("one second after creation + 1 day: %v, want ErrTokenServiceUnauthorizedClient", err)
	}
	if _, err := saSvc.LookupForClient(context.Background(), bound); !errors.Is(err, ErrServiceAccountExpired) {
		t.Fatalf("lookup after expiry: %v, want ErrServiceAccountExpired (today's expired-account refusal)", err)
	}

	// N = 0: no default expiry, so ten years on the account still gets a token.
	org0 := uuid.New()
	saSvc0, _, _ := newDefaultExpirySAService(org0, 0)
	sa0, err := saSvc0.CreateForActor(context.Background(), newOrgAdmin(org0), org0, ServiceAccountAdminInput{Name: "ci"})
	if err != nil {
		t.Fatalf("create N=0: %v", err)
	}
	tokens0 := NewTokenService(nil, provider, TokenServiceOptions{Issuer: "https://idp.test"}).
		WithServiceAccountLookup(saSvc0, &stubClientLookup{client: &domain.Client{ClientID: "cli-1", ServiceAccountID: &sa0.ID}})
	saSvc0.now = func() time.Time { return saExpiryT0.Add(3650 * 24 * time.Hour) }
	if _, err := tokens0.IssueClientCredentials(context.Background(), newConfidentialOAuthClient(), ClientCredentialsRequest{GrantType: "client_credentials"}); err != nil {
		t.Fatalf("N = 0 account after ten years: %v, want a token", err)
	}
}

// Ruling d: an account that exists without expires_at keeps it NULL when the
// organization's N changes and the account is read or updated.
func TestDefaultExpiry_ExistingAccountUnchangedWhenNChanges(t *testing.T) {
	org := uuid.New()
	svc, repo, orgs := newDefaultExpirySAService(org, 0)
	existing := &domain.ServiceAccount{ID: uuid.New(), OrganizationID: org, Name: "old", Active: true, Role: domain.RoleOrgUser}
	repo.byID[existing.ID] = existing
	orgs.days[org] = 30
	admin := newOrgAdmin(org)
	got, err := svc.GetForActor(context.Background(), admin, existing.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ExpiresAt != nil {
		t.Fatalf("read after N changed: expires_at = %v, want NULL", got.ExpiresAt)
	}
	desc := "renamed"
	if _, err := svc.UpdateForActor(context.Background(), admin, existing.ID, ServiceAccountUpdateInput{Description: &desc}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if repo.byID[existing.ID].ExpiresAt != nil {
		t.Fatalf("update after N changed set expires_at = %v, want NULL", repo.byID[existing.ID].ExpiresAt)
	}
}
