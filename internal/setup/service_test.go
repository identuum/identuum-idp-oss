package setup

// Unit tests for the appliance setup Service. We compose against in-memory
// fakes for every repository and a real *service.OrganizationService /
// *service.KeyService over those fakes. The fakes implement only the
// methods the Service actually calls; the unused interface methods return
// the zero value or a sentinel error so the type system is satisfied
// without us having to re-implement the entire repository surface.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// --- in-memory Repository (setup state) -------------------------------------

type memSetupStateRepo struct {
	mu    sync.Mutex
	state domain.SetupState
}

func newMemSetupStateRepo() *memSetupStateRepo {
	return &memSetupStateRepo{
		state: domain.SetupState{
			ID:        domain.SetupStateSingletonID,
			Status:    domain.SetupStatusRequired,
			UpdatedAt: time.Now().UTC(),
		},
	}
}

func (m *memSetupStateRepo) Get(_ context.Context) (*domain.SetupState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := m.state
	return &cp, nil
}
func (m *memSetupStateRepo) EnsureRow(_ context.Context) error { return nil }
func (m *memSetupStateRepo) UpdateTokenHash(_ context.Context, hash string, createdAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.SetupTokenHash = hash
	t := createdAt
	m.state.SetupTokenCreatedAt = &t
	m.state.UpdatedAt = time.Now().UTC()
	return nil
}
func (m *memSetupStateRepo) MarkComplete(_ context.Context, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.Status = domain.SetupStatusComplete
	m.state.SetupTokenHash = ""
	c := at
	m.state.CompletedAt = &c
	m.state.UpdatedAt = time.Now().UTC()
	return nil
}

// --- in-memory KeyRepository ------------------------------------------------

type memKeyRepo struct {
	mu   sync.Mutex
	keys []domain.SigningKey
}

func (m *memKeyRepo) GetActiveSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]domain.SigningKey, 0, len(m.keys))
	for _, k := range m.keys {
		if k.State == domain.KeyStateActive || k.State == domain.KeyStateRotating {
			out = append(out, k)
		}
	}
	return out, nil
}
func (m *memKeyRepo) GetAllSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]domain.SigningKey(nil), m.keys...), nil
}
func (m *memKeyRepo) GetSigningKeyByKID(_ context.Context, kid string) (*domain.SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.keys {
		if m.keys[i].KID == kid {
			k := m.keys[i]
			return &k, nil
		}
	}
	return nil, errors.New("test fake: key not found")
}
func (m *memKeyRepo) CreateSigningKey(_ context.Context, key *domain.SigningKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys = append(m.keys, *key)
	return nil
}
func (m *memKeyRepo) ActivateSigningKey(_ context.Context, _ string) error { return nil }
func (m *memKeyRepo) RotateSigningKey(_ context.Context, _, _ string, _ *time.Time) error {
	return nil
}
func (m *memKeyRepo) DeprecateSigningKey(_ context.Context, _ string, _ time.Time) error {
	return nil
}
func (m *memKeyRepo) DeleteExpiredKeys(_ context.Context) (int, error) { return 0, nil }

var _ repository.KeyRepository = (*memKeyRepo)(nil)

// --- in-memory UserRepository ----------------------------------------------

type memUserRepo struct {
	mu    sync.Mutex
	users []*domain.User
}

func (m *memUserRepo) Create(_ context.Context, u *domain.User) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.users {
		if existing.Email == u.Email && existing.OrganizationID == u.OrganizationID {
			return nil, domain.ErrUserAlreadyExists
		}
	}
	cp := *u
	m.users = append(m.users, &cp)
	out := cp
	return &out, nil
}
func (m *memUserRepo) GetByEmailAndOrgID(_ context.Context, orgID uuid.UUID, email string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Email == email && u.OrganizationID == orgID {
			out := *u
			return &out, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

// Stubs for the rest of the repository.UserRepository interface (unused
// by the setup Service but required by the type system).
func (m *memUserRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.ID == id {
			out := *u
			return &out, nil
		}
	}
	return nil, domain.ErrUserNotFound
}
func (m *memUserRepo) FindUsersByEmail(_ context.Context, _ string) ([]*domain.User, error) {
	return nil, nil
}
func (m *memUserRepo) GetByExternalID(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}
func (m *memUserRepo) GetByIDWithOrg(_ context.Context, _ uuid.UUID) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}
func (m *memUserRepo) Update(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ repository.UpdateUserOptions) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}
func (m *memUserRepo) Delete(_ context.Context, _, _ uuid.UUID) error   { return nil }
func (m *memUserRepo) Undelete(_ context.Context, _, _ uuid.UUID) error { return nil }
func (m *memUserRepo) List(_ context.Context, _ repository.ListUserOptions) ([]*domain.User, int, error) {
	return nil, 0, nil
}
func (m *memUserRepo) ListByOrganization(_ context.Context, _ uuid.UUID, _ repository.ListUserOptions) ([]*domain.User, int, error) {
	return nil, 0, nil
}
func (m *memUserRepo) UpdateLastLogin(_ context.Context, _ uuid.UUID) error            { return nil }
func (m *memUserRepo) CountByOrganization(_ context.Context, _ uuid.UUID) (int, error) { return 0, nil }
func (m *memUserRepo) CountOrgAdminsByOrganization(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, nil
}
func (m *memUserRepo) CountOrgAdminsByOrganizations(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]int, error) {
	return nil, nil
}
func (m *memUserRepo) CountVerifiedOrgAdminsByOrganization(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, nil
}
func (m *memUserRepo) CountVerifiedOrgAdminsByOrganizations(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]int, error) {
	return nil, nil
}
func (m *memUserRepo) VerifyPassword(_ context.Context, _, _ string) error { return nil }
func (m *memUserRepo) GetUserOrganization(_ context.Context, _ uuid.UUID) (*domain.Organization, error) {
	return nil, nil
}
func (m *memUserRepo) UpdateOrganizationID(_ context.Context, _, _ uuid.UUID) error { return nil }
func (m *memUserRepo) HashPassword(s string) (string, error)                        { return s, nil }
func (m *memUserRepo) ConsumeRecoveryCode(context.Context, uuid.UUID, string) (*domain.User, bool, error) {
	return nil, false, nil
}

var _ repository.UserRepository = (*memUserRepo)(nil)

// --- in-memory OrganizationRepository --------------------------------------

type memOrgRepo struct {
	mu   sync.Mutex
	orgs []*domain.Organization
}

func newMemOrgRepoWithSystemOrg() *memOrgRepo {
	systemOrgID, _ := uuid.Parse(domain.SystemOrgID)
	now := time.Now().UTC()
	return &memOrgRepo{
		orgs: []*domain.Organization{{
			ID:        systemOrgID,
			Name:      domain.SystemOrgName,
			Domain:    domain.SystemOrgDomain,
			OrgSlug:   "system-local",
			Active:    true,
			CreatedAt: now,
			UpdatedAt: now,
		}},
	}
}

func (m *memOrgRepo) Create(_ context.Context, o *domain.Organization) (*domain.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.orgs {
		if existing.Domain == o.Domain {
			return nil, errors.New("test fake: org domain already exists")
		}
	}
	cp := *o
	m.orgs = append(m.orgs, &cp)
	out := cp
	return &out, nil
}
func (m *memOrgRepo) CreateWithAdmin(_ context.Context, _ *domain.Organization, _ *domain.User) (*domain.Organization, *domain.User, error) {
	return nil, nil, errors.New("test fake: unimplemented")
}
func (m *memOrgRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.orgs {
		if o.ID == id {
			cp := *o
			return &cp, nil
		}
	}
	return nil, nil
}
func (m *memOrgRepo) GetByDomain(_ context.Context, d string) (*domain.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.orgs {
		if o.Domain == d {
			cp := *o
			return &cp, nil
		}
	}
	return nil, nil
}
func (m *memOrgRepo) GetBySlug(_ context.Context, slug string) (*domain.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.orgs {
		if o.OrgSlug == slug {
			cp := *o
			return &cp, nil
		}
	}
	return nil, nil
}
func (m *memOrgRepo) Update(_ context.Context, _ uuid.UUID, _ repository.UpdateOrganizationOptions) (*domain.Organization, error) {
	return nil, nil
}
func (m *memOrgRepo) Delete(_ context.Context, _ uuid.UUID) error   { return nil }
func (m *memOrgRepo) Undelete(_ context.Context, _ uuid.UUID) error { return nil }
func (m *memOrgRepo) List(_ context.Context, _ repository.OrganizationFilter, _ repository.Pagination, _ repository.Sort) ([]*domain.Organization, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*domain.Organization, 0, len(m.orgs))
	for _, o := range m.orgs {
		cp := *o
		out = append(out, &cp)
	}
	return out, len(out), nil
}
func (m *memOrgRepo) CountUsers(_ context.Context, _ uuid.UUID) (int, error)    { return 0, nil }
func (m *memOrgRepo) CountSessions(_ context.Context, _ uuid.UUID) (int, error) { return 0, nil }
func (m *memOrgRepo) GetDetails(_ context.Context, _ uuid.UUID) (*domain.Organization, map[string]int, error) {
	return nil, nil, nil
}

var _ repository.OrganizationRepository = (*memOrgRepo)(nil)

// --- test scaffold ----------------------------------------------------------

type testHarness struct {
	repo     *memSetupStateRepo
	orgRepo  *memOrgRepo
	userRepo *memUserRepo
	keyRepo  *memKeyRepo
	svc      *Service
	dataDir  string
}

func newHarness(t *testing.T) *testHarness {
	t.Helper()
	repo := newMemSetupStateRepo()
	orgRepo := newMemOrgRepoWithSystemOrg()
	userRepo := &memUserRepo{}
	keyRepo := &memKeyRepo{}

	deps := Deps{
		Repo:            repo,
		OrgService:      service.NewOrganizationService(nil, orgRepo),
		KeyService:      service.NewKeyService(keyRepo),
		OrgRepo:         orgRepo,
		UserRepo:        userRepo,
		Issuer:          "http://localhost:7113",
		UIPublicBaseURL: "http://localhost:7104",
		Now:             func() time.Time { return time.Now().UTC() },
	}
	return &testHarness{
		repo:     repo,
		orgRepo:  orgRepo,
		userRepo: userRepo,
		keyRepo:  keyRepo,
		svc:      New(deps),
		dataDir:  t.TempDir(),
	}
}

// --- Initialize tests -------------------------------------------------------

func TestInitialize_FreshDB(t *testing.T) {
	h := newHarness(t)
	banner, err := h.svc.Initialize(context.Background(), h.dataDir)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if banner == nil {
		t.Fatal("expected non-nil banner on fresh DB")
	}
	if banner.SetupURL != "http://localhost:7104/setup" {
		t.Errorf("SetupURL = %q; want http://localhost:7104/setup", banner.SetupURL)
	}
	if banner.SetupToken == "" || len(banner.SetupToken) != 52 {
		t.Errorf("SetupToken should be a 52-char base32 string, got %q (len=%d)", banner.SetupToken, len(banner.SetupToken))
	}
	if !strings.HasSuffix(banner.ShowCodeCommand, h.dataDir) {
		t.Errorf("ShowCodeCommand should reference dataDir: %q", banner.ShowCodeCommand)
	}

	// State should now hold the hash.
	state, _ := h.repo.Get(context.Background())
	if state.SetupTokenHash == "" {
		t.Errorf("hash not persisted after Initialize")
	}
	if !VerifyToken(banner.SetupToken, state.SetupTokenHash) {
		t.Errorf("banner token does not match persisted hash")
	}

	// File should be on disk.
	gotFile, err := ReadTokenFile(h.dataDir)
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	if gotFile != banner.SetupToken {
		t.Errorf("file != banner token")
	}
}

func TestInitialize_ReBootReusesExistingToken(t *testing.T) {
	h := newHarness(t)
	first, err := h.svc.Initialize(context.Background(), h.dataDir)
	if err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	second, err := h.svc.Initialize(context.Background(), h.dataDir)
	if err != nil {
		t.Fatalf("second Initialize: %v", err)
	}
	if first.SetupToken != second.SetupToken {
		t.Errorf("re-boot should reuse the existing token (file + hash present)")
	}
}

func TestInitialize_HashPresentFileMissingRegenerates(t *testing.T) {
	h := newHarness(t)
	first, err := h.svc.Initialize(context.Background(), h.dataDir)
	if err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	if err := DeleteTokenFile(h.dataDir); err != nil {
		t.Fatalf("DeleteTokenFile: %v", err)
	}
	second, err := h.svc.Initialize(context.Background(), h.dataDir)
	if err != nil {
		t.Fatalf("second Initialize: %v", err)
	}
	if first.SetupToken == second.SetupToken {
		t.Errorf("missing file should trigger regeneration")
	}
}

func TestInitialize_AfterCompleteReturnsNil(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.Initialize(context.Background(), h.dataDir)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if err := h.repo.MarkComplete(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("MarkComplete: %v", err)
	}
	banner, err := h.svc.Initialize(context.Background(), h.dataDir)
	if err != nil {
		t.Fatalf("Initialize after complete: %v", err)
	}
	if banner != nil {
		t.Errorf("expected nil banner after completion, got %+v", banner)
	}
	// Defensive cleanup should have removed any orphan file.
	if _, err := ReadTokenFile(h.dataDir); err == nil {
		t.Errorf("token file should be gone after Initialize sees complete state")
	}
}

// --- Status tests -----------------------------------------------------------

func TestStatus_FreshDB(t *testing.T) {
	h := newHarness(t)
	_, _ = h.svc.Initialize(context.Background(), h.dataDir)
	view, err := h.svc.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if view.State != domain.SetupStatusRequired {
		t.Errorf("State = %q; want %q", view.State, domain.SetupStatusRequired)
	}
	if view.SetupComplete {
		t.Errorf("SetupComplete should be false")
	}
	if !view.SetupTokenRequired {
		t.Errorf("SetupTokenRequired should be true")
	}
	if view.Product != ProductOSS {
		t.Errorf("Product = %q; want %q", view.Product, ProductOSS)
	}
	if view.Distribution != DistributionOSS {
		t.Errorf("Distribution = %q; want %q", view.Distribution, DistributionOSS)
	}
	if view.Issuer != "http://localhost:7113" {
		t.Errorf("Issuer leaked or wrong: %q", view.Issuer)
	}
	if view.FirstSigningKeyExists || view.SiteAdminExists || view.FirstOrganizationExists {
		t.Errorf("no entities should exist yet, got %+v", view)
	}
}

// --- VerifyToken tests ------------------------------------------------------

func TestService_VerifyToken_HappyPath(t *testing.T) {
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)
	if err := h.svc.VerifyToken(context.Background(), banner.SetupToken); err != nil {
		t.Errorf("VerifyToken: %v", err)
	}
}

func TestService_VerifyToken_BadToken(t *testing.T) {
	h := newHarness(t)
	_, _ = h.svc.Initialize(context.Background(), h.dataDir)
	err := h.svc.VerifyToken(context.Background(), "WRONGCODE0000000000000000000000000000000000000000000")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("err = %v; want ErrTokenInvalid", err)
	}
}

func TestService_VerifyToken_AfterCompleteIsGone(t *testing.T) {
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)
	_ = h.repo.MarkComplete(context.Background(), time.Now().UTC())
	err := h.svc.VerifyToken(context.Background(), banner.SetupToken)
	if !errors.Is(err, ErrAlreadyComplete) {
		t.Errorf("err = %v; want ErrAlreadyComplete", err)
	}
}

// --- Complete tests ---------------------------------------------------------

func validCompleteInput(token string) CompleteInput {
	return CompleteInput{
		SetupToken:         token,
		OrganizationName:   "Acme Corp",
		OrganizationDomain: "acme.example",
		AdminEmail:         "owner@acme.example",
		AdminPassword:      "Very-Long-Test-Password-1!",
	}
}

func TestComplete_HappyPath(t *testing.T) {
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)

	out, err := h.svc.Complete(context.Background(), h.dataDir, validCompleteInput(banner.SetupToken))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.State != domain.SetupStatusComplete {
		t.Errorf("State = %q; want %q", out.State, domain.SetupStatusComplete)
	}
	if out.OrganizationName != "Acme Corp" {
		t.Errorf("OrganizationName = %q", out.OrganizationName)
	}
	if out.AdminEmail != "owner@acme.example" {
		t.Errorf("AdminEmail = %q", out.AdminEmail)
	}

	// Setup state now reports complete.
	view, _ := h.svc.Status(context.Background())
	if !view.SetupComplete {
		t.Errorf("Status should report complete")
	}
	if !view.FirstSigningKeyExists {
		t.Errorf("signing key should be present")
	}
	if !view.SiteAdminExists {
		t.Errorf("site_admin should be present")
	}
	if !view.FirstOrganizationExists {
		t.Errorf("organization should be present")
	}

	// Token file should be gone.
	if _, err := ReadTokenFile(h.dataDir); err == nil {
		t.Errorf("token file should be deleted after Complete")
	}
}

func TestComplete_BadToken(t *testing.T) {
	h := newHarness(t)
	_, _ = h.svc.Initialize(context.Background(), h.dataDir)
	_, err := h.svc.Complete(context.Background(), h.dataDir, validCompleteInput("WRONG-TOKEN"))
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("err = %v; want ErrTokenInvalid", err)
	}
	view, _ := h.svc.Status(context.Background())
	if view.SetupComplete {
		t.Errorf("bad token must not flip state to complete")
	}
}

func TestComplete_InvalidInput(t *testing.T) {
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)

	for _, tc := range []struct {
		name string
		in   CompleteInput
	}{
		{"empty org name", CompleteInput{SetupToken: banner.SetupToken, OrganizationDomain: "x.example", AdminEmail: "a@b.c", AdminPassword: "Very-Long-Test-Password-1!"}},
		{"empty admin email", CompleteInput{SetupToken: banner.SetupToken, OrganizationName: "X", AdminPassword: "Very-Long-Test-Password-1!"}},
		{"invalid email", CompleteInput{SetupToken: banner.SetupToken, OrganizationName: "X", AdminEmail: "not-an-email", AdminPassword: "Very-Long-Test-Password-1!"}},
		{"short password", CompleteInput{SetupToken: banner.SetupToken, OrganizationName: "X", AdminEmail: "a@b.c", AdminPassword: "short"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.svc.Complete(context.Background(), h.dataDir, tc.in)
			if err == nil {
				t.Errorf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestComplete_ResumesAfterPartialOrg(t *testing.T) {
	// Simulate a prior partial run: the wizard previously created an
	// organization but crashed before site_admin or key. The next call
	// must reuse the existing org rather than creating a duplicate.
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)

	// Pre-seed an org (the "leftover from a prior partial complete").
	preExistingID, _ := uuid.NewRandom()
	now := time.Now().UTC()
	h.orgRepo.orgs = append(h.orgRepo.orgs, &domain.Organization{
		ID:        preExistingID,
		Name:      "Pre-existing Org",
		Domain:    "preexisting.example",
		OrgSlug:   "preexisting-org",
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	})

	out, err := h.svc.Complete(context.Background(), h.dataDir, validCompleteInput(banner.SetupToken))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.OrganizationID != preExistingID {
		t.Errorf("Complete should have reused pre-existing org id (%v), got %v", preExistingID, out.OrganizationID)
	}
	if out.OrganizationName != "Pre-existing Org" {
		t.Errorf("OrganizationName = %q; want %q", out.OrganizationName, "Pre-existing Org")
	}
	// No duplicate org created.
	orgs, _, _ := h.orgRepo.List(context.Background(), repository.OrganizationFilter{}, repository.Pagination{}, repository.Sort{})
	nonSystem := 0
	systemOrgID, _ := uuid.Parse(domain.SystemOrgID)
	for _, o := range orgs {
		if o.ID != systemOrgID {
			nonSystem++
		}
	}
	if nonSystem != 1 {
		t.Errorf("expected exactly 1 non-system org, got %d", nonSystem)
	}
}

func TestComplete_ResumesAfterPartialSiteAdmin(t *testing.T) {
	// Simulate a prior partial run where org + site_admin both landed
	// but the key generation crashed.
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)

	// Pre-seed org + site_admin.
	systemOrgID, _ := uuid.Parse(domain.SystemOrgID)
	siteAdminID, _ := uuid.Parse(domain.SiteAdminID)
	h.userRepo.users = append(h.userRepo.users, &domain.User{
		ID:             siteAdminID,
		OrganizationID: systemOrgID,
		Email:          "owner@acme.example",
		PasswordHash:   "pre-existing-hash",
		Role:           domain.RoleSiteAdmin,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})

	out, err := h.svc.Complete(context.Background(), h.dataDir, validCompleteInput(banner.SetupToken))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.State != domain.SetupStatusComplete {
		t.Errorf("State = %q; want %q", out.State, domain.SetupStatusComplete)
	}
	// Only one site_admin row — Complete must NOT duplicate.
	count := 0
	for _, u := range h.userRepo.users {
		if u.Email == "owner@acme.example" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 site_admin, got %d", count)
	}
}

func TestComplete_RejectsReplay(t *testing.T) {
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)
	_, err := h.svc.Complete(context.Background(), h.dataDir, validCompleteInput(banner.SetupToken))
	if err != nil {
		t.Fatalf("first Complete: %v", err)
	}
	_, err = h.svc.Complete(context.Background(), h.dataDir, validCompleteInput(banner.SetupToken))
	if !errors.Is(err, ErrAlreadyComplete) {
		t.Errorf("err = %v; want ErrAlreadyComplete", err)
	}
}

// --- Loud warning on stale token-file deletion failure ---------------------

func TestComplete_LogsLoudWarningWhenDeleteTokenFileFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX perm bits required to force os.Remove to fail")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 0o500 does not block file removal")
	}

	repo := newMemSetupStateRepo()
	orgRepo := newMemOrgRepoWithSystemOrg()
	userRepo := &memUserRepo{}
	keyRepo := &memKeyRepo{}

	var logBuf bytes.Buffer
	svc := New(Deps{
		Repo:       repo,
		OrgService: service.NewOrganizationService(nil, orgRepo),
		KeyService: service.NewKeyService(keyRepo),
		OrgRepo:    orgRepo,
		UserRepo:   userRepo,
		Issuer:     "http://localhost:7113",
		Logf: func(format string, args ...any) {
			fmt.Fprintf(&logBuf, format+"\n", args...)
		},
	})

	dataDir := t.TempDir()
	banner, err := svc.Initialize(context.Background(), dataDir)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if banner == nil {
		t.Fatalf("Initialize: expected banner on fresh DB")
	}

	// Strip write permission from the data dir so DeleteTokenFile fails
	// with EACCES on Linux/macOS. t.Cleanup restores perms so t.TempDir
	// can clear itself when the test ends.
	if err := os.Chmod(dataDir, 0o500); err != nil {
		t.Fatalf("chmod 0500: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o700) })

	out, err := svc.Complete(context.Background(), dataDir, validCompleteInput(banner.SetupToken))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.State != domain.SetupStatusComplete {
		t.Errorf("State = %q; want %q (Complete must still succeed even if the token file cannot be deleted)", out.State, domain.SetupStatusComplete)
	}

	got := logBuf.String()
	if !strings.Contains(strings.ToLower(got), "warn") {
		t.Errorf("expected a WARN-level log on delete failure; got %q", got)
	}
	if !strings.Contains(got, "setup-token.txt") {
		t.Errorf("warning should reference the token file path; got %q", got)
	}
	// Action-oriented guidance for the operator: tell them how to clean
	// up the stale file. The exact phrasing is intentional ("delete it
	// by hand") so the message reads as actionable in operator logs.
	if !strings.Contains(got, "delete it by hand") {
		t.Errorf("warning should be action-oriented (\"delete it by hand\"); got %q", got)
	}
}

func TestComplete_NoLoggerIsSafe(t *testing.T) {
	// Default (Logf == nil) must not panic on the success path.
	h := newHarness(t)
	banner, _ := h.svc.Initialize(context.Background(), h.dataDir)
	if _, err := h.svc.Complete(context.Background(), h.dataDir, validCompleteInput(banner.SetupToken)); err != nil {
		t.Fatalf("Complete with nil Logf: %v", err)
	}
}

// --- Banner URL fallback ----------------------------------------------------

func TestBuildSetupURL_FallsBackToIssuer(t *testing.T) {
	svc := New(Deps{
		Repo:       newMemSetupStateRepo(),
		OrgService: nil, // unused here
		Issuer:     "http://localhost:7113",
	})
	got := svc.buildSetupURL()
	if got != "http://localhost:7113/setup" {
		t.Errorf("got %q; want http://localhost:7113/setup (UIPublicBaseURL empty → use issuer)", got)
	}
}

func TestBuildSetupURL_EmptyBothMeansRelative(t *testing.T) {
	svc := New(Deps{
		Repo: newMemSetupStateRepo(),
	})
	if got := svc.buildSetupURL(); got != "/setup" {
		t.Errorf("got %q; want relative /setup", got)
	}
}
