package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// inMemoryUserRepo is the smallest UserRepository fake that
// satisfies the OSS UserService surface. Unused methods panic so a
// new dep surfaces as a test failure.
type inMemoryUserRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.User
}

func newUserRepo() *inMemoryUserRepo {
	return &inMemoryUserRepo{rows: map[uuid.UUID]*domain.User{}}
}

func (r *inMemoryUserRepo) Create(_ context.Context, u *domain.User) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[u.ID] = u
	return u, nil
}
func (r *inMemoryUserRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}
func (r *inMemoryUserRepo) FindUsersByEmail(_ context.Context, _ string) ([]*domain.User, error) {
	panic("not used")
}
func (r *inMemoryUserRepo) GetByEmailAndOrgID(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) {
	panic("not used")
}
func (r *inMemoryUserRepo) GetByExternalID(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) {
	panic("not used")
}
func (r *inMemoryUserRepo) GetByIDWithOrg(_ context.Context, _ uuid.UUID) (*domain.User, error) {
	panic("not used")
}
func (r *inMemoryUserRepo) Update(_ context.Context, id uuid.UUID, _ uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.rows[id]
	if !ok {
		return nil, nil
	}
	if opts.Email != nil {
		u.Email = *opts.Email
	}
	if opts.Password != nil {
		u.PasswordHash = *opts.Password
	}
	if opts.Banned != nil {
		u.Banned = *opts.Banned
	}
	if opts.MFAEnabled != nil {
		u.MFAEnabled = *opts.MFAEnabled
	}
	if opts.MFASecret != nil {
		s := *opts.MFASecret
		u.MFASecret = &s
	}
	if opts.MFARecoveryCodes != nil {
		u.MFARecoveryCodes = append([]string(nil), opts.MFARecoveryCodes...)
	}
	return u, nil
}
func (r *inMemoryUserRepo) Delete(_ context.Context, id uuid.UUID, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u, ok := r.rows[id]; ok {
		now := time.Now().UTC()
		u.DeletedAt = &now
	}
	return nil
}
func (r *inMemoryUserRepo) Undelete(_ context.Context, id uuid.UUID, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u, ok := r.rows[id]; ok {
		u.DeletedAt = nil
	}
	return nil
}
func (r *inMemoryUserRepo) List(_ context.Context, _ repository.ListUserOptions) ([]*domain.User, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.User, 0, len(r.rows))
	for _, v := range r.rows {
		out = append(out, v)
	}
	return out, len(out), nil
}
func (r *inMemoryUserRepo) ListByOrganization(_ context.Context, _ uuid.UUID, _ repository.ListUserOptions) ([]*domain.User, int, error) {
	return r.List(context.Background(), repository.ListUserOptions{})
}
func (r *inMemoryUserRepo) UpdateLastLogin(_ context.Context, _ uuid.UUID) error { return nil }
func (r *inMemoryUserRepo) ConsumeRecoveryCode(context.Context, uuid.UUID, string) (*domain.User, bool, error) {
	return nil, false, nil
}
func (r *inMemoryUserRepo) CountByOrganization(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, nil
}

// CountOrgAdminsByOrganization counts for real. A hardcoded 0 is weaker than
// the database and silently reads as "this org has no admins yet", which is
// precisely the predicate SITE-ADMIN-TENANT-WRITE gates the site_admin
// delegation on — a stub there would let every guarded test pass vacuously.
func (r *inMemoryUserRepo) CountOrgAdminsByOrganization(_ context.Context, orgID uuid.UUID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, u := range r.rows {
		if u == nil || u.OrganizationID != orgID {
			continue
		}
		if u.Role == domain.RoleOrgAdmin && !u.Banned && u.DeletedAt == nil {
			n++
		}
	}
	return n, nil
}
func (r *inMemoryUserRepo) CountOrgAdminsByOrganizations(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]int, error) {
	return map[uuid.UUID]int{}, nil
}
func (r *inMemoryUserRepo) CountVerifiedOrgAdminsByOrganization(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, nil
}
func (r *inMemoryUserRepo) CountVerifiedOrgAdminsByOrganizations(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]int, error) {
	return map[uuid.UUID]int{}, nil
}
func (r *inMemoryUserRepo) VerifyPassword(_ context.Context, _ string, _ string) error {
	return nil
}
func (r *inMemoryUserRepo) HashPassword(p string) (string, error) {
	return "hashed:" + p, nil
}
func (r *inMemoryUserRepo) GetUserOrganization(_ context.Context, _ uuid.UUID) (*domain.Organization, error) {
	panic("not used")
}
func (r *inMemoryUserRepo) UpdateOrganizationID(_ context.Context, _ uuid.UUID, _ uuid.UUID) error {
	return nil
}

func TestUserService_CreateHashesPassword(t *testing.T) {
	svc := NewUserService(nil, newUserRepo())
	const plaintext = "Plaintext-Password-1!"
	u, err := svc.Create(context.Background(), CreateUserOptions{
		OrganizationID: uuid.New(),
		Email:          "x@example.com",
		Password:       plaintext,
		Role:           domain.RoleOrgUser,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.PasswordHash == plaintext {
		t.Errorf("plaintext password leaked into storage")
	}
	if u.PasswordHash == "" {
		t.Errorf("password hash not set")
	}
}

func TestUserService_CreateRequiresEmailAndPassword(t *testing.T) {
	svc := NewUserService(nil, newUserRepo())
	if _, err := svc.Create(context.Background(), CreateUserOptions{Role: domain.RoleOrgUser, OrganizationID: uuid.New()}); err == nil {
		t.Error("Create with empty email/password must fail")
	}
}

func TestUserService_GetNotFound(t *testing.T) {
	svc := NewUserService(nil, newUserRepo())
	_, err := svc.GetByID(context.Background(), uuid.New())
	if !errors.Is(err, ErrUserNotFound()) {
		t.Errorf("GetByID(missing) = %v, want ErrUserNotFound", err)
	}
}

// inMemoryOrgRepo
type inMemoryOrgRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.Organization
}

func newOrgRepo() *inMemoryOrgRepo {
	return &inMemoryOrgRepo{rows: map[uuid.UUID]*domain.Organization{}}
}

func (r *inMemoryOrgRepo) Create(_ context.Context, o *domain.Organization) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[o.ID] = o
	return o, nil
}
func (r *inMemoryOrgRepo) CreateWithAdmin(_ context.Context, _ *domain.Organization, _ *domain.User) (*domain.Organization, *domain.User, error) {
	panic("not used")
}
func (r *inMemoryOrgRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}
func (r *inMemoryOrgRepo) GetByDomain(_ context.Context, _ string) (*domain.Organization, error) {
	panic("not used")
}
func (r *inMemoryOrgRepo) GetBySlug(_ context.Context, _ string) (*domain.Organization, error) {
	panic("not used")
}
func (r *inMemoryOrgRepo) Update(_ context.Context, id uuid.UUID, opts repository.UpdateOrganizationOptions) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.rows[id]
	if !ok {
		return nil, nil
	}
	if opts.Name != nil {
		o.Name = *opts.Name
	}
	if opts.Active != nil {
		o.Active = *opts.Active
	}
	return o, nil
}
func (r *inMemoryOrgRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o, ok := r.rows[id]; ok {
		now := time.Now().UTC()
		o.DeletedAt = &now
	}
	return nil
}
func (r *inMemoryOrgRepo) Undelete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o, ok := r.rows[id]; ok {
		o.DeletedAt = nil
	}
	return nil
}
func (r *inMemoryOrgRepo) List(_ context.Context, _ repository.OrganizationFilter, _ repository.Pagination, _ repository.Sort) ([]*domain.Organization, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.Organization, 0, len(r.rows))
	for _, v := range r.rows {
		out = append(out, v)
	}
	return out, len(out), nil
}
func (r *inMemoryOrgRepo) CountUsers(_ context.Context, _ uuid.UUID) (int, error) { return 0, nil }
func (r *inMemoryOrgRepo) CountSessions(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, nil
}
func (r *inMemoryOrgRepo) GetDetails(_ context.Context, _ uuid.UUID) (*domain.Organization, map[string]int, error) {
	return nil, nil, nil
}

func TestOrganizationService_CreateAppliesDefaults(t *testing.T) {
	svc := NewOrganizationService(nil, newOrgRepo())
	o, err := svc.Create(context.Background(), CreateOrganizationOptions{
		Name:   "Acme",
		Domain: "acme.com",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if o.OrgSlug != "acme" {
		t.Errorf("slug = %q, want %q", o.OrgSlug, "acme")
	}
	if o.MFAPolicy != "optional" {
		t.Errorf("mfa policy default = %q, want optional", o.MFAPolicy)
	}
	if o.MaxSessionsPerUser != 10 {
		t.Errorf("max sessions default = %d, want 10", o.MaxSessionsPerUser)
	}
}

func TestOrganizationService_Create_PasswordComplexityEnabledDefaultsTrue(t *testing.T) {
	// Secure-default pin landed 2026-06-24 PM by slice
	// agent-a-20260718-idp-oss-orgservice-create-passwordcomplexity-secure-default.
	// Pre-fix: OrganizationService.Create constructed the domain.Organization
	// struct without setting PasswordComplexityEnabled, so the Go bool
	// zero-value `false` propagated through PgxOrganizationRepository.Create's
	// positional INSERT, persisting RELAXED complexity policy. Post-fix:
	// the service sets `PasswordComplexityEnabled: true` explicitly to
	// honor the migration's `NOT NULL DEFAULT true` (strict mode) at the
	// new-org create boundary.
	svc := NewOrganizationService(nil, newOrgRepo())
	o, err := svc.Create(context.Background(), CreateOrganizationOptions{
		Name:   "Acme",
		Domain: "acme.com",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !o.PasswordComplexityEnabled {
		t.Fatalf("SECURE-DEFAULT REGRESSION: new tenant org PasswordComplexityEnabled = false; want true (Decision D-015 §9 + the migration's NOT NULL DEFAULT)")
	}
}

func TestOrganizationService_CreateRequiresNameDomain(t *testing.T) {
	svc := NewOrganizationService(nil, newOrgRepo())
	if _, err := svc.Create(context.Background(), CreateOrganizationOptions{}); err == nil {
		t.Error("Create(empty) must fail")
	}
}

func TestOrganizationService_GetNotFound(t *testing.T) {
	svc := NewOrganizationService(nil, newOrgRepo())
	_, err := svc.GetByID(context.Background(), uuid.New())
	if !errors.Is(err, ErrOrganizationNotFound()) {
		t.Errorf("GetByID(missing) = %v, want ErrOrganizationNotFound", err)
	}
}

// inMemoryOrgDomainRepo
type inMemoryOrgDomainRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.OrganizationDomain
}

func newOrgDomainRepo() *inMemoryOrgDomainRepo {
	return &inMemoryOrgDomainRepo{rows: map[uuid.UUID]*domain.OrganizationDomain{}}
}

func (r *inMemoryOrgDomainRepo) CreateOrganizationDomain(_ context.Context, d *domain.OrganizationDomain) (*domain.OrganizationDomain, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[d.ID] = d
	return d, nil
}
func (r *inMemoryOrgDomainRepo) GetOrganizationDomainByID(_ context.Context, id uuid.UUID) (*domain.OrganizationDomain, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}
func (r *inMemoryOrgDomainRepo) ListOrganizationDomainsByOrganization(_ context.Context, orgID uuid.UUID) ([]*domain.OrganizationDomain, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.OrganizationDomain, 0)
	for _, v := range r.rows {
		if v.OrganizationID == orgID {
			out = append(out, v)
		}
	}
	return out, nil
}
func (r *inMemoryOrgDomainRepo) GetVerifiedOrganizationDomainByDomain(_ context.Context, _ string) (*domain.OrganizationDomain, error) {
	return nil, nil
}
func (r *inMemoryOrgDomainRepo) SetOrganizationDomainVerified(_ context.Context, id uuid.UUID, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.rows[id]; ok {
		v.VerifiedAt = &at
		v.VerificationTokenHash = nil
		v.VerificationTokenExpiresAt = nil
	}
	return nil
}
func (r *inMemoryOrgDomainRepo) IncrementOrganizationDomainVerificationAttempts(_ context.Context, id, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.rows[id]; ok {
		v.VerificationAttempts++
	}
	return nil
}
func (r *inMemoryOrgDomainRepo) DeleteOrganizationDomain(_ context.Context, id, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, id)
	return nil
}
func (r *inMemoryOrgDomainRepo) SetPrimaryOrganizationDomain(_ context.Context, id, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.rows {
		v.IsPrimary = false
	}
	if v, ok := r.rows[id]; ok {
		v.IsPrimary = true
	}
	return nil
}

type fakeVerifier struct{ err error }

func (v fakeVerifier) Verify(_ context.Context, _, _ string) error { return v.err }

func TestOrganizationDomainService_AddReturnsOneTimeRawToken(t *testing.T) {
	svc := NewOrganizationDomainService(nil, newOrgDomainRepo(), nil)
	orgID := uuid.New()
	row, raw, err := svc.AddOrganizationDomain(context.Background(), orgID, "Example.COM")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if raw == "" {
		t.Errorf("raw token must be returned once on Add")
	}
	if row.VerificationTokenHash == nil || *row.VerificationTokenHash == "" {
		t.Errorf("hash must be persisted")
	}
	if row.VerificationTokenHash != nil && *row.VerificationTokenHash == raw {
		t.Errorf("persisted value must be hash, not raw token")
	}
	if row.Domain != "example.com" {
		t.Errorf("domain not normalized: %q", row.Domain)
	}
}

func TestOrganizationDomainService_VerifyFailsClosedWithoutVerifier(t *testing.T) {
	svc := NewOrganizationDomainService(nil, newOrgDomainRepo(), nil)
	orgID := uuid.New()
	row, _, _ := svc.AddOrganizationDomain(context.Background(), orgID, "example.com")
	err := svc.Verify(context.Background(), row.ID, orgID)
	if !errors.Is(err, ErrDomainVerifierUnavailable) {
		t.Errorf("Verify without verifier = %v, want ErrDomainVerifierUnavailable", err)
	}
}

func TestOrganizationDomainService_VerifySuccessFlipsRow(t *testing.T) {
	repo := newOrgDomainRepo()
	svc := NewOrganizationDomainService(nil, repo, fakeVerifier{err: nil})
	orgID := uuid.New()
	row, _, _ := svc.AddOrganizationDomain(context.Background(), orgID, "example.com")
	if err := svc.Verify(context.Background(), row.ID, orgID); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	updated := repo.rows[row.ID]
	if !updated.IsVerified() {
		t.Errorf("row not flipped to verified")
	}
	if updated.VerificationTokenHash != nil {
		t.Errorf("verified row must clear token hash")
	}
}

func TestOrganizationDomainService_VerifyFailsOnWrongOrg(t *testing.T) {
	svc := NewOrganizationDomainService(nil, newOrgDomainRepo(), fakeVerifier{err: nil})
	orgID := uuid.New()
	row, _, _ := svc.AddOrganizationDomain(context.Background(), orgID, "example.com")
	other := uuid.New()
	err := svc.Verify(context.Background(), row.ID, other)
	if !errors.Is(err, ErrOrganizationDomainNotFound()) {
		t.Errorf("cross-tenant Verify = %v, want ErrOrganizationDomainNotFound", err)
	}
}

// ---------- PasswordComplexityEnabled per-org enforcement ----------
//
// Tests below pin the contract from slice
// agent-a-20260715-idp-oss-password-complexity-perorg-enforcement
// (Decision D-015 §9). UserService.Create + Update consult the
// per-org PasswordComplexityEnabled flag through CreateUserOptions /
// UpdateUserOptions. nil ⇒ STRICT mode (safe default). The
// strictness mirrors domain.ValidatePasswordPolicy's character-class
// requirements.

func complexityPtr(b bool) *bool { return &b }

func TestUserService_Create_PerOrgComplexityEnabledRejectsWeakPassword(t *testing.T) {
	svc := NewUserService(nil, newUserRepo())
	_, err := svc.Create(context.Background(), CreateUserOptions{
		OrganizationID:            uuid.New(),
		Email:                     "y@example.com",
		Password:                  "longenoughpw", // length-passes-but-no-class-diversity
		Role:                      domain.RoleOrgUser,
		PasswordComplexityEnabled: complexityPtr(true),
	})
	if err == nil {
		t.Fatal("complexityEnabled=true MUST reject longenoughpw (no upper/digit/special)")
	}
}

func TestUserService_Create_PerOrgComplexityDisabledAcceptsWeakButLongEnoughPassword(t *testing.T) {
	svc := NewUserService(nil, newUserRepo())
	_, err := svc.Create(context.Background(), CreateUserOptions{
		OrganizationID:            uuid.New(),
		Email:                     "y@example.com",
		Password:                  "longenoughpw",
		Role:                      domain.RoleOrgUser,
		PasswordComplexityEnabled: complexityPtr(false),
	})
	if err != nil {
		t.Fatalf("complexityEnabled=false MUST accept longenoughpw, got %v", err)
	}
}

func TestUserService_Create_TooShortRejectedRegardlessOfComplexity(t *testing.T) {
	for _, complex := range []*bool{complexityPtr(true), complexityPtr(false), nil} {
		svc := NewUserService(nil, newUserRepo())
		_, err := svc.Create(context.Background(), CreateUserOptions{
			OrganizationID:            uuid.New(),
			Email:                     "y@example.com",
			Password:                  "short",
			Role:                      domain.RoleOrgUser,
			PasswordComplexityEnabled: complex,
		})
		if err == nil {
			t.Fatalf("complexityEnabled=%v MUST reject 'short' (length floor)", complex)
		}
	}
}

func TestUserService_Create_NilComplexityDefaultsToStrict(t *testing.T) {
	// nil ⇒ STRICT mode (safe default for backward-compat).
	svc := NewUserService(nil, newUserRepo())
	_, err := svc.Create(context.Background(), CreateUserOptions{
		OrganizationID: uuid.New(),
		Email:          "y@example.com",
		Password:       "longenoughpw", // no class diversity
		Role:           domain.RoleOrgUser,
		// PasswordComplexityEnabled: nil
	})
	if err == nil {
		t.Fatal("nil PasswordComplexityEnabled MUST default to STRICT mode and reject longenoughpw")
	}
}

func TestUserService_Update_PerOrgComplexityEnforced(t *testing.T) {
	svc := NewUserService(nil, newUserRepo())
	created, err := svc.Create(context.Background(), CreateUserOptions{
		OrganizationID:            uuid.New(),
		Email:                     "z@example.com",
		Password:                  "Strong-Password-1!",
		Role:                      domain.RoleOrgUser,
		PasswordComplexityEnabled: complexityPtr(true),
	})
	if err != nil {
		t.Fatalf("setup Create: %v", err)
	}
	weak := "longenoughpw"
	_, err = svc.Update(context.Background(), created.ID, created.OrganizationID, UpdateUserOptions{
		Password:                  &weak,
		PasswordComplexityEnabled: complexityPtr(true),
	})
	if err == nil {
		t.Fatal("Update with complexityEnabled=true MUST reject weak password")
	}
	// Update WITHOUT a password field MUST NOT consult complexity
	// (no-op for users updating only name/email/etc.).
	newName := "renamed"
	_, err = svc.Update(context.Background(), created.ID, created.OrganizationID, UpdateUserOptions{
		Name:                      &newName,
		PasswordComplexityEnabled: complexityPtr(true),
	})
	if err != nil {
		t.Fatalf("Update without Password MUST NOT enforce complexity, got %v", err)
	}
}
