package main

// Unit tests for the bootstrap subcommand. These exercise the pure
// state-machine half (bootstrapCore + loadBootstrapOptions) using
// in-memory repository fakes. The pgxpool plumbing in runBootstrap
// is covered by the existing integration harness path; here we focus
// on:
//
//   1. Idempotency on both halves (key + user).
//   2. Sentinel UUID pinning (created user.ID == domain.SiteAdminID).
//   3. Env-var validation including the algorithm allowlist.
//   4. No-leak invariants on stdout/stderr (password/PHC-hash absence).
//
// The in-memory fakes are deliberately the smallest viable
// implementations of the repository interfaces. The bootstrap code
// path only calls a 4-method subset; other interface methods return
// the zero value for completeness and to satisfy the type system.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// --- in-memory KeyRepository -----------------------------------------------

type memKeyRepo struct {
	keys []domain.SigningKey
}

func (m *memKeyRepo) GetActiveSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	out := make([]domain.SigningKey, 0, len(m.keys))
	for _, k := range m.keys {
		if k.State == domain.KeyStateActive || k.State == domain.KeyStateRotating {
			out = append(out, k)
		}
	}
	return out, nil
}
func (m *memKeyRepo) GetAllSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	return append([]domain.SigningKey(nil), m.keys...), nil
}
func (m *memKeyRepo) GetSigningKeyByKID(_ context.Context, kid string) (*domain.SigningKey, error) {
	for i := range m.keys {
		if m.keys[i].KID == kid {
			k := m.keys[i]
			return &k, nil
		}
	}
	return nil, errors.New("test fake: key not found")
}
func (m *memKeyRepo) CreateSigningKey(_ context.Context, key *domain.SigningKey) error {
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

// --- in-memory UserRepository ---------------------------------------------

type memUserRepo struct {
	users []*domain.User
}

func (m *memUserRepo) Create(_ context.Context, u *domain.User) (*domain.User, error) {
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
	for _, u := range m.users {
		if u.Email == email && u.OrganizationID == orgID {
			out := *u
			return &out, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

// Everything below is unused by bootstrapCore but required by the
// repository.UserRepository interface contract.
func (m *memUserRepo) GetByID(_ context.Context, _ uuid.UUID) (*domain.User, error) {
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
func (m *memUserRepo) Update(_ context.Context, id uuid.UUID, orgID uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	// Partial-update semantics matching the production PgxUserRepository:
	// any non-nil field in opts overwrites the stored value; nil fields
	// are preserved. Plaintext passwords are stored as-is (the test does
	// not care what the hash looks like — see HashPassword below).
	for _, u := range m.users {
		if u.ID != id || u.OrganizationID != orgID {
			continue
		}
		if opts.Password != nil {
			u.PasswordHash = *opts.Password
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
		if opts.RequiresPasswordChange != nil {
			u.RequiresPasswordChange = *opts.RequiresPasswordChange
		}
		if opts.Email != nil {
			u.Email = *opts.Email
		}
		if opts.Role != nil {
			u.Role = *opts.Role
		}
		if opts.EmailVerified != nil {
			u.EmailVerified = *opts.EmailVerified
		}
		if opts.Banned != nil {
			u.Banned = *opts.Banned
		}
		if opts.AuthSource != nil {
			u.AuthSource = *opts.AuthSource
		}
		out := *u
		return &out, nil
	}
	return nil, domain.ErrUserNotFound
}
func (m *memUserRepo) Delete(_ context.Context, _ uuid.UUID, _ uuid.UUID) error   { return nil }
func (m *memUserRepo) Undelete(_ context.Context, _ uuid.UUID, _ uuid.UUID) error { return nil }
func (m *memUserRepo) List(_ context.Context, _ repository.ListUserOptions) ([]*domain.User, int, error) {
	return nil, 0, nil
}
func (m *memUserRepo) ListByOrganization(_ context.Context, _ uuid.UUID, _ repository.ListUserOptions) ([]*domain.User, int, error) {
	return nil, 0, nil
}
func (m *memUserRepo) UpdateLastLogin(_ context.Context, _ uuid.UUID) error { return nil }
func (m *memUserRepo) ConsumeRecoveryCode(context.Context, uuid.UUID, string) (*domain.User, bool, error) {
	return nil, false, nil
}
func (m *memUserRepo) CountByOrganization(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, nil
}
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
func (m *memUserRepo) UpdateOrganizationID(_ context.Context, _ uuid.UUID, _ uuid.UUID) error {
	return nil
}
func (m *memUserRepo) HashPassword(s string) (string, error) {
	// Identity hash is enough for the bootstrap test — the production
	// path runs through internal/crypto.GenerateHash, which is what
	// PgxUserRepository.Create invokes when the field is not already
	// PHC-encoded. The test does not care what the hash looks like.
	return s, nil
}

var _ repository.KeyRepository = (*memKeyRepo)(nil)
var _ repository.UserRepository = (*memUserRepo)(nil)

// --- loadBootstrapOptions tests --------------------------------------------

func TestLoadBootstrapOptions(t *testing.T) {
	t.Parallel()

	t.Run("password required", func(t *testing.T) {
		t.Parallel()
		_, err := loadBootstrapOptions(func(string) string { return "" })
		if err == nil || !strings.Contains(err.Error(), envBootstrapPassword) {
			t.Fatalf("expected error mentioning %s, got %v", envBootstrapPassword, err)
		}
	})

	t.Run("defaults applied when only password set", func(t *testing.T) {
		t.Parallel()
		got, err := loadBootstrapOptions(func(k string) string {
			if k == envBootstrapPassword {
				return "Demo-Only-Not-Printed-1!"
			}
			return ""
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Email != domain.SiteAdminEmail {
			t.Fatalf("expected default email %q, got %q", domain.SiteAdminEmail, got.Email)
		}
		if got.Algorithm != domain.KeyAlgorithmEdDSA {
			t.Fatalf("expected default EdDSA, got %q", got.Algorithm)
		}
	})

	t.Run("algorithm allowlist accepts ES256", func(t *testing.T) {
		t.Parallel()
		got, err := loadBootstrapOptions(func(k string) string {
			switch k {
			case envBootstrapPassword:
				return "Demo-Only-Strong-1!"
			case envBootstrapAlgorithm:
				return "ES256"
			}
			return ""
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Algorithm != domain.KeyAlgorithmES256 {
			t.Fatalf("expected ES256, got %q", got.Algorithm)
		}
	})

	t.Run("algorithm allowlist rejects RS256", func(t *testing.T) {
		t.Parallel()
		_, err := loadBootstrapOptions(func(k string) string {
			switch k {
			case envBootstrapPassword:
				return "Demo-Only-Strong-1!"
			case envBootstrapAlgorithm:
				return "RS256"
			}
			return ""
		})
		if err == nil {
			t.Fatal("expected algorithm allowlist to reject RS256")
		}
		if !strings.Contains(err.Error(), envBootstrapAlgorithm) {
			t.Fatalf("expected error mentioning env var name, got %v", err)
		}
	})
}

// --- bootstrapCore tests ---------------------------------------------------

func newTestOpts() bootstrapOptions {
	return bootstrapOptions{
		Email:     domain.SiteAdminEmail,
		Password:  "Demo-Only-Not-Printed-Anywhere-1!",
		Algorithm: domain.KeyAlgorithmEdDSA,
	}
}

// RULE: SA-IN-SYSORG-1
func TestBootstrapCore_FreshDatabase(t *testing.T) {
	t.Parallel()

	deps := bootstrapDeps{
		Keys:  &memKeyRepo{},
		Users: &memUserRepo{},
	}
	var stdout, stderr bytes.Buffer

	rc := bootstrapCore(context.Background(), deps, newTestOpts(), &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("expected rc=0, got %d (stderr=%s)", rc, stderr.String())
	}

	if got := stdout.String(); !strings.Contains(got, "created signing key") {
		t.Fatalf("expected signing-key creation log, got %q", got)
	}
	if got := stdout.String(); !strings.Contains(got, "created site_admin") {
		t.Fatalf("expected site_admin creation log, got %q", got)
	}

	users := deps.Users.(*memUserRepo).users
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].ID.String() != domain.SiteAdminID {
		t.Fatalf("expected SiteAdminID sentinel, got %s", users[0].ID)
	}
	if users[0].OrganizationID.String() != domain.SystemOrgID {
		t.Fatalf("expected SystemOrgID, got %s", users[0].OrganizationID)
	}
	if users[0].Role != domain.RoleSiteAdmin {
		t.Fatalf("expected RoleSiteAdmin, got %q", users[0].Role)
	}
	if !users[0].EmailVerified {
		t.Fatal("expected EmailVerified=true on bootstrap user")
	}
	if users[0].AuthSource != domain.AuthSourceLocal {
		t.Fatalf("expected AuthSourceLocal, got %q", users[0].AuthSource)
	}

	keys := deps.Keys.(*memKeyRepo).keys
	if len(keys) != 1 {
		t.Fatalf("expected 1 signing key, got %d", len(keys))
	}
	if keys[0].Algorithm != domain.KeyAlgorithmEdDSA {
		t.Fatalf("expected EdDSA, got %q", keys[0].Algorithm)
	}
	if keys[0].State != domain.KeyStateActive {
		t.Fatalf("expected KeyStateActive, got %q", keys[0].State)
	}
}

// RULE: SA-SINGLETON-1
func TestBootstrapCore_Idempotent(t *testing.T) {
	t.Parallel()

	deps := bootstrapDeps{
		Keys:  &memKeyRepo{},
		Users: &memUserRepo{},
	}

	for i := range 3 {
		var stdout, stderr bytes.Buffer
		rc := bootstrapCore(context.Background(), deps, newTestOpts(), &stdout, &stderr)
		if rc != 0 {
			t.Fatalf("invocation %d: expected rc=0, got %d (stderr=%s)", i, rc, stderr.String())
		}
		if i > 0 {
			out := stdout.String()
			if !strings.Contains(out, "signing key already present") {
				t.Fatalf("invocation %d: expected 'signing key already present', got %q", i, out)
			}
			if !strings.Contains(out, "site_admin already present") {
				t.Fatalf("invocation %d: expected 'site_admin already present', got %q", i, out)
			}
		}
	}

	if got := len(deps.Keys.(*memKeyRepo).keys); got != 1 {
		t.Fatalf("expected exactly 1 signing key after 3 invocations, got %d", got)
	}
	if got := len(deps.Users.(*memUserRepo).users); got != 1 {
		t.Fatalf("expected exactly 1 user after 3 invocations, got %d", got)
	}
}

func TestBootstrapCore_NeverLeaksPassword(t *testing.T) {
	t.Parallel()

	const secret = "demo-password-marker-zzz-not-printed"
	opts := newTestOpts()
	opts.Password = secret

	deps := bootstrapDeps{
		Keys:  &memKeyRepo{},
		Users: &memUserRepo{},
	}
	var stdout, stderr bytes.Buffer
	rc := bootstrapCore(context.Background(), deps, opts, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("expected rc=0, got %d", rc)
	}

	// PREMISE: a successful bootstrap PRINTS (key + site_admin confirmations
	// on every rc=0 path). An empty transcript contains no password by
	// definition, so without this the sweep below proves nothing (V4).
	if stdout.Len() == 0 {
		t.Fatalf("bootstrap printed nothing — an empty transcript cannot leak, so the sweep below would pass vacuously")
	}
	for name, buf := range map[string]*bytes.Buffer{"stdout": &stdout, "stderr": &stderr} {
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("%s contained bootstrap password marker", name)
		}
	}
}

func TestBootstrapCore_CustomEmail(t *testing.T) {
	t.Parallel()

	opts := newTestOpts()
	opts.Email = "ops-demo@system.local"

	deps := bootstrapDeps{
		Keys:  &memKeyRepo{},
		Users: &memUserRepo{},
	}
	var stdout, stderr bytes.Buffer
	rc := bootstrapCore(context.Background(), deps, opts, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("expected rc=0, got %d (stderr=%s)", rc, stderr.String())
	}

	users := deps.Users.(*memUserRepo).users
	if len(users) != 1 || users[0].Email != opts.Email {
		t.Fatalf("expected single user with email %q, got %+v", opts.Email, users)
	}
	if users[0].ID.String() != domain.SiteAdminID {
		t.Fatalf("expected SiteAdminID sentinel even with custom email, got %s", users[0].ID)
	}
}

// resolveSigningKeyCipher falls back to the key the appliance persisted in
// the data volume when the environment carries none — the break-glass path
// for `docker exec` against a distroless container whose key was generated
// at first boot and lives only in the file.
func TestResolveSigningKeyCipher_FileFallback(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "")
	t.Setenv("AUTH_SERVICE_ENCRYPTION_KEY", "")

	t.Run("reads the appliance key file", func(t *testing.T) {
		dir := t.TempDir()
		key := strings.Repeat("ab", 32) // 32-byte hex
		if err := os.WriteFile(filepath.Join(dir, "encryption-key"), []byte(key+"\n"), 0o600); err != nil {
			t.Fatalf("write key file: %v", err)
		}
		t.Setenv("IDENTUUM_IDP_DATA_DIR", dir)
		cipher, err := resolveSigningKeyCipher()
		if err != nil {
			t.Fatalf("file-backed key must resolve: %v", err)
		}
		if cipher == nil {
			t.Fatal("nil cipher with nil error")
		}
	})
	t.Run("env still wins over the file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "encryption-key"),
			[]byte("not-hex-so-a-file-read-would-error"), 0o600); err != nil {
			t.Fatalf("write decoy: %v", err)
		}
		t.Setenv("IDENTUUM_IDP_DATA_DIR", dir)
		t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", strings.Repeat("cd", 32))
		if _, err := resolveSigningKeyCipher(); err != nil {
			t.Fatalf("env key must win and resolve: %v", err)
		}
	})
	t.Run("nothing anywhere names both sources", func(t *testing.T) {
		t.Setenv("IDENTUUM_IDP_DATA_DIR", t.TempDir()) // empty dir, no key file
		_, err := resolveSigningKeyCipher()
		if err == nil {
			t.Fatal("no env and no file must refuse")
		}
		for _, want := range []string{"IDENTUUM_IDP_ENCRYPTION_KEY", "encryption-key"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("refusal must name %q; got: %v", want, err)
			}
		}
	})
}

// fakeSetupCompleter records whether bootstrap marked the setup-state row
// complete (WIZARD-SPLIT-BRAIN-1).
type fakeSetupCompleter struct {
	ensured  bool
	complete bool
}

func (f *fakeSetupCompleter) EnsureRow(_ context.Context) error { f.ensured = true; return nil }
func (f *fakeSetupCompleter) MarkComplete(_ context.Context, _ time.Time) error {
	f.complete = true
	return nil
}

// WIZARD-SPLIT-BRAIN-1: bootstrap creates a site_admin + signing key, so it
// MUST leave the setup-state row COMPLETE — a bootstrapped database that stays
// setup_required while a site_admin exists is the split-brain the wizard then
// silently discards credentials into. devseed calls bootstrap, so this is what
// stops devseed manufacturing that state.
// RULE: BOOTSTRAP-SETUP-COHERENT-1
func TestBootstrapCore_MarksSetupComplete(t *testing.T) {
	t.Parallel()

	setup := &fakeSetupCompleter{}
	deps := bootstrapDeps{
		Keys:  &memKeyRepo{},
		Users: &memUserRepo{},
		Setup: setup,
	}
	var stdout, stderr bytes.Buffer
	if rc := bootstrapCore(context.Background(), deps, newTestOpts(), &stdout, &stderr); rc != 0 {
		t.Fatalf("expected rc=0, got %d (stderr=%s)", rc, stderr.String())
	}
	if !setup.complete {
		t.Fatal("bootstrap created a site_admin but did NOT mark setup complete — this is the split-brain devseed manufactured (state setup_required + site_admin present)")
	}
}
