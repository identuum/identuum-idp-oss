package setup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Product identifiers surfaced through GET /api/setup/status. The UI
// distinguishes OSS vs CE deployments by this exact value; do not
// localise or pluralise.
const (
	ProductOSS      = "identuum-idp-oss"
	DistributionOSS = "oss"
)

// Errors returned by the Service. Handlers map them to specific HTTP
// status codes (see internal/api/setup_routes.go).
var (
	// ErrAlreadyComplete is returned by Complete (and the verify-token
	// path) when setup has already succeeded. Handlers map this to 410
	// Gone so the wizard cannot accidentally re-run.
	ErrAlreadyComplete = errors.New("setup: already complete")

	// ErrTokenFileMissing is returned by Initialize when the database
	// holds a token hash but the on-disk plaintext file is gone (e.g.
	// the data volume was wiped). The startup path treats this as
	// "regenerate" — see Initialize's behaviour.
	ErrTokenFileMissing = errors.New("setup: token file missing while hash present")
)

// Repository is the narrow data interface the Service depends on.
// Constructed against PgxSetupStateRepository in production.
type Repository interface {
	Get(ctx context.Context) (*domain.SetupState, error)
	EnsureRow(ctx context.Context) error
	UpdateTokenHash(ctx context.Context, hash string, createdAt time.Time) error
	MarkComplete(ctx context.Context, at time.Time) error
}

// SetupBanner is returned by Initialize while status == setup_required.
// The boot code logs it once per startup; it is also the basis for
// the no-secrets-in-response GET /api/setup/status hints.
type SetupBanner struct {
	SetupURL        string
	SetupToken      string // plaintext — caller MUST treat as a credential
	TokenFilePath   string
	ShowCodeCommand string
}

// StatusView is the serialisable shape returned by /api/setup/status.
// It carries no secrets — explicitly no token, no token hash, no DB URL,
// no signing key material.
type StatusView struct {
	State                   string `json:"state"`
	SetupComplete           bool   `json:"setup_complete"`
	SetupTokenRequired      bool   `json:"setup_token_required"`
	Product                 string `json:"product"`
	Distribution            string `json:"distribution"`
	Issuer                  string `json:"issuer,omitempty"`
	FirstSigningKeyExists   bool   `json:"first_signing_key_exists"`
	SiteAdminExists         bool   `json:"site_admin_exists"`
	FirstOrganizationExists bool   `json:"first_organization_exists"`
	NextAction              string `json:"next_action"`
}

// CompleteInput captures the wizard form submission. The password is
// the operator-supplied plaintext; the user repository argon2id-hashes
// it on insert (same path as the --bootstrap CLI).
type CompleteInput struct {
	SetupToken         string
	OrganizationName   string
	OrganizationDomain string // optional; defaults to slug(OrganizationName) + ".local"
	AdminEmail         string
	AdminPassword      string
}

// CompleteOutput is the wizard's success body. No secrets.
type CompleteOutput struct {
	State            string    `json:"state"`
	OrganizationID   uuid.UUID `json:"organization_id"`
	OrganizationName string    `json:"organization_name"`
	// AdminEmail is the operator's typed address (demoted to contact detail).
	AdminEmail string `json:"admin_email"`
	// LoginEmail is the PINNED site_admin login — the identity the operator
	// must actually log in as (site_admin@system.local), which is NOT the
	// address they typed (WIZARD-SPLIT-BRAIN-1: the completion screen has to
	// state who to log in as, or the next login uses the wrong identity).
	LoginEmail string `json:"login_email"`
}

// Deps bundles every collaborator. The Service is intentionally
// concrete-typed against the existing OSS services + repositories so
// the future "single transactional setup" hardening pass can introduce
// a transactional handle without breaking the API.
type Deps struct {
	Repo            Repository
	OrgService      *service.OrganizationService
	KeyService      *service.KeyService
	OrgRepo         repository.OrganizationRepository
	UserRepo        repository.UserRepository
	Issuer          string
	UIPublicBaseURL string // optional — preferred for SetupURL when set
	Now             func() time.Time
	// Logf is an optional structured-log sink used by Complete to surface
	// a loud, action-oriented warning when the post-completion
	// DeleteTokenFile sweep fails. The runtime wires it to its stderr
	// writer; tests pass a buffer. Nil is safe — the warning is dropped.
	// The DB state is already 'setup_complete' and the hash is cleared
	// before this is called, so the warning is the only signal a stale
	// plaintext file is sitting on disk. The show-setup-code subcommand
	// remains safe because it consults the DB first.
	Logf func(format string, args ...any)
}

// Service implements the appliance setup state machine.
type Service struct {
	deps Deps
}

// New constructs a Service. The caller is responsible for wiring real
// services + repos; the Service itself does no DB connection management.
func New(deps Deps) *Service {
	if deps.Now == nil {
		deps.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{deps: deps}
}

// Initialize is called once at boot, after migrations run. It guarantees
// the setup-state row exists, generates a fresh token if one is needed,
// and writes the plaintext to $DATA_DIR/setup-token.txt. Returns a
// non-nil banner when status == setup_required so the caller can log it
// (URL + token + show-code command); returns (nil, nil) when setup is
// already complete.
//
// Re-boot behaviour while status == setup_required:
//   - hash present + file present + match → reuse the existing token
//     (operator continues to see the same code on every boot)
//   - hash present + file missing OR mismatched → regenerate. Drops
//     any in-flight wizard session but keeps the appliance usable.
//   - hash absent (fresh DB) → generate.
func (s *Service) Initialize(ctx context.Context, dataDir string) (*SetupBanner, error) {
	if err := s.deps.Repo.EnsureRow(ctx); err != nil {
		return nil, fmt.Errorf("setup initialize: ensure row: %w", err)
	}
	state, err := s.deps.Repo.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("setup initialize: get state: %w", err)
	}

	if state.IsComplete() {
		// Defensive cleanup: in case a prior process crashed after
		// MarkComplete but before DeleteTokenFile, sweep it now.
		_ = DeleteTokenFile(dataDir)
		return nil, nil
	}

	// status == setup_required from here on.
	plaintext, needRegen := s.resolveExistingToken(state, dataDir)
	if needRegen {
		var newHash string
		var newPlain string
		newPlain, newHash, err = GenerateToken()
		if err != nil {
			return nil, fmt.Errorf("setup initialize: generate token: %w", err)
		}
		if _, err := WriteTokenFile(dataDir, newPlain); err != nil {
			return nil, fmt.Errorf("setup initialize: write token file: %w", err)
		}
		if err := s.deps.Repo.UpdateTokenHash(ctx, newHash, s.deps.Now()); err != nil {
			return nil, fmt.Errorf("setup initialize: persist token hash: %w", err)
		}
		plaintext = newPlain
	}

	return &SetupBanner{
		SetupURL:        s.buildSetupURL(),
		SetupToken:      plaintext,
		TokenFilePath:   TokenFilePath(dataDir),
		ShowCodeCommand: fmt.Sprintf("identuum-idp show-setup-code %s", dataDir),
	}, nil
}

// resolveExistingToken inspects the DB hash + on-disk file and reports
// whether a regeneration is required, along with the plaintext to use
// if no regeneration is needed.
func (s *Service) resolveExistingToken(state *domain.SetupState, dataDir string) (plaintext string, needRegen bool) {
	if state.SetupTokenHash == "" {
		return "", true
	}
	candidate, err := ReadTokenFile(dataDir)
	if err != nil {
		return "", true
	}
	if !VerifyToken(candidate, state.SetupTokenHash) {
		return "", true
	}
	return candidate, false
}

// buildSetupURL picks the most operator-friendly base URL we have:
// the UI public base if configured (e.g. https://idp.example.com), else
// the issuer (which doubles as the IDP base URL in the OSS stack). The
// wizard always lives at the `/setup` path.
func (s *Service) buildSetupURL() string {
	base := strings.TrimRight(s.deps.UIPublicBaseURL, "/")
	if base == "" {
		base = strings.TrimRight(s.deps.Issuer, "/")
	}
	if base == "" {
		return "/setup"
	}
	return base + "/setup"
}

// Status returns the no-secrets snapshot for GET /api/setup/status. It
// is safe to expose unauthenticated. The booleans let the UI render an
// accurate progress hint after a partial completion.
func (s *Service) Status(ctx context.Context) (*StatusView, error) {
	state, err := s.deps.Repo.Get(ctx)
	if err != nil {
		return nil, err
	}

	siteAdminExists, err := s.siteAdminPresent(ctx)
	if err != nil {
		return nil, err
	}
	orgExists, err := s.firstOrganizationPresent(ctx)
	if err != nil {
		return nil, err
	}
	keyExists, err := s.firstSigningKeyPresent(ctx)
	if err != nil {
		return nil, err
	}

	view := &StatusView{
		State:                   state.Status,
		SetupComplete:           state.IsComplete(),
		SetupTokenRequired:      !state.IsComplete(),
		Product:                 ProductOSS,
		Distribution:            DistributionOSS,
		Issuer:                  s.deps.Issuer,
		FirstSigningKeyExists:   keyExists,
		SiteAdminExists:         siteAdminExists,
		FirstOrganizationExists: orgExists,
	}
	view.NextAction = nextActionHint(view)
	return view, nil
}

// nextActionHint is the human-readable suggestion the UI surfaces in
// the wizard intro. Kept here so server + UI never disagree on copy.
func nextActionHint(v *StatusView) string {
	if v.SetupComplete {
		return "Setup is complete. Use the login page to sign in."
	}
	if !v.SiteAdminExists || !v.FirstOrganizationExists || !v.FirstSigningKeyExists {
		return "Open the setup wizard and submit the first organization, the site administrator credentials, and the setup code from the data-volume file."
	}
	return "Setup is partially complete. Re-run the wizard to finalize."
}

// VerifyToken checks the supplied plaintext against the currently-stored
// hash. Returns ErrAlreadyComplete (caller maps to 410 Gone) once setup
// has finished. ErrTokenInvalid (caller maps to 401) on mismatch.
func (s *Service) VerifyToken(ctx context.Context, plaintext string) error {
	state, err := s.deps.Repo.Get(ctx)
	if err != nil {
		return err
	}
	if state.IsComplete() {
		return ErrAlreadyComplete
	}
	if !VerifyToken(plaintext, state.SetupTokenHash) {
		return ErrTokenInvalid
	}
	return nil
}

// Complete runs the full first-run flow. Order is deliberate:
//
//  1. Verify the setup token. Bail before mutating anything on failure.
//  2. Find or create the first non-system organization.
//  3. Find or create the site_admin user pinned at SiteAdminID.
//  4. Generate the first EdDSA signing key if none active.
//  5. MarkComplete (flips status, clears hash) — this is the LAST DB
//     write so a crash anywhere above leaves status == setup_required
//     and the next call resumes from the same step.
//  6. Delete the token file. Failure here is non-fatal: the DB state
//     is already complete and the hash is cleared, so the orphan file
//     is harmless. Operators see a warning to clean it up by hand.
//
// dataDir is needed only for step 6.
func (s *Service) Complete(ctx context.Context, dataDir string, in CompleteInput) (*CompleteOutput, error) {
	state, err := s.deps.Repo.Get(ctx)
	if err != nil {
		return nil, err
	}
	if state.IsComplete() {
		return nil, ErrAlreadyComplete
	}
	if !VerifyToken(in.SetupToken, state.SetupTokenHash) {
		return nil, ErrTokenInvalid
	}
	if err := validateCompleteInput(in); err != nil {
		return nil, err
	}

	// Step 2: organization.
	orgID, orgName, err := s.ensureFirstOrganization(ctx, in)
	if err != nil {
		return nil, err
	}

	// Step 3: site_admin.
	if err := s.ensureSiteAdmin(ctx, orgID, in); err != nil {
		return nil, err
	}

	// Step 4: signing key.
	if err := s.ensureFirstSigningKey(ctx); err != nil {
		return nil, err
	}

	// Step 5: flip status.
	if err := s.deps.Repo.MarkComplete(ctx, s.deps.Now()); err != nil {
		return nil, fmt.Errorf("setup complete: mark complete: %w", err)
	}

	// Step 6: delete token file. Non-fatal — the DB state is already
	// 'setup_complete' and the hash is cleared. A leftover plaintext
	// file is reported via a loud warning so the operator can clean it
	// up by hand; the show-setup-code subcommand refuses to print it
	// because it consults the DB first (see
	// cmd/identuum-idp/setup_show_code.go).
	if err := DeleteTokenFile(dataDir); err != nil {
		s.warnTokenFileSweepFailed(dataDir, err)
	}

	login, _ := siteAdminIdentity(in.AdminEmail)
	return &CompleteOutput{
		State:            domain.SetupStatusComplete,
		OrganizationID:   orgID,
		OrganizationName: orgName,
		AdminEmail:       in.AdminEmail,
		LoginEmail:       login,
	}, nil
}

// warnTokenFileSweepFailed emits the loud action-oriented warning the
// operator sees when the post-completion DeleteTokenFile sweep returns
// an error. The DB has already flipped to 'setup_complete' and the
// hash has been cleared at this point, so the stale plaintext on disk
// is no longer a wizard-authorisation credential. The warning's job
// is to make sure the operator notices and deletes the file by hand.
func (s *Service) warnTokenFileSweepFailed(dataDir string, err error) {
	if s.deps.Logf == nil {
		return
	}
	s.deps.Logf(
		"setup: WARN: setup is complete but the on-disk setup token file at %s could not be deleted (%v); the file is no longer accepted by the setup wizard, but please delete it by hand so the plaintext does not linger on the data volume",
		TokenFilePath(dataDir), err,
	)
}

func validateCompleteInput(in CompleteInput) error {
	if strings.TrimSpace(in.OrganizationName) == "" {
		return fmt.Errorf("setup complete: organization_name is required")
	}
	if strings.TrimSpace(in.AdminEmail) == "" {
		return fmt.Errorf("setup complete: admin_email is required")
	}
	if !strings.Contains(in.AdminEmail, "@") {
		return fmt.Errorf("setup complete: admin_email is not a valid email address")
	}
	if len(in.AdminPassword) < 12 {
		return fmt.Errorf("setup complete: admin_password must be at least 12 characters")
	}
	// Setup completion creates the FIRST site_admin row — control-
	// plane infrastructure per Decision D-004. The locked
	// admin-local invariant requires STRICT password validation
	// here regardless of any future SystemOrg policy. Wired by
	// slice agent-a-20260715-idp-oss-password-complexity-perorg-
	// enforcement (Decision D-015 §9 EXCLUDED control-plane path).
	if err := domain.ValidatePassword(in.AdminPassword, 12); err != nil {
		return fmt.Errorf("setup complete: admin_password failed strict policy: %w", err)
	}
	return nil
}

// ensureFirstOrganization is idempotent: it reuses an existing
// non-system organization if one is present (resumable partial state),
// and only creates a new one when the operator is starting fresh. We
// look up by domain (slug of name) rather than name so the OSS
// uniqueness constraint is the source of truth.
func (s *Service) ensureFirstOrganization(ctx context.Context, in CompleteInput) (uuid.UUID, string, error) {
	desiredDomain := strings.ToLower(strings.TrimSpace(in.OrganizationDomain))
	if desiredDomain == "" {
		desiredDomain = strings.TrimSpace(in.OrganizationName)
	}

	systemOrgID, err := uuid.Parse(domain.SystemOrgID)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("setup complete: parse system org id: %w", err)
	}

	// Resumable path: was there already a non-system org from a prior
	// partial run? If so, reuse it and ignore the new input.
	orgs, _, err := s.deps.OrgRepo.List(ctx, repository.OrganizationFilter{}, repository.NewPagination(1, 5), repository.Sort{})
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("setup complete: list organizations: %w", err)
	}
	for _, o := range orgs {
		if o == nil || o.ID == systemOrgID {
			continue
		}
		return o.ID, o.Name, nil
	}

	// Fresh path: create.
	created, err := s.deps.OrgService.Create(ctx, service.CreateOrganizationOptions{
		Name:   in.OrganizationName,
		Domain: desiredDomain,
		Active: true,
	})
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("setup complete: create organization: %w", err)
	}
	return created.ID, created.Name, nil
}

// ensureSiteAdmin creates the pinned-id site_admin user when absent.
// Mirrors the --bootstrap CLI's path so the two surfaces stay
// behaviourally consistent.
func (s *Service) ensureSiteAdmin(ctx context.Context, orgID uuid.UUID, in CompleteInput) error {
	systemOrgID, err := uuid.Parse(domain.SystemOrgID)
	if err != nil {
		return fmt.Errorf("setup complete: parse system org id: %w", err)
	}
	siteAdminID, err := uuid.Parse(domain.SiteAdminID)
	if err != nil {
		return fmt.Errorf("setup complete: parse site admin id: %w", err)
	}

	// G15 — THE LOGIN IS PINNED, THE OPERATOR'S ADDRESS IS CONTACT DETAIL.
	//
	// AdminPermissionsModel.md: "site_admin's user id (login) is
	// site_admin@system.local" and "site_admin has a separate contact-email
	// field set by the installing user". Setup used to write the operator's
	// typed address as the LOGIN, which makes the account's identity depend on
	// who happened to run the installer — and left identuum-idp-ce, which
	// already pins the canonical login, disagreeing with OSS about the identity
	// of the single most privileged account in the product. The parity rule
	// makes that divergence a defect in its own right.
	//
	// The typed address is not discarded: it is written to users.contact_email
	// (migration 0026) by the same repository call, which is also what finally
	// gives that column a writer (G9).
	login, contact := siteAdminIdentity(in.AdminEmail)

	existing, err := s.deps.UserRepo.GetByEmailAndOrgID(ctx, systemOrgID, login)
	switch {
	case err == nil && existing != nil:
		// WIZARD-SPLIT-BRAIN-1: a site_admin already exists. The wizard used
		// to return nil here — silently DISCARDING the operator's submitted
		// password and completing anyway, so the next login said "Invalid
		// credentials". That happened whenever a prior run (or devseed) left a
		// site_admin behind. ADOPT-AND-RESET instead: the operator's submitted
		// password becomes authoritative, so setup completes with exactly the
		// credentials the operator just typed. Never silently discard.
		pw := in.AdminPassword
		if _, uerr := s.deps.UserRepo.Update(ctx, existing.ID, systemOrgID, repository.UpdateUserOptions{
			Password: &pw,
		}); uerr != nil {
			return fmt.Errorf("setup complete: adopt-and-reset existing site_admin: %w", uerr)
		}
		return nil
	case errors.Is(err, domain.ErrUserNotFound):
		// fall through
	default:
		if err != nil {
			return fmt.Errorf("setup complete: lookup site_admin: %w", err)
		}
	}

	user := &domain.User{
		ID:             siteAdminID,
		OrganizationID: systemOrgID,
		Email:          login,
		ContactEmail:   contact,
		PasswordHash:   in.AdminPassword, // user repo argon2id-hashes plaintext
		Role:           domain.RoleSiteAdmin,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	}
	if _, err := s.deps.UserRepo.Create(ctx, user); err != nil {
		if errors.Is(err, domain.ErrUserAlreadyExists) {
			return nil
		}
		return fmt.Errorf("setup complete: create site_admin: %w", err)
	}
	// orgID is captured here in case future hardening needs to honour
	// a non-system organisation for the bootstrap admin; today every
	// site_admin sits inside SystemOrgID per the existing convention.
	_ = orgID
	return nil
}

// ensureFirstSigningKey is the appliance-target version of the manual
// POST /api/v1/keys/generate the operator used to run. Resolves
// D-IDP-INSTALL-09's open item against the current code.
func (s *Service) ensureFirstSigningKey(ctx context.Context) error {
	existing, err := s.deps.KeyService.ListActive(ctx)
	if err != nil {
		return fmt.Errorf("setup complete: list active keys: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}
	if _, err := s.deps.KeyService.Generate(ctx, service.GenerateKeyOptions{
		Algorithm: string(domain.KeyAlgorithmEdDSA),
		State:     domain.KeyStateActive,
	}); err != nil {
		return fmt.Errorf("setup complete: generate signing key: %w", err)
	}
	return nil
}

// --- helpers used by Status -------------------------------------------------

// siteAdminPresent uses the pinned SiteAdminID (the singleton PK) rather
// than the legacy bootstrap email so the wizard's operator-supplied
// email is honoured — Status reports true whether the site_admin was
// created with the default site_admin@system.local or any other email.
func (s *Service) siteAdminPresent(ctx context.Context) (bool, error) {
	siteAdminID, err := uuid.Parse(domain.SiteAdminID)
	if err != nil {
		return false, fmt.Errorf("setup status: parse site admin id: %w", err)
	}
	u, err := s.deps.UserRepo.GetByID(ctx, siteAdminID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("setup status: lookup site_admin: %w", err)
	}
	return u != nil, nil
}

func (s *Service) firstOrganizationPresent(ctx context.Context) (bool, error) {
	systemOrgID, err := uuid.Parse(domain.SystemOrgID)
	if err != nil {
		return false, fmt.Errorf("setup status: parse system org id: %w", err)
	}
	orgs, _, err := s.deps.OrgRepo.List(ctx, repository.OrganizationFilter{}, repository.NewPagination(1, 5), repository.Sort{})
	if err != nil {
		return false, fmt.Errorf("setup status: list organizations: %w", err)
	}
	for _, o := range orgs {
		if o != nil && o.ID != systemOrgID {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) firstSigningKeyPresent(ctx context.Context) (bool, error) {
	keys, err := s.deps.KeyService.ListActive(ctx)
	if err != nil {
		return false, fmt.Errorf("setup status: list active keys: %w", err)
	}
	return len(keys) > 0, nil
}

// siteAdminIdentity splits what the installer types into the two fields the
// model keeps separate: the pinned LOGIN and the operator's CONTACT address.
//
// It is a named function rather than two lines inline so the rule has somewhere
// to be asserted (rg15_login_identity_test.go). Inlined, the only way to test
// it would be to restate it in the test, which tests the restatement.
func siteAdminIdentity(operatorEmail string) (login, contact string) {
	return domain.SiteAdminEmail, strings.TrimSpace(operatorEmail)
}
