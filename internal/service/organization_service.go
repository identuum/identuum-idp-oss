package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// OrganizationService is the OSS-narrow organization admin surface.
// It takes ONLY the organization repository: tenant guards live at
// the HTTP middleware layer. Out of scope here:
//
//   - first-admin claim issuance (ClaimService)
//   - activation token regeneration (email notification path)
//   - org_admin/site_admin authority enforcement beyond
//     RequireSiteAdmin at the handler layer
//   - CreateWithAdmin atomic tx (commercial code path)
//
// The OSS Create path persists the organization only; first-admin
// delegation is delivered by a future CE composition slice.
type OrganizationService struct {
	repo repository.OrganizationRepository
}

func NewOrganizationService(report *lifecycle.StartupReport, repo repository.OrganizationRepository) *OrganizationService {
	if repo == nil {
		report.Fatal("NewOrganizationService", "service: NewOrganizationService requires a non-nil OrganizationRepository")
	}
	return &OrganizationService{repo: repo}
}

// CreateOrganizationOptions is the OSS-narrow create shape.
type CreateOrganizationOptions struct {
	Name               string
	Domain             string
	MaxSessionsPerUser int
	MFAPolicy          string
	AuthPolicy         string
	Active             bool
	// Slug is honored when non-empty; otherwise derived from Name.
	// The slug is create-only: the update wire refuses it loudly
	// (org_slug is a UNIQUE external identifier — THE-INERT-ORG-FIELDS).
	Slug string
	// The four below were monolith create-wire fields the OSS split
	// silently dropped; absent means the same false/0 the INSERT
	// always wrote (THE-INERT-ORG-FIELDS).
	AllowPublicRegistration     bool
	RequireRegistrationApproval bool
	RequireStrictReauth         bool
	ServiceAccountExpiryDays    int
}

// UpdateOrganizationOptions is forwarded verbatim to the repository
// shape. Field-level guards (e.g. tenant-settings restrictions for
// non-site-admin actors) are a future CE addition.
type UpdateOrganizationOptions = repository.UpdateOrganizationOptions

var errOrganizationNotFound = errors.New("service: organization not found")

// ErrOrganizationNotFound exposes the OSS not-found sentinel.
func ErrOrganizationNotFound() error { return errOrganizationNotFound }

// errOrganizationInvalid wraps every field-validation failure on the UPDATE
// path (THE-UNVALIDATED-UPDATE). The update handler collapsed EVERY error to
// 404 "not found", so without a distinguishable sentinel a rejected rename
// would be reported as a missing organization — a second lying message on top
// of the missing guard. Wrapping lets the handler answer 400 while leaving
// its other branches exactly as they were.
var errOrganizationInvalid = errors.New("service: organization invalid")

// ErrOrganizationInvalid exposes the validation sentinel to handlers.
func ErrOrganizationInvalid() error { return errOrganizationInvalid }

// Create persists a new organization. Defaults are applied when
// MaxSessionsPerUser==0 or MFAPolicy=="" so a minimal request body
// still passes domain validation.
//
// Secure defaults landed 2026-06-24 PM by slice
// agent-a-20260718-idp-oss-orgservice-create-passwordcomplexity-secure-default:
// PasswordComplexityEnabled defaults to `true` (strict mode) per the
// migration's NOT NULL DEFAULT. Pre-fix the field was left at Go's
// bool zero-value `false` (relaxed mode), which silently weakened the
// per-org password policy at every new-org create. The repository's
// INSERT positional binding always writes the struct's bool value,
// so the migration default never applied; the service-layer fix is
// to set the secure default at struct-construction time.
func (s *OrganizationService) Create(ctx context.Context, opts CreateOrganizationOptions) (*domain.Organization, error) {
	org, err := buildOrganization(opts)
	if err != nil {
		return nil, err
	}
	created, err := s.repo.Create(ctx, org)
	if err != nil {
		return nil, err
	}
	return created, nil
}

// buildOrganization is the shared normalization + validation step used by
// Create and CreateWithInitialAdmin — one place decides slugs, policy
// defaults, and domain canonicalization.
func buildOrganization(opts CreateOrganizationOptions) (*domain.Organization, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, fmt.Errorf("organization uuid generation failed: %w", err)
	}
	now := time.Now().UTC()
	maxSess := opts.MaxSessionsPerUser
	if maxSess <= 0 {
		maxSess = 10
	}
	mfa := opts.MFAPolicy
	if mfa == "" {
		mfa = "optional"
	}
	slug := strings.ToLower(strings.TrimSpace(opts.Slug))
	if slug == "" {
		slug = slugifyOrgName(opts.Name)
	}
	org := &domain.Organization{
		ID:                          id,
		Name:                        opts.Name,
		Domain:                      strings.ToLower(strings.TrimSpace(opts.Domain)),
		OrgSlug:                     slug,
		MaxSessionsPerUser:          maxSess,
		MFAPolicy:                   mfa,
		AuthPolicy:                  opts.AuthPolicy,
		Active:                      opts.Active,
		AllowPublicRegistration:     opts.AllowPublicRegistration,
		RequireRegistrationApproval: opts.RequireRegistrationApproval,
		RequireStrictReauth:         opts.RequireStrictReauth,
		ServiceAccountExpiryDays:    opts.ServiceAccountExpiryDays,
		PasswordComplexityEnabled:   true, // secure default per Decision D-015 §9 + the migration's NOT NULL DEFAULT true.
		CreatedAt:                   now,
		UpdatedAt:                   now,
	}
	if err := org.Validate(); err != nil {
		return nil, err
	}
	return org, nil
}

// normalizeAndValidateUpdate is buildOrganization's counterpart for the
// UPDATE path (THE-UNVALIDATED-UPDATE, 2026-08-31).
//
// A partial update cannot run Organization.Validate — most fields are absent
// — so it validates each SUPPLIED field with the SAME per-field validator
// Organization.Validate calls. There is no second grammar: domain shape comes
// from domain.ValidateDomainFormat, exactly as on create.
//
// Normalization mirrors buildOrganization so a rename cannot produce a shape
// a create would have rejected, and so "LEXUS.COM " and "lexus.com" cannot
// become two different rows. The returned copy is what the caller must pass
// on — the input is not mutated.
func normalizeAndValidateUpdate(opts UpdateOrganizationOptions) (UpdateOrganizationOptions, error) {
	if opts.Name != nil {
		name := strings.TrimSpace(*opts.Name)
		if err := domain.ValidateOrganizationName(name); err != nil {
			return opts, err
		}
		opts.Name = &name
	}
	if opts.Domain != nil {
		d := domain.NormalizeDomain(*opts.Domain)
		if err := domain.ValidateDomainFormat(d); err != nil {
			return opts, err
		}
		opts.Domain = &d
	}
	if opts.MaxSessionsPerUser != nil {
		if err := domain.ValidateMaxSessionsPerUser(*opts.MaxSessionsPerUser); err != nil {
			return opts, err
		}
	}
	if opts.MFAPolicy != nil {
		if err := domain.ValidateMFAPolicy(*opts.MFAPolicy); err != nil {
			return opts, err
		}
	}
	if opts.AuthPolicy != nil {
		if err := domain.ValidateAuthPolicyValue(*opts.AuthPolicy); err != nil {
			return opts, err
		}
	}
	if opts.ApiAuthorizationPolicy != nil {
		if err := domain.ValidateAPIAuthorizationPolicyValue(*opts.ApiAuthorizationPolicy); err != nil {
			return opts, err
		}
	}
	if opts.ServiceAccountExpiryDays != nil {
		if err := domain.ValidateServiceAccountExpiryDays(*opts.ServiceAccountExpiryDays); err != nil {
			return opts, err
		}
	}
	if opts.M2MAnomalyLimit != nil {
		if err := domain.ValidateM2MAnomalyLimit(*opts.M2MAnomalyLimit); err != nil {
			return opts, err
		}
	}
	if opts.M2MAnomalyWindowSeconds != nil {
		if err := domain.ValidateM2MAnomalyWindowSeconds(*opts.M2MAnomalyWindowSeconds); err != nil {
			return opts, err
		}
	}
	if opts.Tier != nil {
		if err := domain.ValidateOrganizationTier(*opts.Tier); err != nil {
			return opts, err
		}
	}
	if opts.ComplianceContactEmail != nil {
		email := strings.TrimSpace(*opts.ComplianceContactEmail)
		if err := domain.ValidateComplianceContactEmail(email); err != nil {
			return opts, err
		}
		opts.ComplianceContactEmail = &email
	}
	// Booleans (Active, AllowPublicRegistration, RequireRegistrationApproval,
	// RequireStrictReauth, LocalAdminOnly, PasswordComplexityEnabled) have no
	// invalid value to reject: the wire decoder already refused anything that
	// is not a bool.
	return opts, nil
}

// CreateWithInitialAdmin creates the organization AND its initial
// org_admin in one repository transaction (repo.CreateWithAdmin) — a bad
// admin email creates NOTHING, so a retry is clean instead of hitting the
// just-created org's domain conflict (THE-BORN-DEACTIVATED).
//
// The org is forced INACTIVE regardless of opts.Active: the activation
// ceremony (ConsumeActivationToken) is what sets the admin's real
// password and flips the org active, and it refuses already-active
// organizations. The admin is created with an unguessable placeholder
// password hash — generated and hashed HERE, plaintext discarded before
// return — solely to satisfy the password-required domain invariant
// (USER-PW-REQUIRED-1); until the claim, the org is inactive so no login
// can complete, and the placeholder is 32 bytes of entropy nobody holds.
func (s *OrganizationService) CreateWithInitialAdmin(ctx context.Context, opts CreateOrganizationOptions, adminEmail string) (*domain.Organization, *domain.User, error) {
	opts.Active = false
	org, err := buildOrganization(opts)
	if err != nil {
		return nil, nil, err
	}

	adminEmail = strings.ToLower(strings.TrimSpace(adminEmail))
	adminID, err := uuidgen.NewV7()
	if err != nil {
		return nil, nil, fmt.Errorf("admin uuid generation failed: %w", err)
	}
	placeholder := make([]byte, 32)
	if _, err := rand.Read(placeholder); err != nil {
		return nil, nil, fmt.Errorf("placeholder generation failed: %w", err)
	}
	hash, err := crypto.GenerateHash(placeholder)
	if err != nil {
		return nil, nil, fmt.Errorf("placeholder hashing failed: %w", err)
	}
	now := time.Now().UTC()
	admin := &domain.User{
		ID:             adminID,
		OrganizationID: org.ID,
		Email:          adminEmail,
		PasswordHash:   hash,
		Role:           domain.RoleOrgAdmin,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  false,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := admin.Validate(); err != nil {
		return nil, nil, err
	}

	createdOrg, createdAdmin, err := s.repo.CreateWithAdmin(ctx, org, admin)
	if err != nil {
		return nil, nil, err
	}
	return createdOrg, createdAdmin, nil
}

// Update mutates an organization by id.
func (s *OrganizationService) Update(ctx context.Context, id uuid.UUID, opts UpdateOrganizationOptions) (*domain.Organization, error) {
	// AdminPermissionsModel.md: "System organization CANNOT be deleted and
	// renamed." A rename was answering 200.
	if id.String() == domain.SystemOrgID && opts.Name != nil {
		return nil, domain.ErrForbidden
	}
	// THE-UNVALIDATED-UPDATE (2026-08-31): this method went straight to
	// repo.Update, so PUT {"domain":"lexus"} persisted a domain the create
	// path refuses — and the repository appended *opts.Domain raw, without
	// even the lowercase/trim the create path applies, so "LEXUS.COM " and
	// "lexus.com" could become two different rows.
	//
	// LAYER: the SERVICE, because that is where create already normalizes
	// and validates (buildOrganization). Putting it here keeps ONE
	// convention and one grammar; the repository stays a dumb writer, as
	// its Create counterpart is.
	normalized, err := normalizeAndValidateUpdate(opts)
	if err != nil {
		// Wrapped so the handler can answer 400 instead of its
		// catch-all 404 — the message keeps the field-specific text.
		return nil, fmt.Errorf("%w: %v", errOrganizationInvalid, err)
	}
	opts = normalized

	updated, err := s.repo.Update(ctx, id, opts)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, errOrganizationNotFound
	}
	return updated, nil
}

// Delete soft-deletes an organization.
func (s *OrganizationService) Delete(ctx context.Context, id uuid.UUID) error {
	// AdminPermissionsModel.md: "System organization CANNOT be deleted and
	// renamed." This answered 200 and took the site_admin's own organization
	// with it — every later request then failed 401 from a dead session, so
	// the installation was bricked by one call.
	if id.String() == domain.SystemOrgID {
		return domain.ErrForbidden
	}
	return s.repo.Delete(ctx, id)
}

// Restore un-deletes an organization.
func (s *OrganizationService) Restore(ctx context.Context, id uuid.UUID) error {
	// G14 — the sentinel is excluded here as well as at Delete.
	//
	// This is UNREACHABLE today: Delete refuses the System organization, so
	// there is no deleted System organization to restore, and migration 0028
	// now refuses the soft-delete at the database too. It is guarded anyway
	// because "unreachable" is a property of the CURRENT call graph, and the
	// next route that reaches this method will not come with a reminder that
	// the sentinel was someone else's problem. A no-op guard costs one
	// comparison; discovering it was needed costs an installation.
	if id.String() == domain.SystemOrgID {
		return domain.ErrForbidden
	}
	return s.repo.Undelete(ctx, id)
}

// GetByID returns an organization by id.
func (s *OrganizationService) GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	o, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if o == nil {
		return nil, errOrganizationNotFound
	}
	return o, nil
}

// GetByIDAdminView reads an organization in ANY active state (the admin
// read path — a deactivated org must stay inspectable, else deactivation
// is a trap door). It intentionally still RETURNS soft-deleted rows so the
// caller can distinguish deleted (404 per ORG-RESTORE-1) from absent; the
// handler owns that mapping. Falls back to the narrow GetByID when the
// repository has no admin accessor.
func (s *OrganizationService) GetByIDAdminView(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	if ar, ok := s.repo.(repository.AdminOrganizationRepository); ok {
		o, err := ar.GetByIDAdmin(ctx, id)
		if err != nil {
			return nil, err
		}
		if o == nil {
			return nil, errOrganizationNotFound
		}
		return o, nil
	}
	return s.GetByID(ctx, id)
}

// List returns organizations with filter + paging.
func (s *OrganizationService) List(ctx context.Context, filter repository.OrganizationFilter, pagination repository.Pagination, sort repository.Sort) ([]*domain.Organization, int, error) {
	return s.repo.List(ctx, filter, pagination, sort)
}

// slugifyOrgName returns a lowercase, hyphen-separated slug for an
// org name. Anything that isn't alphanum becomes a hyphen; multiple
// hyphens collapse. Mirrors the monolith helper without importing it.
func slugifyOrgName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	out := make([]byte, 0, len(name))
	lastDash := true
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
			lastDash = false
		default:
			if !lastDash {
				out = append(out, '-')
				lastDash = true
			}
		}
	}
	return strings.Trim(string(out), "-")
}
