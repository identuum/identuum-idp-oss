package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// APIResourceService is the OSS-narrow API-resource admin surface.
// Authorization (role/scope checks) is enforced at the HTTP layer.
// Feature-gate enforcement (AuthorizationServer tier) is NOT
// implemented in OSS today; future CE composition can mount a
// feature-gate middleware before this service is exposed.
type APIResourceService struct {
	repo repository.APIResourceRepository
}

func NewAPIResourceService(report *lifecycle.StartupReport, repo repository.APIResourceRepository) *APIResourceService {
	if repo == nil {
		report.Fatal("NewAPIResourceService", "service: NewAPIResourceService requires a non-nil APIResourceRepository")
	}
	return &APIResourceService{repo: repo}
}

// CreateAPIResourceOptions captures the OSS-safe shape required to
// register a new API resource. Scopes are persisted in the same
// transaction as the resource row.
type CreateAPIResourceOptions struct {
	OrganizationID uuid.UUID
	Name           string
	Audience       string
	Active         bool
	TokenTTLSecs   int
	Scopes         []domain.APIScope
}

// UpdateAPIResourceOptions captures the OSS-safe mutable surface.
type UpdateAPIResourceOptions struct {
	Name         *string
	Audience     *string
	Active       *bool
	TokenTTLSecs *int
	Scopes       []domain.APIScope // non-nil → replace
}

var errAPIResourceNotFound = errors.New("service: api resource not found")

// ErrAPIResourceNotFound exposes the not-found sentinel so handlers can
// reserve 404 for real misses (THE-SIXTEEN-ELSES).
func ErrAPIResourceNotFound() error { return errAPIResourceNotFound }

// ErrAPIResourceForbidden refuses every actor outside the
// org_admin-within-its-own-organization contract (THE-INVERTED-GUARD).
var ErrAPIResourceForbidden = errors.New("service: api resource forbidden")

// apiResourceActorOrg resolves the ONLY organization an actor may touch
// API resources in. Modelled on ServiceAccountService.requireOrgAdmin with
// ONE deliberate divergence: site_admin is REFUSED, not admitted —
// AdminPermissionsModel.md is law, API resources carry OrganizationID, and
// tenant-owned resources are the tenant's own business once an org_admin
// exists. Cross-org ids never reach here: every read/mutation below is
// repo-scoped to the returned org, so a foreign id is indistinguishable
// from a miss (404, never a confirming 403 — the SA rationale).
func apiResourceActorOrg(actor *domain.Principal) (uuid.UUID, error) {
	if actor == nil || !actor.IsOrgAdminOnly() {
		return uuid.Nil, ErrAPIResourceForbidden
	}
	return actor.OrganizationID, nil
}

// Create persists a new APIResource plus its scope set. Returns the
// stored resource and (for newly-created rows) the plaintext
// resource secret EXACTLY ONCE. The actor must be an org_admin; the
// resource is pinned to the actor's own organization (a request naming
// ANOTHER org answers not-found, never a confirming 403).
func (s *APIResourceService) Create(ctx context.Context, actor *domain.Principal, opts CreateAPIResourceOptions) (*domain.APIResource, string, error) {
	org, err := apiResourceActorOrg(actor)
	if err != nil {
		return nil, "", err
	}
	if opts.OrganizationID == uuid.Nil {
		opts.OrganizationID = org
	}
	if opts.OrganizationID != org {
		return nil, "", errAPIResourceNotFound
	}
	if opts.Name == "" || opts.Audience == "" {
		return nil, "", fmt.Errorf("api resource name and audience are required")
	}
	// Scope-prefix invariant: reject `system:` / `keys:` / `backups:` and
	// whitespace/empty scope names BEFORE provisioning any resource secret
	// or DB row. Previously wired here by
	// `agent-claude-20260624-idp-oss-api-resource-scope-prefix-wirein`.
	if err := domain.ValidateAPIScopes(opts.Scopes); err != nil {
		return nil, "", err
	}
	if opts.TokenTTLSecs <= 0 {
		opts.TokenTTLSecs = 3600
	}

	plaintext, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, "", fmt.Errorf("api resource secret generation failed: %w", err)
	}
	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, "", fmt.Errorf("api resource uuid generation failed: %w", err)
	}
	now := time.Now().UTC()
	resource := &domain.APIResource{
		ID:                 id,
		OrganizationID:     opts.OrganizationID,
		Name:               opts.Name,
		Audience:           opts.Audience,
		Active:             opts.Active,
		TokenTTLSecs:       opts.TokenTTLSecs,
		ResourceSecretHash: crypto.HashSecret(plaintext),
		CreatedAt:          now,
		UpdatedAt:          now,
		Scopes:             opts.Scopes,
	}
	if err := resource.Validate(); err != nil {
		return nil, "", err
	}
	if err := s.repo.Create(ctx, resource, opts.Scopes); err != nil {
		return nil, "", err
	}
	return resource, plaintext, nil
}

// Update mutates the resource and atomically replaces its scope set
// when opts.Scopes is non-nil. The fetch is scoped to the actor's own
// organization, so a foreign-org id is indistinguishable from a miss.
func (s *APIResourceService) Update(ctx context.Context, actor *domain.Principal, id uuid.UUID, opts UpdateAPIResourceOptions) (*domain.APIResource, error) {
	org, authzErr := apiResourceActorOrg(actor)
	if authzErr != nil {
		return nil, authzErr
	}
	resource, err := s.repo.GetByID(ctx, id, &org)
	if err != nil || resource == nil {
		return nil, errAPIResourceNotFound
	}
	if opts.Name != nil {
		resource.Name = *opts.Name
	}
	if opts.Audience != nil {
		resource.Audience = *opts.Audience
	}
	if opts.Active != nil {
		resource.Active = *opts.Active
	}
	if opts.TokenTTLSecs != nil {
		resource.TokenTTLSecs = *opts.TokenTTLSecs
	}
	resource.UpdatedAt = time.Now().UTC()

	// P2-16: VALIDATE BEFORE ANY WRITE. resource.Validate() AND the
	// scope-prefix invariant (domain.ValidateAPIScopes) both run before any
	// repo write, so an invalid field OR an invalid scope set (e.g. a
	// forbidden `system:`/`keys:`/`backups:` prefix) commits NOTHING — the
	// prior bug validated scopes AFTER repo.Update had already committed the
	// field changes, leaving a partial write.
	if err := resource.Validate(); err != nil {
		return nil, err
	}
	if opts.Scopes != nil {
		if err := domain.ValidateAPIScopes(opts.Scopes); err != nil {
			return nil, err
		}
		// ATOMIC: the field update AND the scope replacement commit in ONE
		// transaction (mirrors Create). A failure in either step rolls BOTH
		// back — no partial write (fields committed but scopes stale). The
		// prior code did repo.Update then repo.ReplaceScopes as two commits.
		if err := s.repo.UpdateWithScopes(ctx, resource, opts.Scopes); err != nil {
			return nil, err
		}
		resource.Scopes = opts.Scopes
		return resource, nil
	}

	// No scope change requested → plain field update, unchanged path.
	if err := s.repo.Update(ctx, resource); err != nil {
		return nil, err
	}
	return resource, nil
}

// Delete removes the resource, scoped to the actor's own organization.
// Documented-idempotent: a miss — including a foreign-org id, which the
// org-scoped DELETE simply does not match — answers success with zero
// rows affected, mutating nothing and confirming nothing.
func (s *APIResourceService) Delete(ctx context.Context, actor *domain.Principal, id uuid.UUID) error {
	org, err := apiResourceActorOrg(actor)
	if err != nil {
		return err
	}
	return s.repo.Delete(ctx, id, &org)
}

// RegenerateSecret rotates the resource secret. Returns the new
// plaintext EXACTLY ONCE. Org-scoped fetch: foreign-org ids read as a
// miss.
func (s *APIResourceService) RegenerateSecret(ctx context.Context, actor *domain.Principal, id uuid.UUID) (*domain.APIResource, string, error) {
	org, authzErr := apiResourceActorOrg(actor)
	if authzErr != nil {
		return nil, "", authzErr
	}
	resource, err := s.repo.GetByID(ctx, id, &org)
	if err != nil || resource == nil {
		return nil, "", errAPIResourceNotFound
	}
	plaintext, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, "", fmt.Errorf("api resource secret generation failed: %w", err)
	}
	resource.ResourceSecretHash = crypto.HashSecret(plaintext)
	resource.UpdatedAt = time.Now().UTC()
	if err := s.repo.Update(ctx, resource); err != nil {
		return nil, "", err
	}
	return resource, plaintext, nil
}

// GetByID returns the resource keyed by id, scoped to the actor's own
// organization: a foreign-org id is indistinguishable from a miss.
func (s *APIResourceService) GetByID(ctx context.Context, actor *domain.Principal, id uuid.UUID) (*domain.APIResource, error) {
	org, authzErr := apiResourceActorOrg(actor)
	if authzErr != nil {
		return nil, authzErr
	}
	r, err := s.repo.GetByID(ctx, id, &org)
	if err != nil || r == nil {
		return nil, errAPIResourceNotFound
	}
	return r, nil
}

// List returns a paginated set of the actor's own organization's
// resources.
func (s *APIResourceService) List(ctx context.Context, actor *domain.Principal, pagination repository.Pagination) ([]*domain.APIResource, int, error) {
	org, err := apiResourceActorOrg(actor)
	if err != nil {
		return nil, 0, err
	}
	return s.repo.List(ctx, pagination, &org)
}

// ErrAPIResourceNotFound was removed by
// `agent-claude-20260624-idp-oss-dead-accessor-cleanup`. It was a
// dead public accessor with 0 callers in OSS and CE; external callers
// that need to inspect "api resource not found" should use the
// domain-package public sentinel `domain.ErrAPIResourceNotFound` via
// errors.Is(). The unexported `errAPIResourceNotFound` remains used
// internally by Get/Update/RegenerateSecret in this file.

// AuthenticateAPIResource is the OSS API-resource credential
// check. The lookup key is the resource's audience URL — callers
// pass it through the standard `client_id` slot when running the
// client-auth flow on an introspection/revocation endpoint.
//
// Rules:
//   - Empty audience or empty secret → ErrInvalidAPIResourceCredentials
//   - Unknown audience → ErrInvalidAPIResourceCredentials
//   - Inactive resource → ErrInvalidAPIResourceCredentials
//   - subtle.ConstantTimeCompare on the hex-encoded sha256 digests
//
// The raw secret is NEVER returned or echoed.
func (s *APIResourceService) AuthenticateAPIResource(ctx context.Context, audience, secret string) (*domain.APIResource, error) {
	if audience == "" || secret == "" {
		return nil, ErrInvalidAPIResourceCredentials
	}
	res, err := s.repo.GetByAudienceGlobal(ctx, audience)
	if err != nil {
		return nil, ErrInvalidAPIResourceCredentials
	}
	if res == nil || !res.Active {
		return nil, ErrInvalidAPIResourceCredentials
	}
	got := crypto.HashSecret(secret)
	if subtle.ConstantTimeCompare([]byte(got), []byte(res.ResourceSecretHash)) != 1 {
		return nil, ErrInvalidAPIResourceCredentials
	}
	return res, nil
}

// ErrInvalidAPIResourceCredentials is the single opaque sentinel
// for failed API-resource credential checks.
var ErrInvalidAPIResourceCredentials = errors.New("service: invalid api-resource credentials")

// LookupAudience resolves an audience string to its persisted
// APIResource row WITHOUT a credential check. The caller is
// responsible for interpreting the Active flag — the TokenService
// uses it to map `inactive_audience → invalid_target` per RFC 8707.
//
// Returns (nil, nil) for unknown audiences so callers can
// distinguish "not registered" from "lookup failed".
func (s *APIResourceService) LookupAudience(ctx context.Context, audience string) (*domain.APIResource, error) {
	if audience == "" {
		return nil, nil
	}
	res, err := s.repo.GetByAudienceGlobal(ctx, audience)
	if err != nil {
		return nil, err
	}
	return res, nil
}
