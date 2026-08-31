package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// ScopeTemplateService is the OSS-narrow scope-template admin
// surface. All operations are organization-scoped: a template
// belongs to exactly one tenant and is fetched/listed against the
// caller's tenant id.
type ScopeTemplateService struct {
	repo repository.ScopeTemplateRepository
}

func NewScopeTemplateService(report *lifecycle.StartupReport, repo repository.ScopeTemplateRepository) *ScopeTemplateService {
	if repo == nil {
		report.Fatal("NewScopeTemplateService", "service: NewScopeTemplateService requires a non-nil ScopeTemplateRepository")
	}
	return &ScopeTemplateService{repo: repo}
}

// CreateScopeTemplateOptions is the OSS request shape.
type CreateScopeTemplateOptions struct {
	OrganizationID uuid.UUID
	Name           string
	Description    string
	Scopes         []string
}

// UpdateScopeTemplateOptions captures the mutable fields. Non-nil
// Scopes replaces the prior value; empty Description is treated as
// "leave unchanged".
type UpdateScopeTemplateOptions struct {
	// THE-SILENT-DROP: pointers, so nil is "not supplied" and a supplied
	// blank is a value the validator gets to refuse. Name is REQUIRED;
	// Description is optional and a supplied empty value clears it.
	Name        *string
	Description *string
	Scopes      []string
}

var errScopeTemplateNotFound = errors.New("service: scope template not found")

// errScopeTemplateInvalid wraps a domain-validation failure (reserved scope
// prefix, empty/whitespace scope, name limits) so the handler can answer 400
// rather than a 500 (THE-SCOPE-TEMPLATES).
var errScopeTemplateInvalid = errors.New("service: scope template invalid")

// ErrScopeTemplateInvalid exposes the validation sentinel to handlers.
func ErrScopeTemplateInvalid() error { return errScopeTemplateInvalid }

// Create persists a new scope template scoped to opts.OrganizationID.
func (s *ScopeTemplateService) Create(ctx context.Context, opts CreateScopeTemplateOptions) (*domain.ScopeTemplate, error) {
	if opts.OrganizationID == uuid.Nil {
		return nil, fmt.Errorf("organization id is required")
	}
	if opts.Name == "" {
		return nil, fmt.Errorf("scope template name is required")
	}
	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, fmt.Errorf("scope template uuid generation failed: %w", err)
	}
	now := time.Now().UTC()
	template := &domain.ScopeTemplate{
		ID:             id,
		OrganizationID: opts.OrganizationID,
		Name:           opts.Name,
		Description:    opts.Description,
		Scopes:         opts.Scopes,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	// THE-SCOPE-TEMPLATES (2026-08-30): validate BEFORE any write. Until this
	// slice ScopeTemplate.Validate had ZERO callers — the reserved-prefix bound
	// ("system:"/"keys:"/"backups:") was written but never enforced, safe only
	// because the surface was site_admin-only. Now that org_admin writes
	// templates (owner ruling: tenant-owned), Validate is wired here so a
	// reserved prefix (or whitespace / empty scope) is refused at the door.
	if err := template.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errScopeTemplateInvalid, err)
	}
	if err := s.repo.Create(ctx, template); err != nil {
		return nil, err
	}
	return template, nil
}

// Update mutates an existing template scoped to orgID. Empty Name
// is treated as "leave unchanged"; non-nil Scopes replaces.
func (s *ScopeTemplateService) Update(ctx context.Context, id, orgID uuid.UUID, opts UpdateScopeTemplateOptions) (*domain.ScopeTemplate, error) {
	if orgID == uuid.Nil {
		return nil, fmt.Errorf("organization id is required")
	}
	template, err := s.repo.GetByID(ctx, id, orgID)
	if err != nil || template == nil {
		return nil, errScopeTemplateNotFound
	}
	// Build the PROPOSED state on a copy — a rejected update must not mutate
	// the fetched object (belt-and-suspenders: harmless against the Pgx repo,
	// which returns a fresh row, but correct against any repo that hands back
	// its stored pointer).
	next := *template
	// THE-SILENT-DROP (2026-08-31): these were plain strings compared against
	// "", so a supplied blank name was DROPPED and answered 200 with an
	// unchanged row, and a description could never be cleared. As pointers,
	// nil is "not supplied" and a supplied value is validated below —
	// including the whitespace-only name that Validate used to accept.
	if opts.Name != nil {
		next.Name = *opts.Name
	}
	if opts.Description != nil {
		next.Description = *opts.Description
	}
	if opts.Scopes != nil {
		next.Scopes = opts.Scopes
	}
	next.UpdatedAt = time.Now().UTC()
	// THE-SCOPE-TEMPLATES: re-validate the WHOLE template before the write —
	// the reserved-prefix bound must hold on update too, not only create (the
	// hazard the owner flagged: a path copying the stored slice without
	// re-validation would silently bypass it).
	if err := next.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errScopeTemplateInvalid, err)
	}
	if err := s.repo.Update(ctx, &next); err != nil {
		return nil, err
	}
	return &next, nil
}

// Delete removes the template scoped to orgID.
func (s *ScopeTemplateService) Delete(ctx context.Context, id, orgID uuid.UUID) error {
	if orgID == uuid.Nil {
		return fmt.Errorf("organization id is required")
	}
	return s.repo.Delete(ctx, id, orgID)
}

// GetByID fetches a template by id scoped to orgID.
func (s *ScopeTemplateService) GetByID(ctx context.Context, id, orgID uuid.UUID) (*domain.ScopeTemplate, error) {
	t, err := s.repo.GetByID(ctx, id, orgID)
	if err != nil || t == nil {
		return nil, errScopeTemplateNotFound
	}
	return t, nil
}

// List returns all templates for orgID.
func (s *ScopeTemplateService) List(ctx context.Context, orgID uuid.UUID) ([]*domain.ScopeTemplate, error) {
	if orgID == uuid.Nil {
		return nil, fmt.Errorf("organization id is required")
	}
	return s.repo.List(ctx, orgID)
}

// ErrScopeTemplateNotFound exposes the OSS sentinel.
func ErrScopeTemplateNotFound() error { return errScopeTemplateNotFound }
