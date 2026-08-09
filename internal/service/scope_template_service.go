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
	Name        string
	Description string
	Scopes      []string
}

var errScopeTemplateNotFound = errors.New("service: scope template not found")

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
	if opts.Name != "" {
		template.Name = opts.Name
	}
	if opts.Description != "" {
		template.Description = opts.Description
	}
	if opts.Scopes != nil {
		template.Scopes = opts.Scopes
	}
	template.UpdatedAt = time.Now().UTC()
	if err := s.repo.Update(ctx, template); err != nil {
		return nil, err
	}
	return template, nil
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
