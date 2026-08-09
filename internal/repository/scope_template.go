package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ScopeTemplateRepository governs database operations for Scope Templates.
type ScopeTemplateRepository interface {
	Create(ctx context.Context, t *domain.ScopeTemplate) error
	GetByID(ctx context.Context, id, orgID uuid.UUID) (*domain.ScopeTemplate, error)
	List(ctx context.Context, orgID uuid.UUID) ([]*domain.ScopeTemplate, error)
	Update(ctx context.Context, t *domain.ScopeTemplate) error
	Delete(ctx context.Context, id, orgID uuid.UUID) error
}
