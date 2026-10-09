package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ErrQuotaExceeded is CreateUnderCeiling's refusal: the organization already
// holds ceiling API resources.
var ErrQuotaExceeded = errors.New("repository: quota exceeded")

// APIResourceQuotaStore is the quota-bound create of an APIResourceRepository
// (OSS-SEAM-5). A repository without it cannot serve a quota, and the service
// then refuses the create.
type APIResourceQuotaStore interface {
	// CountByOrg is how many API resources an organization holds.
	CountByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
	// CreateUnderCeiling is Create when the organization holds fewer than
	// ceiling API resources, and ErrQuotaExceeded otherwise. The count and the
	// insert are one transaction, serialized per organization, so concurrent
	// creates cannot pass the ceiling; a failed insert writes nothing.
	CreateUnderCeiling(ctx context.Context, resource *domain.APIResource, scopes []domain.APIScope, ceiling int64) error
}

// APIResourceRepository governs database operations for API Resources and their scopes
type APIResourceRepository interface {
	Create(ctx context.Context, resource *domain.APIResource, scopes []domain.APIScope) error
	GetByID(ctx context.Context, id uuid.UUID, orgID *uuid.UUID) (*domain.APIResource, error)
	GetByAudienceGlobal(ctx context.Context, audience string) (*domain.APIResource, error)
	Update(ctx context.Context, resource *domain.APIResource) error
	Delete(ctx context.Context, id uuid.UUID, orgID *uuid.UUID) error
	List(ctx context.Context, pagination Pagination, orgID *uuid.UUID) ([]*domain.APIResource, int, error)

	AddScopes(ctx context.Context, resourceID uuid.UUID, scopes []domain.APIScope) error
	RemoveScope(ctx context.Context, resourceID, scopeID uuid.UUID) error

	// ReplaceScopes atomically replaces the full scope set for a resource.
	// Used by APIResourceService.Update so the PUT /api-resources/:id body's
	// `scopes` field actually lands in the DB (the top-level Update SQL does
	// not touch api_resource_scopes). The implementation must be transactional:
	// DELETE + INSERT inside a single transaction so a partial failure cannot
	// leave the resource with an empty or half-applied scope set.
	ReplaceScopes(ctx context.Context, resourceID uuid.UUID, scopes []domain.APIScope) error

	// UpdateWithScopes applies the resource field update AND replaces its full
	// scope set in ONE transaction (P2-16). It exists because a plain Update
	// followed by a separate ReplaceScopes are two commits — a failure on the
	// second leaves the fields committed but the scopes stale (partial write).
	// The implementation MUST be transactional (mirror Create): the field
	// UPDATE and the scope DELETE+INSERT commit together, and a failure in
	// either rolls BOTH back.
	UpdateWithScopes(ctx context.Context, resource *domain.APIResource, scopes []domain.APIScope) error
}
