package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/infra/cache"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/logger"
)

// CachedIdentityProviderRepository decorates IdentityProviderRepository with Redis lookaside caching.
// GetByOrgAndType and ListByOrganization are called on every login for HRD resolution.
type CachedIdentityProviderRepository struct {
	delegate    IdentityProviderRepository
	redisClient *cache.RedisClient
	cacheTTL    time.Duration
	listTTL     time.Duration
}

// Compile-time interface check
var _ IdentityProviderRepository = (*CachedIdentityProviderRepository)(nil)

// NewCachedIdentityProviderRepository creates a new cached IDP repository.
func NewCachedIdentityProviderRepository(delegate IdentityProviderRepository, redisClient *cache.RedisClient, cacheTTL time.Duration) *CachedIdentityProviderRepository {
	if cacheTTL == 0 {
		cacheTTL = 10 * time.Minute
	}
	return &CachedIdentityProviderRepository{
		delegate:    delegate,
		redisClient: redisClient,
		cacheTTL:    cacheTTL,
		listTTL:     5 * time.Minute, // shorter TTL for list operations
	}
}

// --- Cache key helpers ---

func (r *CachedIdentityProviderRepository) idKey(id uuid.UUID) string {
	return fmt.Sprintf("idp:id:%s", id)
}

func (r *CachedIdentityProviderRepository) orgTypeKey(orgID uuid.UUID, providerType domain.IdentityProviderType) string {
	return fmt.Sprintf("idp:org_type:%s:%s", orgID, providerType)
}

func (r *CachedIdentityProviderRepository) orgListKey(orgID uuid.UUID) string {
	return fmt.Sprintf("idp:org:%s", orgID)
}

// invalidateIDPCache removes all cache entries for an identity provider.
func (r *CachedIdentityProviderRepository) invalidateIDPCache(ctx context.Context, idp *domain.IdentityProvider) {
	if idp == nil {
		return
	}
	keys := []string{
		r.idKey(idp.ID),
		r.orgTypeKey(idp.OrganizationID, idp.Type),
		r.orgListKey(idp.OrganizationID),
	}
	for _, key := range keys {
		if err := r.redisClient.Del(ctx, key); err != nil {
			logger.Error.Printf("Failed to invalidate IDP cache key %s: %v", key, err)
		}
	}
}

// === Cached Methods ===

// GetByID retrieves an IDP by its UUID.
func (r *CachedIdentityProviderRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.IdentityProvider, error) {
	key := r.idKey(id)
	var idp domain.IdentityProvider

	if err := r.redisClient.Get(ctx, key, &idp); err == nil {
		metrics.CacheOperations.WithLabelValues("idp", "get_by_id", "hit").Inc()
		return &idp, nil
	}

	metrics.CacheOperations.WithLabelValues("idp", "get_by_id", "miss").Inc()
	result, err := r.delegate.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache IDP GetByID: %v", err)
	}

	return result, nil
}

// GetByOrgAndType retrieves the primary IDP for an org+type pair.
// This is on the critical login path for Home Realm Discovery (HRD).
func (r *CachedIdentityProviderRepository) GetByOrgAndType(ctx context.Context, orgID uuid.UUID, providerType domain.IdentityProviderType) (*domain.IdentityProvider, error) {
	key := r.orgTypeKey(orgID, providerType)
	var idp domain.IdentityProvider

	if err := r.redisClient.Get(ctx, key, &idp); err == nil {
		metrics.CacheOperations.WithLabelValues("idp", "get_by_org_type", "hit").Inc()
		return &idp, nil
	}

	metrics.CacheOperations.WithLabelValues("idp", "get_by_org_type", "miss").Inc()
	result, err := r.delegate.GetByOrgAndType(ctx, orgID, providerType)
	if err != nil {
		return nil, err
	}

	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache IDP GetByOrgAndType: %v", err)
	}

	return result, nil
}

// ListByOrganization retrieves all IDPs for an organization, ordered by priority.
func (r *CachedIdentityProviderRepository) ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*domain.IdentityProvider, error) {
	key := r.orgListKey(orgID)

	// We store a slice; use a pointer-compatible wrapper
	type listCache struct {
		Items []*domain.IdentityProvider
	}
	var cached listCache

	if err := r.redisClient.Get(ctx, key, &cached); err == nil {
		metrics.CacheOperations.WithLabelValues("idp", "list_by_org", "hit").Inc()
		return cached.Items, nil
	}

	metrics.CacheOperations.WithLabelValues("idp", "list_by_org", "miss").Inc()
	result, err := r.delegate.ListByOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}

	cached = listCache{Items: result}
	if err := r.redisClient.Set(ctx, key, cached, r.listTTL); err != nil {
		logger.Error.Printf("Failed to cache IDP list for org %s: %v", orgID, err)
	}

	return result, nil
}

// === Mutating Methods — delegate + cache invalidation ===

func (r *CachedIdentityProviderRepository) Create(ctx context.Context, provider *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	result, err := r.delegate.Create(ctx, provider)
	if err != nil {
		return nil, err
	}

	// Invalidate the org list so it reflects the new provider
	if err := r.redisClient.Del(ctx, r.orgListKey(result.OrganizationID)); err != nil {
		logger.Error.Printf("Failed to invalidate IDP org list cache after create: %v", err)
	}

	return result, nil
}

func (r *CachedIdentityProviderRepository) Update(ctx context.Context, provider *domain.IdentityProvider) (*domain.IdentityProvider, error) {
	// Fetch before update to capture the old type if it changed
	existing, errFetch := r.delegate.GetByID(ctx, provider.ID)
	if errFetch != nil {
		logger.Warning.Printf("Update: failed to fetch existing IDP %s for invalidation: %v", provider.ID, errFetch)
	}

	result, err := r.delegate.Update(ctx, provider)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		r.invalidateIDPCache(ctx, existing)
	} else {
		_ = r.redisClient.Del(ctx, r.idKey(provider.ID))
		_ = r.redisClient.Del(ctx, r.orgTypeKey(provider.OrganizationID, provider.Type))
		_ = r.redisClient.Del(ctx, r.orgListKey(provider.OrganizationID))
	}

	if result != nil {
		r.invalidateIDPCache(ctx, result)
	}

	return result, nil
}

func (r *CachedIdentityProviderRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	existing, errFetch := r.delegate.GetByID(ctx, id)
	if errFetch != nil {
		logger.Warning.Printf("Delete: failed to fetch existing IDP %s for invalidation: %v", id, errFetch)
	}

	if err := r.delegate.Delete(ctx, id, orgID); err != nil {
		return err
	}

	if existing != nil {
		r.invalidateIDPCache(ctx, existing)
	} else {
		_ = r.redisClient.Del(ctx, r.idKey(id))
		_ = r.redisClient.Del(ctx, r.orgListKey(orgID))
	}

	return nil
}
