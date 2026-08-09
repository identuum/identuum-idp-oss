package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/infra/cache"
	"github.com/identuum/identuum-idp-oss/internal/metrics" // Added metrics
	"github.com/identuum/identuum-idp-oss/logger"
)

// CachedServiceAccountRepository decorates ServiceAccountRepository with Redis caching
type CachedServiceAccountRepository struct {
	delegate    ServiceAccountRepository
	redisClient *cache.RedisClient
	cacheTTL    time.Duration
}

// Compile-time interface check
var _ ServiceAccountRepository = (*CachedServiceAccountRepository)(nil)

// NewCachedServiceAccountRepository creates a new cached service account repository
func NewCachedServiceAccountRepository(delegate ServiceAccountRepository, redisClient *cache.RedisClient, cacheTTL time.Duration) *CachedServiceAccountRepository {
	if cacheTTL == 0 {
		cacheTTL = 10 * time.Minute // Default to 10 minutes
	}
	return &CachedServiceAccountRepository{
		delegate:    delegate,
		redisClient: redisClient,
		cacheTTL:    cacheTTL,
	}
}

// Helper to generate cache keys
func (r *CachedServiceAccountRepository) idKey(id uuid.UUID) string {
	return fmt.Sprintf("sa:id:%s", id)
}

// invalidateSACache removes cache entries for a service account
func (r *CachedServiceAccountRepository) invalidateSACache(ctx context.Context, sa *domain.ServiceAccount) {
	if sa == nil {
		return
	}
	key := r.idKey(sa.ID)
	if err := r.redisClient.Del(ctx, key); err != nil {
		logger.Error.Printf("Failed to invalidate SA cache key %s: %v", key, err)
	}
}

// === Cached Methods ===

func (r *CachedServiceAccountRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.ServiceAccount, error) {
	key := r.idKey(id)
	var sa domain.ServiceAccount

	// 1. Try Cache
	if err := r.redisClient.Get(ctx, key, &sa); err == nil {
		logger.Debug.Printf("Cache HIT for SA GetByID: %s", id)
		metrics.CacheOperations.WithLabelValues("service_account", "get_by_id", "hit").Inc()
		return &sa, nil
	}

	// 2. Cache Miss - Call Delegate
	logger.Debug.Printf("Cache MISS for SA GetByID: %s", id)
	metrics.CacheOperations.WithLabelValues("service_account", "get_by_id", "miss").Inc()
	result, err := r.delegate.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// 3. Set Cache
	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache SA GetByID: %v", err)
		metrics.CacheOperations.WithLabelValues("service_account", "get_by_id", "error").Inc()
	}

	return result, nil
}

// === Methods with Cache Invalidation ===

func (r *CachedServiceAccountRepository) Update(ctx context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	result, err := r.delegate.Update(ctx, sa)
	if err != nil {
		return nil, err
	}
	r.invalidateSACache(ctx, result)
	return result, nil
}

func (r *CachedServiceAccountRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	// Get SA before deletion for cache invalidation (best effort)
	sa, errFetch := r.delegate.GetByID(ctx, id)
	if errFetch != nil {
		logger.Warning.Printf("Delete: failed to fetch existing SA %s for invalidation: %v", id, errFetch)
	}

	err := r.delegate.Delete(ctx, id, orgID)
	if err != nil {
		return err
	}

	if sa != nil {
		r.invalidateSACache(ctx, sa)
	} else {
		_ = r.redisClient.Del(ctx, r.idKey(id))
	}
	return nil
}

// === Pass-through Methods (No Caching) ===

func (r *CachedServiceAccountRepository) Create(ctx context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	return r.delegate.Create(ctx, sa)
}

func (r *CachedServiceAccountRepository) GetByName(ctx context.Context, orgID uuid.UUID, name string) (*domain.ServiceAccount, error) {
	// Name lookup less frequent in critical path, skip caching for now
	return r.delegate.GetByName(ctx, orgID, name)
}

func (r *CachedServiceAccountRepository) ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*domain.ServiceAccount, error) {
	return r.delegate.ListByOrganization(ctx, orgID)
}

func (r *CachedServiceAccountRepository) UpdateLastUsedAt(ctx context.Context, id uuid.UUID) error {
	if err := r.delegate.UpdateLastUsedAt(ctx, id); err != nil {
		return err
	}
	_ = r.redisClient.Del(ctx, r.idKey(id))
	return nil
}

// UpdateActive (slice identuum-20260530-service-account-disable-enable-
// backend). Same cache-invalidation pattern as Delete: forward to the
// delegate, then drop the cached row so a subsequent GetByID returns
// fresh state. Errors from the delegate are surfaced verbatim. We
// always drop the cache key (best effort) even if the delegate
// returned an error — if the underlying mutation partially succeeded
// at the DB layer, the next read should hit the source of truth.
func (r *CachedServiceAccountRepository) UpdateActive(ctx context.Context, id uuid.UUID, orgID uuid.UUID, active bool) error {
	err := r.delegate.UpdateActive(ctx, id, orgID, active)
	if delErr := r.redisClient.Del(ctx, r.idKey(id)); delErr != nil {
		logger.Warning.Printf("UpdateActive: failed to invalidate cached SA %s: %v", id, delErr)
	}
	return err
}
