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

// CachedOrganizationRepository decorates OrganizationRepository with Redis caching
type CachedOrganizationRepository struct {
	delegate    OrganizationRepository
	redisClient *cache.RedisClient
	cacheTTL    time.Duration
}

// Compile-time interface checks
var _ OrganizationRepository = (*CachedOrganizationRepository)(nil)
var _ AdminOrganizationRepository = (*CachedOrganizationRepository)(nil)

// NewCachedOrganizationRepository creates a new cached organization repository
func NewCachedOrganizationRepository(delegate OrganizationRepository, redisClient *cache.RedisClient, cacheTTL time.Duration) *CachedOrganizationRepository {
	if cacheTTL == 0 {
		cacheTTL = 10 * time.Minute // Default to 10 minutes
	}
	return &CachedOrganizationRepository{
		delegate:    delegate,
		redisClient: redisClient,
		cacheTTL:    cacheTTL,
	}
}

// Helper to generate cache keys
func (r *CachedOrganizationRepository) idKey(id uuid.UUID) string {
	return fmt.Sprintf("org:id:%s", id)
}

func (r *CachedOrganizationRepository) domainKey(domain string) string {
	return fmt.Sprintf("org:domain:%s", domain)
}

// invalidateOrgCache removes all cache entries for an organization
func (r *CachedOrganizationRepository) invalidateOrgCache(ctx context.Context, org *domain.Organization) {
	if org == nil {
		return
	}

	keys := []string{
		r.idKey(org.ID),
	}

	if org.Domain != "" {
		keys = append(keys, r.domainKey(org.Domain))
	}

	if org.OrgSlug != "" {
		keys = append(keys, fmt.Sprintf("org:slug:%s", org.OrgSlug))
	}

	for _, key := range keys {
		if err := r.redisClient.Del(ctx, key); err != nil {
			logger.Error.Printf("Failed to invalidate cache key %s: %v", key, err)
		}
	}
}

// === Cached Methods ===

func (r *CachedOrganizationRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	key := r.idKey(id)
	var org domain.Organization

	// 1. Try Cache
	if err := r.redisClient.Get(ctx, key, &org); err == nil {
		// Cache HIT
		metrics.CacheOperations.WithLabelValues("organization", "get_by_id", "hit").Inc()
		return &org, nil
	}

	// 2. Cache Miss - Call Delegate
	// Cache MISS
	metrics.CacheOperations.WithLabelValues("organization", "get_by_id", "miss").Inc()
	result, err := r.delegate.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// 3. Set Cache
	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache org GetByID: %v", err)
		metrics.CacheOperations.WithLabelValues("organization", "get_by_id", "error").Inc()
	}

	return result, nil
}

func (r *CachedOrganizationRepository) GetByDomain(ctx context.Context, domainName string) (*domain.Organization, error) {
	key := r.domainKey(domainName)
	var org domain.Organization

	// 1. Try Cache
	if err := r.redisClient.Get(ctx, key, &org); err == nil {
		metrics.CacheOperations.WithLabelValues("organization", "get_by_domain", "hit").Inc()
		return &org, nil
	}

	// 2. Cache Miss - Call Delegate
	metrics.CacheOperations.WithLabelValues("organization", "get_by_domain", "miss").Inc()
	result, err := r.delegate.GetByDomain(ctx, domainName)
	if err != nil {
		return nil, err
	}

	// 3. Set Cache
	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache org GetByDomain: %v", err)
		metrics.CacheOperations.WithLabelValues("organization", "get_by_domain", "error").Inc()
	}

	return result, nil
}

func (r *CachedOrganizationRepository) GetBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	key := fmt.Sprintf("org:slug:%s", slug)
	var org domain.Organization
	// 1. Try Cache
	if err := r.redisClient.Get(ctx, key, &org); err == nil {
		// Cache HIT
		metrics.CacheOperations.WithLabelValues("organization", "get_by_slug", "hit").Inc()
		return &org, nil
	}

	// 2. Cache Miss - Call Delegate
	// Cache MISS
	metrics.CacheOperations.WithLabelValues("organization", "get_by_slug", "miss").Inc()
	result, err := r.delegate.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}

	// 3. Set Cache
	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache org GetBySlug: %v", err)
		metrics.CacheOperations.WithLabelValues("organization", "get_by_slug", "error").Inc()
	}

	return result, nil
}

// GetDetails returns the organization alongside live child-table counts.
// The organization portion is served from the GetByID cache; the stats map
// is always computed from the delegate so user/session mutations in sibling
// repositories are reflected immediately — child-table counts cannot be
// invalidated across decorators without a cross-repo eventing mechanism.
func (r *CachedOrganizationRepository) GetDetails(ctx context.Context, id uuid.UUID) (*domain.Organization, map[string]int, error) {
	org, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}

	userCount, err := r.delegate.CountUsers(ctx, id)
	if err != nil {
		return nil, nil, err
	}

	sessionCount, _ := r.delegate.CountSessions(ctx, id)

	return org, map[string]int{
		"user_count":    userCount,
		"session_count": sessionCount,
	}, nil
}

// === Methods with Cache Invalidation ===

func (r *CachedOrganizationRepository) Create(ctx context.Context, org *domain.Organization) (*domain.Organization, error) {
	result, err := r.delegate.Create(ctx, org)
	if err != nil {
		return nil, err
	}

	// No need to invalidate cache on create since the org doesn't exist yet
	return result, nil
}

// CreateWithAdmin delegates to the underlying repo, which owns the transaction.
// No caching is applied: the org is not yet known to any cache key before this call.
func (r *CachedOrganizationRepository) CreateWithAdmin(ctx context.Context, org *domain.Organization, adminUser *domain.User) (*domain.Organization, *domain.User, error) {
	return r.delegate.CreateWithAdmin(ctx, org, adminUser)
}

func (r *CachedOrganizationRepository) Update(ctx context.Context, id uuid.UUID, opts UpdateOrganizationOptions) (*domain.Organization, error) {
	// Get current org for domain invalidation
	currentOrg, errFetch := r.delegate.GetByID(ctx, id)
	if errFetch != nil {
		logger.Warning.Printf("Update: failed to fetch current org %s for invalidation: %v", id, errFetch)
	}

	result, err := r.delegate.Update(ctx, id, opts)
	if err != nil {
		return nil, err
	}

	// Invalidate old cache entries
	if currentOrg != nil {
		r.invalidateOrgCache(ctx, currentOrg)
	} else {
		_ = r.redisClient.Del(ctx, r.idKey(id))
	}

	// Invalidate new cache entries (in case domain changed)
	r.invalidateOrgCache(ctx, result)

	return result, nil
}

func (r *CachedOrganizationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	// Get org before deletion for cache invalidation
	org, errFetch := r.delegate.GetByID(ctx, id)
	if errFetch != nil {
		logger.Warning.Printf("Delete: failed to fetch org %s for invalidation: %v", id, errFetch)
	}

	err := r.delegate.Delete(ctx, id)
	if err != nil {
		return err
	}

	// Invalidate cache
	if org != nil {
		r.invalidateOrgCache(ctx, org)
	} else {
		_ = r.redisClient.Del(ctx, r.idKey(id))
	}

	return nil
}

func (r *CachedOrganizationRepository) Undelete(ctx context.Context, id uuid.UUID) error {
	err := r.delegate.Undelete(ctx, id)
	if err != nil {
		return err
	}

	// Get updated org and invalidate cache
	org, errFetch := r.delegate.GetByID(ctx, id)
	if errFetch != nil {
		logger.Warning.Printf("Undelete: failed to fetch org %s for invalidation: %v", id, errFetch)
	}

	if org != nil {
		r.invalidateOrgCache(ctx, org)
	} else {
		_ = r.redisClient.Del(ctx, r.idKey(id))
	}

	return nil
}

// === Pure Pass-throughs (no caching) ===

func (r *CachedOrganizationRepository) List(ctx context.Context, filter OrganizationFilter, pagination Pagination, sort Sort) ([]*domain.Organization, int, error) {
	// List operations are not cached due to complexity and variable filters
	return r.delegate.List(ctx, filter, pagination, sort)
}

func (r *CachedOrganizationRepository) CountUsers(ctx context.Context, id uuid.UUID) (int, error) {
	// Count operations change frequently, not worth caching
	return r.delegate.CountUsers(ctx, id)
}

func (r *CachedOrganizationRepository) CountSessions(ctx context.Context, id uuid.UUID) (int, error) {
	// Count operations change frequently, not worth caching
	return r.delegate.CountSessions(ctx, id)
}

// AdminOrganizationRepository implementation - delegate to underlying repository

// GetDetailsAdmin retrieves organization details including statistics (admin only, includes inactive/deleted)
func (r *CachedOrganizationRepository) GetDetailsAdmin(ctx context.Context, id uuid.UUID) (*domain.Organization, map[string]int, error) {
	adminRepo, ok := r.delegate.(AdminOrganizationRepository)
	if !ok {
		return nil, nil, fmt.Errorf("delegate repository does not support admin operations")
	}
	// Don't cache admin queries
	return adminRepo.GetDetailsAdmin(ctx, id)
}

// GetByIDAdmin retrieves an organization by ID including deleted orgs (no cache)
func (r *CachedOrganizationRepository) GetByIDAdmin(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	// Type assert delegate to AdminOrganizationRepository
	adminRepo, ok := r.delegate.(AdminOrganizationRepository)
	if !ok {
		return nil, fmt.Errorf("delegate repository does not support admin operations")
	}
	// Don't cache admin queries - they need to see real-time state
	return adminRepo.GetByIDAdmin(ctx, id)
}

// ListDeleted retrieves all soft-deleted organizations (no cache)
func (r *CachedOrganizationRepository) ListDeleted(ctx context.Context, pagination Pagination) ([]*domain.Organization, int, error) {
	adminRepo, ok := r.delegate.(AdminOrganizationRepository)
	if !ok {
		return nil, 0, fmt.Errorf("delegate repository does not support admin operations")
	}
	// Don't cache admin queries
	return adminRepo.ListDeleted(ctx, pagination)
}

// ListAll retrieves all organizations including deleted (no cache)
func (r *CachedOrganizationRepository) ListAll(ctx context.Context, filter OrganizationFilter, pagination Pagination, sort Sort) ([]*domain.Organization, int, error) {
	adminRepo, ok := r.delegate.(AdminOrganizationRepository)
	if !ok {
		return nil, 0, fmt.Errorf("delegate repository does not support admin operations")
	}
	// Don't cache admin queries
	return adminRepo.ListAll(ctx, filter, pagination, sort)
}

// HardDelete permanently deletes an organization (no cache)
func (r *CachedOrganizationRepository) HardDelete(ctx context.Context, id uuid.UUID) error {
	adminRepo, ok := r.delegate.(AdminOrganizationRepository)
	if !ok {
		return fmt.Errorf("delegate repository does not support admin operations")
	}

	// Invalidate cache before hard delete
	org, errFetch := r.GetByID(ctx, id)
	if errFetch != nil {
		logger.Warning.Printf("HardDelete: failed to fetch org %s for invalidation: %v", id, errFetch)
	}

	if org != nil {
		r.invalidateOrgCache(ctx, org)
	} else {
		_ = r.redisClient.Del(ctx, r.idKey(id))
	}

	return adminRepo.HardDelete(ctx, id)
}

// UpdateID updates the organization ID (admin only, migration/maintenance)
func (r *CachedOrganizationRepository) UpdateID(ctx context.Context, oldID, newID uuid.UUID) error {
	adminRepo, ok := r.delegate.(AdminOrganizationRepository)
	if !ok {
		return fmt.Errorf("delegate repository does not support admin operations")
	}

	// 1. Get current org state to invalidate cache keys derived from it (Slug, Domain)
	// We need this BEFORE the update because after update, ID-based lookups for oldID will fail/miss
	org, err := r.GetByID(ctx, oldID)
	if err != nil {
		// If we can't find it, maybe it doesn't exist or DB error.
		// We proceed to attempt update anyway, but log warning.
		logger.Warning.Printf("UpdateID: Failed to fetch org %s before update: %v", oldID, err)
	}

	// 2. Perform the update
	if err := adminRepo.UpdateID(ctx, oldID, newID); err != nil {
		return err
	}

	// 3. Invalidate Cache
	// Invalidate entries for the OLD ID
	if org != nil {
		r.invalidateOrgCache(ctx, org)
	}

	// Invalidate entries for the NEW ID (just in case something stale is there)
	// We construct a temporary org object with new ID and same domain/slug to ensure we clear those keys too if they map to new ID (unlikely but safe)
	if org != nil {
		newOrg := *org
		newOrg.ID = newID
		r.invalidateOrgCache(ctx, &newOrg)
	} else {
		// Fallback: manually invalidate at least the ID keys if we couldn't fetch org
		for _, key := range []string{r.idKey(oldID), r.idKey(newID)} {
			if err := r.redisClient.Del(ctx, key); err != nil {
				logger.Warning.Printf("cache invalidation failed during org ID swap (fallback) key=%s: %v", key, err)
			}
		}
	}

	return nil
}
