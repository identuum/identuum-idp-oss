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

// CachedUserRepository decorates UserRepository with Redis caching
type CachedUserRepository struct {
	delegate    UserRepository
	redisClient *cache.RedisClient
	cacheTTL    time.Duration
}

// Compile-time interface check
var _ UserRepository = (*CachedUserRepository)(nil)

// NewCachedUserRepository creates a new cached user repository
func NewCachedUserRepository(delegate UserRepository, redisClient *cache.RedisClient, cacheTTL time.Duration) *CachedUserRepository {
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute // Default to 5 minutes
	}
	return &CachedUserRepository{
		delegate:    delegate,
		redisClient: redisClient,
		cacheTTL:    cacheTTL,
	}
}

// ConsumeRecoveryCode delegates the atomic per-code removal (P0-11) and
// invalidates the user cache on a successful redemption so a stale cached user
// cannot resurrect a spent recovery code.
func (r *CachedUserRepository) ConsumeRecoveryCode(ctx context.Context, id uuid.UUID, codeHash string) (*domain.User, bool, error) {
	user, ok, err := r.delegate.ConsumeRecoveryCode(ctx, id, codeHash)
	if err == nil && ok && user != nil {
		r.invalidateUserCache(ctx, user)
	}
	return user, ok, err
}

// Helper to generate cache keys
func (r *CachedUserRepository) idKey(id uuid.UUID) string {
	return fmt.Sprintf("user:id:%s", id)
}

func (r *CachedUserRepository) emailKey(email string) string {
	return fmt.Sprintf("user:email:%s", email)
}

func (r *CachedUserRepository) withOrgKey(id uuid.UUID) string {
	return fmt.Sprintf("user:with_org:%s", id)
}

func (r *CachedUserRepository) orgCountKey(orgID uuid.UUID) string {
	return fmt.Sprintf("user:org_count:%s", orgID)
}

// invalidateUserCache removes all cache entries for a user
func (r *CachedUserRepository) invalidateUserCache(ctx context.Context, user *domain.User) {
	if user == nil {
		return
	}

	keys := []string{
		r.idKey(user.ID),
		r.withOrgKey(user.ID),
	}

	if user.Email != "" {
		keys = append(keys, r.emailKey(user.Email))
	}

	// Also invalidate org count cache
	keys = append(keys, r.orgCountKey(user.OrganizationID))

	// Invalidate GetByEmailAndOrgID cache
	if user.Email != "" {
		keys = append(keys, fmt.Sprintf("user:email_org:%s:%s", user.OrganizationID, user.Email))
	}

	// Invalidate GetByExternalID cache
	if user.ExternalID != nil && *user.ExternalID != "" {
		keys = append(keys, fmt.Sprintf("user:external:%s:%s", user.OrganizationID, *user.ExternalID))
	}

	for _, key := range keys {
		if err := r.redisClient.Del(ctx, key); err != nil {
			logger.Error.Printf("Failed to invalidate cache key %s: %v", key, err)
		}
	}
}

// === Cached Methods ===

func (r *CachedUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	key := r.idKey(id)
	var user domain.User

	// 1. Try Cache
	if err := r.redisClient.Get(ctx, key, &user); err == nil {

		metrics.CacheOperations.WithLabelValues("user", "get_by_id", "hit").Inc()
		return &user, nil
	}

	// 2. Cache Miss - Call Delegate

	metrics.CacheOperations.WithLabelValues("user", "get_by_id", "miss").Inc()
	result, err := r.delegate.GetByID(ctx, id)
	if err != nil {
		metrics.CacheOperations.WithLabelValues("user", "get_by_id", "error").Inc()
		return nil, err
	}

	// 3. Set Cache
	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache user GetByID: %v", err)
	}

	return result, nil
}

func (r *CachedUserRepository) FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error) {
	// List operations are not cached - this is used for login resolution
	return r.delegate.FindUsersByEmail(ctx, email)
}

func (r *CachedUserRepository) GetByEmailAndOrgID(ctx context.Context, orgID uuid.UUID, email string) (*domain.User, error) {
	key := fmt.Sprintf("user:email_org:%s:%s", orgID, email)
	var user domain.User

	// 1. Try Cache
	if err := r.redisClient.Get(ctx, key, &user); err == nil {

		metrics.CacheOperations.WithLabelValues("user", "get_by_email_and_org", "hit").Inc()
		return &user, nil
	}

	// 2. Cache Miss - Call Delegate

	metrics.CacheOperations.WithLabelValues("user", "get_by_email_and_org", "miss").Inc()
	result, err := r.delegate.GetByEmailAndOrgID(ctx, orgID, email)
	if err != nil {
		metrics.CacheOperations.WithLabelValues("user", "get_by_email_and_org", "error").Inc()
		return nil, err
	}

	// 3. Set Cache
	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache user by email/org: %v", err)
	}

	return result, nil
}

func (r *CachedUserRepository) GetByExternalID(ctx context.Context, orgID uuid.UUID, externalID string) (*domain.User, error) {
	key := fmt.Sprintf("user:external:%s:%s", orgID, externalID)
	var user domain.User

	// 1. Try Cache
	if err := r.redisClient.Get(ctx, key, &user); err == nil {

		return &user, nil
	}

	// 2. Cache Miss - Call Delegate

	result, err := r.delegate.GetByExternalID(ctx, orgID, externalID)
	if err != nil {
		return nil, err
	}

	// 3. Set Cache
	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache user by external ID: %v", err)
	}

	return result, nil
}

func (r *CachedUserRepository) GetByIDWithOrg(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	key := r.withOrgKey(id)
	var user domain.User

	// 1. Try Cache
	if err := r.redisClient.Get(ctx, key, &user); err == nil {

		return &user, nil
	}

	// 2. Cache Miss - Call Delegate

	result, err := r.delegate.GetByIDWithOrg(ctx, id)
	if err != nil {
		return nil, err
	}

	// 3. Set Cache
	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache user GetByIDWithOrg: %v", err)
	}

	return result, nil
}

func (r *CachedUserRepository) CountByOrganization(ctx context.Context, orgID uuid.UUID) (int, error) {
	key := r.orgCountKey(orgID)
	var count int

	// 1. Try Cache
	if err := r.redisClient.Get(ctx, key, &count); err == nil {

		return count, nil
	}

	// 2. Cache Miss - Call Delegate

	count, err := r.delegate.CountByOrganization(ctx, orgID)
	if err != nil {
		return 0, err
	}

	// 3. Set Cache with shorter TTL (counts can change frequently)
	cacheTTL := r.cacheTTL / 2 // Half the normal TTL for counts
	if err := r.redisClient.Set(ctx, key, count, cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache user CountByOrganization: %v", err)
	}

	return count, nil
}

// CountOrgAdminsByOrganization is a security-critical check — no caching to avoid stale reads.
func (r *CachedUserRepository) CountOrgAdminsByOrganization(ctx context.Context, orgID uuid.UUID) (int, error) {
	return r.delegate.CountOrgAdminsByOrganization(ctx, orgID)
}

// CountOrgAdminsByOrganizations is a security-adjacent check — no caching to avoid stale reads.
func (r *CachedUserRepository) CountOrgAdminsByOrganizations(ctx context.Context, orgIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	return r.delegate.CountOrgAdminsByOrganizations(ctx, orgIDs)
}

// CountVerifiedOrgAdminsByOrganization is a security-critical check — no caching to avoid stale reads.
func (r *CachedUserRepository) CountVerifiedOrgAdminsByOrganization(ctx context.Context, orgID uuid.UUID) (int, error) {
	return r.delegate.CountVerifiedOrgAdminsByOrganization(ctx, orgID)
}

// CountVerifiedOrgAdminsByOrganizations is a security-adjacent check — no caching to avoid stale reads.
func (r *CachedUserRepository) CountVerifiedOrgAdminsByOrganizations(ctx context.Context, orgIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	return r.delegate.CountVerifiedOrgAdminsByOrganizations(ctx, orgIDs)
}

// === Pass-through methods with cache invalidation ===

func (r *CachedUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	result, err := r.delegate.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	// Invalidate org count cache
	if err := r.redisClient.Del(ctx, r.orgCountKey(user.OrganizationID)); err != nil {
		logger.Error.Printf("Failed to invalidate org count cache: %v", err)
	}

	return result, nil
}

func (r *CachedUserRepository) Update(ctx context.Context, id uuid.UUID, orgID uuid.UUID, opts UpdateUserOptions) (*domain.User, error) {
	// Get existing user to invalidate old email cache
	existingUser, errFetch := r.delegate.GetByID(ctx, id)
	if errFetch != nil {
		logger.Warning.Printf("Update: failed to fetch existing user %s for invalidation: %v", id, errFetch)
	}

	result, err := r.delegate.Update(ctx, id, orgID, opts)
	if err != nil {
		return nil, err
	}

	// Invalidate old user cache
	if existingUser != nil {
		r.invalidateUserCache(ctx, existingUser)
	} else {
		_ = r.redisClient.Del(ctx, r.idKey(id))
		_ = r.redisClient.Del(ctx, r.withOrgKey(id))
	}

	// Invalidate new user cache
	r.invalidateUserCache(ctx, result)

	return result, nil
}

func (r *CachedUserRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	// Get user before deleting to invalidate cache
	user, errFetch := r.delegate.GetByID(ctx, id)
	if errFetch != nil {
		logger.Warning.Printf("Delete: failed to fetch existing user %s for invalidation: %v", id, errFetch)
	}

	if err := r.delegate.Delete(ctx, id, orgID); err != nil {
		return err
	}

	// Invalidate cache
	if user != nil {
		r.invalidateUserCache(ctx, user)
	} else {
		_ = r.redisClient.Del(ctx, r.idKey(id))
		_ = r.redisClient.Del(ctx, r.withOrgKey(id))
	}

	return nil
}

func (r *CachedUserRepository) Undelete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	if err := r.delegate.Undelete(ctx, id, orgID); err != nil {
		return err
	}

	// Invalidate cache - user status changed
	if err := r.redisClient.Del(ctx, r.idKey(id)); err != nil {
		logger.Error.Printf("Failed to invalidate user cache on undelete: %v", err)
	}

	return nil
}

// === Pass-through methods without caching (list operations) ===

func (r *CachedUserRepository) List(ctx context.Context, opts ListUserOptions) ([]*domain.User, int, error) {
	// List operations are not cached - they change frequently and have complex filters
	return r.delegate.List(ctx, opts)
}

func (r *CachedUserRepository) ListByOrganization(ctx context.Context, orgID uuid.UUID, opts ListUserOptions) ([]*domain.User, int, error) {
	// List operations are not cached
	return r.delegate.ListByOrganization(ctx, orgID, opts)
}

func (r *CachedUserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	if err := r.delegate.UpdateLastLogin(ctx, id); err != nil {
		return err
	}

	// Invalidate cache (best-effort — last login timestamp is non-critical)
	if err := r.redisClient.Del(ctx, r.idKey(id)); err != nil {
		logger.Warning.Printf("cache invalidation failed after UpdateLastLogin for user %s: %v", id, err)
	}
	if err := r.redisClient.Del(ctx, r.withOrgKey(id)); err != nil {
		logger.Warning.Printf("cache invalidation failed after UpdateLastLogin (withOrg) for user %s: %v", id, err)
	}

	return nil
}

// === Pass-through methods (no caching needed) ===

func (r *CachedUserRepository) VerifyPassword(ctx context.Context, password, hash string) error {
	return r.delegate.VerifyPassword(ctx, password, hash)
}

func (r *CachedUserRepository) HashPassword(password string) (string, error) {
	return r.delegate.HashPassword(password)
}

func (r *CachedUserRepository) GetUserOrganization(ctx context.Context, userID uuid.UUID) (*domain.Organization, error) {
	// Organization data is cached separately by CachedOrganizationRepository
	return r.delegate.GetUserOrganization(ctx, userID)
}

func (r *CachedUserRepository) UpdateOrganizationID(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	// Get user before update to invalidate old cache
	user, errFetch := r.delegate.GetByID(ctx, id)
	if errFetch != nil {
		logger.Warning.Printf("UpdateOrganizationID: failed to fetch existing user %s for invalidation: %v", id, errFetch)
	}

	if err := r.delegate.UpdateOrganizationID(ctx, id, orgID); err != nil {
		return err
	}

	// Invalidate cache
	if user != nil {
		// Invalidate old org count
		if err := r.redisClient.Del(ctx, r.orgCountKey(user.OrganizationID)); err != nil {
			logger.Warning.Printf("cache invalidation failed for old org count %s: %v", user.OrganizationID, err)
		}
		// Invalidate user cache
		r.invalidateUserCache(ctx, user)
	} else {
		_ = r.redisClient.Del(ctx, r.idKey(id))
		_ = r.redisClient.Del(ctx, r.withOrgKey(id))
	}

	// Invalidate new org count
	if err := r.redisClient.Del(ctx, r.orgCountKey(orgID)); err != nil {
		logger.Warning.Printf("cache invalidation failed for new org count %s: %v", orgID, err)
	}

	// Also invalidate user cache again using ID just in case
	if err := r.redisClient.Del(ctx, r.idKey(id)); err != nil {
		logger.Warning.Printf("cache invalidation failed for user id key %s: %v", id, err)
	}
	if err := r.redisClient.Del(ctx, r.withOrgKey(id)); err != nil {
		logger.Warning.Printf("cache invalidation failed for user withOrg key %s: %v", id, err)
	}

	return nil
}

// === AdminUserRepository Implementation ===

func (r *CachedUserRepository) GetByIDAdmin(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	if adminRepo, ok := r.delegate.(AdminUserRepository); ok {
		// We deliberately do not cache admin lookups to ensure freshness and because they might return deleted users
		return adminRepo.GetByIDAdmin(ctx, id)
	}
	return nil, fmt.Errorf("underlying repository does not support admin operations")
}

func (r *CachedUserRepository) GetByEmailAdmin(ctx context.Context, email string) (*domain.User, error) {
	if adminRepo, ok := r.delegate.(AdminUserRepository); ok {
		// We deliberately do not cache admin lookups
		return adminRepo.GetByEmailAdmin(ctx, email)
	}
	return nil, fmt.Errorf("underlying repository does not support admin operations")
}

func (r *CachedUserRepository) ListDeleted(ctx context.Context, pagination Pagination) ([]*domain.User, int, error) {
	if adminRepo, ok := r.delegate.(AdminUserRepository); ok {
		return adminRepo.ListDeleted(ctx, pagination)
	}
	return nil, 0, fmt.Errorf("underlying repository does not support admin operations")
}

func (r *CachedUserRepository) ListAll(ctx context.Context, opts ListUserOptions) ([]*domain.User, int, error) {
	if adminRepo, ok := r.delegate.(AdminUserRepository); ok {
		return adminRepo.ListAll(ctx, opts)
	}
	return nil, 0, fmt.Errorf("underlying repository does not support admin operations")
}

func (r *CachedUserRepository) HardDelete(ctx context.Context, id uuid.UUID) error {
	if adminRepo, ok := r.delegate.(AdminUserRepository); ok {
		err := adminRepo.HardDelete(ctx, id)
		if err == nil {
			// Invalidate cache if successful (even if it's hard delete, better safe)
			// We can't use r.invalidateUserCache easily without the user object, but we can clear ID keys
			_ = r.redisClient.Del(ctx, r.idKey(id))
			_ = r.redisClient.Del(ctx, r.withOrgKey(id))
		}
		return err
	}
	return fmt.Errorf("underlying repository does not support admin operations")
}
