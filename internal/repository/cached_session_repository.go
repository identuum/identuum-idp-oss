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
	"go.uber.org/zap"
)

// CachedSessionRepository decorates SessionRepository with Redis caching
type CachedSessionRepository struct {
	delegate    SessionRepository
	redisClient *cache.RedisClient
	cacheTTL    time.Duration
}

// Compile-time interface check
var _ SessionRepository = (*CachedSessionRepository)(nil)
var _ AdminSessionRepository = (*CachedSessionRepository)(nil)

// NewCachedSessionRepository creates a new cached session repository
func NewCachedSessionRepository(delegate SessionRepository, redisClient *cache.RedisClient) *CachedSessionRepository {
	return &CachedSessionRepository{
		delegate:    delegate,
		redisClient: redisClient,
		cacheTTL:    60 * time.Second, // Short validation cache
	}
}

// Helper to generate cache keys
func (r *CachedSessionRepository) validationKey(sessionID uuid.UUID) string {
	return fmt.Sprintf("session:validation:%s", sessionID)
}

// === Optimized Caching Method ===

func (r *CachedSessionRepository) GetSessionWithUserAndOrgStatus(ctx context.Context, sessionID uuid.UUID) (*domain.SessionValidationInfo, error) {
	key := r.validationKey(sessionID)
	var info domain.SessionValidationInfo

	// 1. Try Cache
	if err := r.redisClient.Get(ctx, key, &info); err == nil {

		metrics.CacheOperations.WithLabelValues("session", "validation", "hit").Inc()
		return &info, nil
	}

	// 2. Cache Miss - Call Delegate

	metrics.CacheOperations.WithLabelValues("session", "validation", "miss").Inc()
	result, err := r.delegate.GetSessionWithUserAndOrgStatus(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// 3. Set Cache
	// Only cache if successful. Background errors shouldn't fail request but should be logged.
	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache session validation: %v", err)
		metrics.CacheOperations.WithLabelValues("session", "validation", "error").Inc()
	}

	return result, nil
}

// === Pass-through Methods (with invalidation where needed) ===

// P3-10: INVALIDATE, COMMIT, INVALIDATE AGAIN.
//
// Invalidating only BEFORE the commit leaves a window: a validation arriving
// between the Del and the delegate's write reads the STILL-ACTIVE row and
// repopulates the cache, and that stale-active entry then outlives the
// revocation until its own TTL expires. Invalidating only AFTER leaves the
// mirror-image window, where the pre-revocation entry is served throughout the
// commit. Only doing both closes both.
//
// The second Del runs even when the commit FAILED. That is deliberate and
// cheap: the cache is not authoritative, so dropping an entry that turns out to
// be valid costs one re-read, whereas keeping one that turns out to be revoked
// costs a live session.
//
// Pinned by TestCachedSessionRepository_Revoke_FailedCommitDoesNotLeaveCacheInvalidated,
// which drives the concurrent read from inside the delegate so it lands in the
// window deterministically rather than by timing luck.
func (r *CachedSessionRepository) Revoke(ctx context.Context, id uuid.UUID, orgID uuid.UUID, reason string) error {
	if err := r.redisClient.Del(ctx, r.validationKey(id)); err != nil {
		logger.Error.Printf("Failed to invalidate cache for session %s: %v", id, err)
	}
	err := r.delegate.Revoke(ctx, id, orgID, reason)
	if delErr := r.redisClient.Del(ctx, r.validationKey(id)); delErr != nil {
		logger.Error.Printf("Failed to re-invalidate cache for session %s: %v", id, delErr)
	}
	return err
}

func (r *CachedSessionRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID, reason string) error {
	// Complex invalidation: We strictly should find all sessions and invalidate them.
	// However, we don't have the list here without querying.
	// Strategy: Get active sessions from DB first, then invalidate keys.
	// This adds DB load to revocation, but ensures consistency.

	sessions, err := r.delegate.ListActiveByUserID(ctx, userID)
	if err == nil {
		for _, s := range sessions {
			if delErr := r.redisClient.Del(ctx, r.validationKey(s.ID)); delErr != nil {
				logger.Warning.Printf("cache invalidation failed for revoked session %s: %v", s.ID, delErr)
			}
		}
	}

	err = r.delegate.RevokeByUserID(ctx, userID, reason)
	// P3-10: second sweep, same reasoning as Revoke — a read landing between the
	// first sweep and the commit repopulates from the not-yet-revoked rows.
	for _, s := range sessions {
		if delErr := r.redisClient.Del(ctx, r.validationKey(s.ID)); delErr != nil {
			logger.Warning.Printf("cache re-invalidation failed for revoked session %s: %v", s.ID, delErr)
		}
	}
	return err
}

func (r *CachedSessionRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	if delErr := r.redisClient.Del(ctx, r.validationKey(id)); delErr != nil {
		logger.Warning.Printf("cache invalidation failed for deleted session %s: %v", id, delErr)
	}
	err := r.delegate.Delete(ctx, id, orgID)
	// P3-10: same window as Revoke.
	if delErr := r.redisClient.Del(ctx, r.validationKey(id)); delErr != nil {
		logger.Warning.Printf("cache re-invalidation failed for deleted session %s: %v", id, delErr)
	}
	return err
}

// === Pure Pass-throughs ===

func (r *CachedSessionRepository) Create(ctx context.Context, session *domain.Session) (*domain.Session, error) {
	return r.delegate.Create(ctx, session)
}

func (r *CachedSessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	return r.delegate.GetByID(ctx, id)
}

func (r *CachedSessionRepository) GetByTokenSelector(ctx context.Context, selector uuid.UUID) (*domain.Session, error) {
	return r.delegate.GetByTokenSelector(ctx, selector)
}

func (r *CachedSessionRepository) Update(ctx context.Context, session *domain.Session, orgID uuid.UUID) error {
	err := r.delegate.Update(ctx, session, orgID)
	if err != nil {
		return err
	}

	// Invalidate cache after successful update
	if err := r.redisClient.Del(ctx, r.validationKey(session.ID)); err != nil {
		logger.Error.Printf("Failed to invalidate cache for session %s after update: %v", session.ID, err)
	}

	return nil
}

// RotateToken delegates the P0-12 compare-and-set rotation and invalidates the
// cached validation entry on a successful rotation (the validator hash + expiry
// changed, so any cached snapshot is stale).
func (r *CachedSessionRepository) RotateToken(ctx context.Context, sessionID uuid.UUID, expectedValidatorHash, newValidatorHash string, newExpiresAt, lastUsedAt time.Time) (*domain.Session, bool, error) {
	session, won, err := r.delegate.RotateToken(ctx, sessionID, expectedValidatorHash, newValidatorHash, newExpiresAt, lastUsedAt)
	if err == nil && won {
		if delErr := r.redisClient.Del(ctx, r.validationKey(sessionID)); delErr != nil {
			logger.Error.Printf("Failed to invalidate cache for session %s after rotate: %v", sessionID, delErr)
		}
	}
	return session, won, err
}

// RecordACRUplift delegates to the underlying repo and invalidates the
// cached validation entry — a step-up changes the session's effective
// ACR/auth_time, so any cached snapshot must be discarded.
func (r *CachedSessionRepository) RecordACRUplift(ctx context.Context, sessionID uuid.UUID, upliftAt time.Time, upliftValue string) error {
	if err := r.delegate.RecordACRUplift(ctx, sessionID, upliftAt, upliftValue); err != nil {
		return err
	}
	if err := r.redisClient.Del(ctx, r.validationKey(sessionID)); err != nil {
		logger.Error.Printf("Failed to invalidate cache for session %s after acr uplift: %v", sessionID, err)
	}
	return nil
}

func (r *CachedSessionRepository) RevokeByOrganizationID(ctx context.Context, orgID uuid.UUID, reason string) error {
	// CRITICAL SECURITY FIX: Invalidate all org session caches BEFORE revoking in database
	// This prevents a race condition where revoked sessions could still validate from cache

	// Strategy: Use AdminSessionRepository.ListByOrganizationID if available to get session IDs
	// Then invalidate all cache entries before calling database revocation

	if adminRepo, ok := r.delegate.(AdminSessionRepository); ok {
		const pageSize = 500
		offset := 0
		totalEvicted := 0

		for {
			page := Pagination{PageSize: pageSize, Offset: offset}
			sessions, _, err := adminRepo.ListByOrganizationID(ctx, orgID, page)
			if err != nil {
				logger.ErrorContext(ctx, "failed to list org sessions for cache invalidation",
					zap.Any("org_id", orgID), zap.Int("offset", offset), zap.Error(err))
				// Fail-open: stop iterating but still proceed to database revocation below
				break
			}
			for _, session := range sessions {
				if delErr := r.redisClient.Del(ctx, r.validationKey(session.ID)); delErr != nil {
					logger.ErrorContext(ctx, "failed to invalidate cache for session",
						zap.Any("session_id", session.ID), zap.Error(delErr))
				}
			}
			totalEvicted += len(sessions)
			if len(sessions) < pageSize {
				break // final page reached
			}
			offset += pageSize
		}

		if totalEvicted > 0 {
			logger.InfoContext(ctx, "invalidated org session cache before revocation",
				zap.Any("org_id", orgID), zap.Int("evicted", totalEvicted))
		}
	} else {
		// Fallback: Delegate doesn't implement AdminSessionRepository
		logger.ErrorContext(ctx, "cannot invalidate org session caches immediately - delegate doesn't implement AdminSessionRepository",
			zap.Any("org_id", orgID))
	}

	// Now revoke in database - cached entries already cleared
	return r.delegate.RevokeByOrganizationID(ctx, orgID, reason)
}

func (r *CachedSessionRepository) ListByUserID(ctx context.Context, userID uuid.UUID, includeInvalid bool) ([]*domain.Session, error) {
	return r.delegate.ListByUserID(ctx, userID, includeInvalid)
}

func (r *CachedSessionRepository) ListActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	return r.delegate.ListActiveByUserID(ctx, userID)
}

func (r *CachedSessionRepository) CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error) {
	return r.delegate.CountActiveByUserID(ctx, userID)
}

func (r *CachedSessionRepository) DeleteExpiredReturning(ctx context.Context, retentionPeriod time.Duration, batchSize int) ([]*domain.Session, error) {
	sessions, err := r.delegate.DeleteExpiredReturning(ctx, retentionPeriod, batchSize)
	if err != nil {
		return nil, err
	}

	// Invalidate cache for deleted sessions
	for _, s := range sessions {
		if delErr := r.redisClient.Del(ctx, r.validationKey(s.ID)); delErr != nil {
			logger.Warning.Printf("cache invalidation failed for expired session %s: %v", s.ID, delErr)
		}
	}

	return sessions, nil
}

func (r *CachedSessionRepository) GetStats(ctx context.Context) (map[string]int, error) {
	return r.delegate.GetStats(ctx)
}

// === AdminSessionRepository Implementation ===

func (r *CachedSessionRepository) ListAll(ctx context.Context, filter SessionFilter, pagination Pagination) ([]*domain.Session, int, error) {
	if adminRepo, ok := r.delegate.(AdminSessionRepository); ok {
		return adminRepo.ListAll(ctx, filter, pagination)
	}
	return nil, 0, fmt.Errorf("delegate repository does not support admin operations")
}

func (r *CachedSessionRepository) ListByOrganizationID(ctx context.Context, orgID uuid.UUID, pagination Pagination) ([]*domain.Session, int, error) {
	if adminRepo, ok := r.delegate.(AdminSessionRepository); ok {
		return adminRepo.ListByOrganizationID(ctx, orgID, pagination)
	}
	return nil, 0, fmt.Errorf("delegate repository does not support admin operations")
}

func (r *CachedSessionRepository) GetStatsByOrganization(ctx context.Context, orgID uuid.UUID) (map[string]int, error) {
	if adminRepo, ok := r.delegate.(AdminSessionRepository); ok {
		return adminRepo.GetStatsByOrganization(ctx, orgID)
	}
	return nil, fmt.Errorf("delegate repository does not support admin operations")
}
