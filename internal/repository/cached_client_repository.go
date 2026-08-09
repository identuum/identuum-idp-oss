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

// CachedClientRepository decorates ClientRepository with Redis lookaside caching.
// It caches hot-path lookups (GetClientByClientID, GetClientByID, GetConsent)
// which are called on every OIDC authorization request.
type CachedClientRepository struct {
	delegate    ClientRepository
	redisClient *cache.RedisClient
	cacheTTL    time.Duration
	consentTTL  time.Duration
}

// Compile-time interface check
var _ ClientRepository = (*CachedClientRepository)(nil)

// NewCachedClientRepository creates a new cached client repository.
func NewCachedClientRepository(delegate ClientRepository, redisClient *cache.RedisClient, cacheTTL time.Duration) *CachedClientRepository {
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}
	return &CachedClientRepository{
		delegate:    delegate,
		redisClient: redisClient,
		cacheTTL:    cacheTTL,
		consentTTL:  15 * time.Minute,
	}
}

// --- Cache key helpers ---

func (r *CachedClientRepository) clientIDKey(clientID string) string {
	return fmt.Sprintf("client:cid:%s", clientID)
}

func (r *CachedClientRepository) idKey(id uuid.UUID) string {
	return fmt.Sprintf("client:id:%s", id)
}

func (r *CachedClientRepository) consentKey(userID, clientID uuid.UUID, apiResourceID *uuid.UUID) string {
	if apiResourceID != nil {
		return fmt.Sprintf("consent:%s:%s:%s", userID, clientID, *apiResourceID)
	}
	return fmt.Sprintf("consent:%s:%s:nil", userID, clientID)
}

// invalidateClientCache removes all cache entries for a client.
func (r *CachedClientRepository) invalidateClientCache(ctx context.Context, client *domain.Client) {
	if client == nil {
		return
	}
	keys := []string{
		r.idKey(client.ID),
		r.clientIDKey(client.ClientID),
	}
	for _, key := range keys {
		if err := r.redisClient.Del(ctx, key); err != nil {
			logger.Error.Printf("Failed to invalidate client cache key %s: %v", key, err)
		}
	}
}

// === Cached Methods ===

// GetClientByClientID retrieves a client by its public client_id string.
// This is on the critical path for every OIDC token exchange.
func (r *CachedClientRepository) GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error) {
	key := r.clientIDKey(clientID)
	var client domain.Client

	if err := r.redisClient.Get(ctx, key, &client); err == nil {
		metrics.CacheOperations.WithLabelValues("client", "get_by_client_id", "hit").Inc()
		return &client, nil
	}

	metrics.CacheOperations.WithLabelValues("client", "get_by_client_id", "miss").Inc()
	result, err := r.delegate.GetClientByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache client GetClientByClientID: %v", err)
	}

	return result, nil
}

// GetClientByID retrieves a client by its internal UUID.
func (r *CachedClientRepository) GetClientByID(ctx context.Context, id uuid.UUID) (*domain.Client, error) {
	key := r.idKey(id)
	var client domain.Client

	if err := r.redisClient.Get(ctx, key, &client); err == nil {
		metrics.CacheOperations.WithLabelValues("client", "get_by_id", "hit").Inc()
		return &client, nil
	}

	metrics.CacheOperations.WithLabelValues("client", "get_by_id", "miss").Inc()
	result, err := r.delegate.GetClientByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if err := r.redisClient.Set(ctx, key, result, r.cacheTTL); err != nil {
		logger.Error.Printf("Failed to cache client GetClientByID: %v", err)
	}

	return result, nil
}

// GetConsent retrieves a stored consent decision for a user+client pair and optional API resource.
func (r *CachedClientRepository) GetConsent(ctx context.Context, userID, clientID uuid.UUID, apiResourceID *uuid.UUID) (*domain.Consent, error) {
	key := r.consentKey(userID, clientID, apiResourceID)
	var consent domain.Consent

	if err := r.redisClient.Get(ctx, key, &consent); err == nil {
		metrics.CacheOperations.WithLabelValues("client", "get_consent", "hit").Inc()
		return &consent, nil
	}

	metrics.CacheOperations.WithLabelValues("client", "get_consent", "miss").Inc()
	result, err := r.delegate.GetConsent(ctx, userID, clientID, apiResourceID)
	if err != nil {
		return nil, err
	}

	// Do not cache a nil result — the consent record does not exist yet.
	// Encoding a nil pointer causes a gob panic.
	if result == nil {
		return nil, nil
	}

	if err := r.redisClient.Set(ctx, key, result, r.consentTTL); err != nil {
		logger.Error.Printf("Failed to cache consent: %v", err)
	}

	return result, nil
}

// === Mutating Methods — delegate + cache invalidation ===

func (r *CachedClientRepository) RegisterClient(ctx context.Context, client *domain.Client) error {
	return r.delegate.RegisterClient(ctx, client)
}

func (r *CachedClientRepository) Update(ctx context.Context, client *domain.Client) error {
	// Fetch before update so we can clear the old clientID key if it changed
	existing, _ := r.delegate.GetClientByID(ctx, client.ID)

	if err := r.delegate.Update(ctx, client); err != nil {
		return err
	}

	if existing != nil {
		r.invalidateClientCache(ctx, existing)
	}
	r.invalidateClientCache(ctx, client)
	return nil
}

func (r *CachedClientRepository) Delete(ctx context.Context, id uuid.UUID, orgID *uuid.UUID) error {
	existing, _ := r.delegate.GetClientByID(ctx, id)

	if err := r.delegate.Delete(ctx, id, orgID); err != nil {
		return err
	}

	r.invalidateClientCache(ctx, existing)
	return nil
}

// SaveConsent persists a consent decision and invalidates the cached entry.
func (r *CachedClientRepository) SaveConsent(ctx context.Context, consent *domain.Consent) error {
	if err := r.delegate.SaveConsent(ctx, consent); err != nil {
		return err
	}

	// Invalidate so the next GetConsent reflects the fresh decision
	if err := r.redisClient.Del(ctx, r.consentKey(consent.UserID, consent.ClientID, consent.APIResourceID)); err != nil {
		logger.Error.Printf("Failed to invalidate consent cache: %v", err)
	}

	return nil
}

// === Pass-through Methods (no caching) ===

func (r *CachedClientRepository) List(ctx context.Context, pagination Pagination, orgID *uuid.UUID) ([]*domain.Client, int, error) {
	return r.delegate.List(ctx, pagination, orgID)
}

func (r *CachedClientRepository) ListByServiceAccountID(ctx context.Context, orgID uuid.UUID, saID uuid.UUID) ([]*domain.Client, error) {
	return r.delegate.ListByServiceAccountID(ctx, orgID, saID)
}
