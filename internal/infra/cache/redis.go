package cache

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// ErrCacheMiss is returned by Get when the key does not exist in Redis.
var ErrCacheMiss = errors.New("cache miss")

// ErrCacheDecode is returned by Get when the bytes were retrieved successfully
// but could not be decoded into dest. Wrapped over the underlying gob error so
// callers can distinguish "Redis was reachable but the payload was malformed"
// from "Redis was unreachable".
var ErrCacheDecode = errors.New("cache decode failed")

// RedisClient wraps the go-redis client
type RedisClient struct {
	client *redis.Client
}

// NewRedisClient creates a new Redis client
func NewRedisClient(addr, password string) (*RedisClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       0, // Use default DB
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return &RedisClient{client: client}, nil
}

// Set stores a value in Redis with TTL
func (r *RedisClient) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	start := time.Now()
	var err error
	defer func() {
		duration := time.Since(start).Seconds()
		status := "success"
		if err != nil {
			status = "error"
		}
		metrics.CacheRequestDuration.WithLabelValues("set", status).Observe(duration)
	}()

	data, err := encode(value)
	if err != nil {
		return err
	}

	if err = r.client.Set(ctx, key, data, ttl).Err(); err != nil {
		logger.ErrorContext(ctx, "Redis Set error", zap.String("key", key), zap.Error(err))
		return err
	}
	return nil
}

// Get retrieves a value from Redis and decodes it into dest
func (r *RedisClient) Get(ctx context.Context, key string, dest any) error {
	start := time.Now()
	var err error
	defer func() {
		duration := time.Since(start).Seconds()
		status := "success"
		if err != nil {
			if errors.Is(err, ErrCacheMiss) {
				status = "miss"
			} else {
				status = "error"
			}
		}
		metrics.CacheRequestDuration.WithLabelValues("get", status).Observe(duration)
	}()

	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			err = ErrCacheMiss
			return err
		}
		logger.ErrorContext(ctx, "Redis Get error", zap.String("key", key), zap.Error(err))
		return err
	}

	if err = decode([]byte(val), dest); err != nil {
		return err
	}
	return nil
}

// encode serializes a value using Gob
func encode(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(value); err != nil {
		return nil, fmt.Errorf("failed to gob encode cache value: %w", err)
	}
	return buf.Bytes(), nil
}

// decode deserializes a value using Gob. Decode failures are wrapped with
// ErrCacheDecode so callers can distinguish them from connectivity failures
// via errors.Is.
func decode(data []byte, dest any) error {
	buf := bytes.NewReader(data)
	if err := gob.NewDecoder(buf).Decode(dest); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheDecode, err)
	}
	return nil
}

// Del removes a key from Redis
func (r *RedisClient) Del(ctx context.Context, key string) error {
	start := time.Now()
	var err error
	defer func() {
		duration := time.Since(start).Seconds()
		status := "success"
		if err != nil {
			status = "error"
		}
		metrics.CacheRequestDuration.WithLabelValues("del", status).Observe(duration)
	}()

	if err = r.client.Del(ctx, key).Err(); err != nil {
		logger.ErrorContext(ctx, "Redis Del error", zap.String("key", key), zap.Error(err))
		return err
	}
	return nil
}

// Close closes the connection to Redis
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// Client returns the underlying redis client
func (r *RedisClient) Client() *redis.Client {
	return r.client
}
