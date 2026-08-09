package mw

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/identuum/identuum-idp-oss/ratelimit"
	"github.com/identuum/identuum-idp-oss/types"
)

// NewRateLimitMiddleware creates a rate-limit middleware keyed on the
// client's resolved IP address. It uses Gin's c.ClientIP(), which
// honours SetTrustedProxies — so X-Forwarded-For is only trusted when
// the request arrives from a configured trusted proxy. Direct
// connections or forged X-Forwarded-For from untrusted sources use
// the raw RemoteAddr instead.
//
// When limit.RequestsPerWindow < 1 the middleware is a noop (c.Next()
// only), matching the behaviour of disabled/unconfigured limiters in
// test environments where OSSRouterDeps.RateLimitConfig is zero-value.
//
// The limiter is an in-process token bucket (see ipRateLimiter) built
// purely on the Go standard library — no third-party dependency. It is
// suitable for OSS single-replica deployments; a distributed
// (e.g. Redis-backed) cross-replica limiter is a CE concern and is not
// wired here.
func NewRateLimitMiddleware(limit ratelimit.RateLimit, limitType string) gin.HandlerFunc {
	return NewRateLimitMiddlewareWithKeyFn(limit, limitType, func(c *gin.Context) string {
		return c.ClientIP()
	})
}

// NewRateLimitMiddlewareWithKeyFn is like NewRateLimitMiddleware but
// accepts a custom key function enabling non-IP-based bucketing (e.g.
// email-keyed limits). keyFn must return a non-empty string; an empty
// result falls back to c.ClientIP() so a request is never un-bucketed.
func NewRateLimitMiddlewareWithKeyFn(limit ratelimit.RateLimit, limitType string, keyFn func(*gin.Context) string) gin.HandlerFunc {
	if limit.RequestsPerWindow < 1 {
		return func(c *gin.Context) { c.Next() }
	}

	rl := newIPRateLimiter(limit)

	return func(c *gin.Context) {
		key := keyFn(c)
		if key == "" {
			key = c.ClientIP()
		}
		if rl.allow(key, time.Now()) {
			c.Next()
			return
		}
		route := c.FullPath()
		if route == "" {
			route = "unknown"
		}
		metrics.RateLimitHits.WithLabelValues(route).Inc()
		logger.Security.WarnContext(c.Request.Context(), "rate limit exceeded",
			zap.String("event_type", "rate_limit_exceeded"),
			zap.String("limit_type", limitType),
			zap.String("ip_address", c.ClientIP()),
			zap.String("path", c.Request.URL.Path),
		)
		c.Header("Retry-After", "60")
		c.AbortWithStatusJSON(http.StatusTooManyRequests, types.ErrorResponse{
			Success: false,
			Message: "Rate limit exceeded. Try again later.",
		})
	}
}

// ipRateLimiter is a minimal in-memory, per-key token-bucket limiter built on
// the Go standard library — no third-party dependency. Each key (the resolved
// client IP, or a custom key) owns a bucket of `capacity` tokens that refills
// at `capacity / window` tokens per second; a request consumes one token and
// is rejected when the bucket is empty. The first `capacity` requests in a
// cold window pass; the next is limited until the bucket refills.
type ipRateLimiter struct {
	mu           sync.Mutex
	buckets      map[string]*tokenBucket
	capacity     float64
	refillPerSec float64
	ttl          time.Duration
	lastSweep    time.Time
}

type tokenBucket struct {
	tokens   float64
	lastSeen time.Time
}

func newIPRateLimiter(limit ratelimit.RateLimit) *ipRateLimiter {
	window := limit.WindowDuration
	if window <= 0 {
		window = time.Minute
	}
	capacity := float64(limit.RequestsPerWindow)
	return &ipRateLimiter{
		buckets:      make(map[string]*tokenBucket),
		capacity:     capacity,
		refillPerSec: capacity / window.Seconds(),
		ttl:          2 * window,
	}
}

// allow reports whether a request for key is permitted at time now, consuming
// one token when it is. Safe for concurrent use.
func (l *ipRateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)

	b := l.buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: l.capacity, lastSeen: now}
		l.buckets[key] = b
	} else {
		if elapsed := now.Sub(b.lastSeen).Seconds(); elapsed > 0 {
			b.tokens += elapsed * l.refillPerSec
			if b.tokens > l.capacity {
				b.tokens = l.capacity
			}
		}
		b.lastSeen = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// sweepLocked evicts idle, fully-refilled buckets to bound memory under
// adversarial source-IP churn. It runs at most once per ttl. Caller holds mu.
func (l *ipRateLimiter) sweepLocked(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < l.ttl {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) >= l.ttl {
			delete(l.buckets, k)
		}
	}
}
