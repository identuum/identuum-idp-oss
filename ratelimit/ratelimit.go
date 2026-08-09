package ratelimit

import (
	"time"
)

// RateLimit defines the parameters for a token-bucket limiter.
// NOTE: ulule/limiter (the backing library) uses fixed period descriptors (S/M/H/D)
// and does not expose a burst configuration through its Gin middleware adapter.
// WindowDuration is mapped to the nearest supported descriptor in NewRateLimitMiddlewareWithKeyFn.
type RateLimit struct {
	RequestsPerWindow int
	WindowDuration    time.Duration
}

// RateLimitConfig holds the configuration for various rate limits
type RateLimitConfig struct {
	LoginLimit    RateLimit
	RegisterLimit RateLimit
	RefreshLimit  RateLimit
	ReadLimit     RateLimit
	WriteLimit    RateLimit
	GlobalLimit   RateLimit
	// DynamicRegistrationLimit governs POST /api/v1/auth/dcr.
	// Default: 5 registrations per hour per IP.
	DynamicRegistrationLimit RateLimit

	// TokenLimit governs POST /api/v1/oauth/token, keyed per
	// authenticated OAuth client (IP fallback). Generous by default —
	// every client access-token refresh hits this endpoint, so a normal
	// client is never throttled while a runaway/compromised client cannot
	// starve others. Default: 120 requests per minute per client.
	TokenLimit RateLimit

	// IntrospectionLimit governs POST /api/v1/oauth/introspection, keyed
	// per authenticated OAuth client (IP fallback). Very generous —
	// introspection is a high-volume server-to-server read path and a
	// legitimate resource server must not be throttled. Default: 600
	// requests per minute per client.
	IntrospectionLimit RateLimit

	// RevocationLimit governs POST /api/v1/oauth/revoke. UNLIKE every other
	// OAuth class here, this limiter is mounted BEFORE the client-auth guard
	// (see internal/handlers/revocation.go), so it also bounds requests whose
	// credentials FAIL — mw.RequireOAuthClient aborts on an auth failure, and
	// a limiter behind it never runs for the attacker it most needs to bound.
	// Keyed PER IP, always — not per client. Because the limiter runs before
	// the guard, no client is authenticated yet when the key is computed, so
	// oauthClientRateLimitKey returns "" on every request here and the
	// middleware falls back to c.ClientIP(). Passing that key function is
	// forward-compatible, not per-client behaviour: on this route it is
	// effectively a constant "".
	//
	// The tradeoff, stated rather than glossed: a legitimate resource server
	// doing >120 revokes/min from ONE egress IP is now throttled where it
	// never was before, and it cannot be exempted per-client the way /token
	// can. Behind shared NAT, a caller on the same egress IP can burn the
	// bucket and delay revocation for its neighbours — bounded to that IP
	// (verified: internal/mw/rate_limit.go falls back to c.ClientIP(), NOT a
	// single shared empty-key bucket, so one attacker cannot starve everyone).
	// Accepted because an unbounded client_secret oracle is the worse risk,
	// and because pre-auth there is nothing else to key on.
	// Default: 120 requests per minute per IP.
	RevocationLimit RateLimit

	// PasswordResetLimit governs POST /api/v1/auth/password/reset-request
	// and POST /api/v1/auth/password/reset, keyed per IP. Tight — these
	// endpoints are abuse-prone (reset-email flooding + account
	// enumeration). Default: 10 requests per 15 minutes per IP.
	PasswordResetLimit RateLimit

	RedisAddr     string
	RedisPassword string
}
