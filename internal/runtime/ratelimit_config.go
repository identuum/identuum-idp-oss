package runtime

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/ratelimit"
)

// resolveRateLimitConfig builds the per-class request-rate limits the OSS
// router applies (login / register / token / introspection / password-reset).
//
// It reads from the SAME env path the serving binary actually consumes — the
// runtime.Config.Getenv hook (os.Getenv in production). Each
// class is overridable via IDENTUUM_IDP_RATE_LIMIT_<CLASS>_REQUESTS and
// _WINDOW; unset/invalid values fall back to the safe defaults below, so the
// shipped runtime always rate-limits (never a zero-value no-op).
//
// Defaults (match the per-class middleware values chosen in the P1b slice):
//
//	login          5 / 1m    (brute-force)
//	register       10 / 1h
//	token          120 / 1m  (generous; per authenticated client)
//	introspection  600 / 1m  (very generous; per authenticated client)
//	revocation     120 / 1m  (per IP, NEVER per client — the limiter mounts
//	                          BEFORE the auth guard, so no client is
//	                          authenticated yet when the key is computed)
//	password-reset 10 / 15m  (tight; per IP — flooding / enumeration)
//
// Only the six classes the router mounts are populated; the remaining
// ratelimit.RateLimitConfig fields are intentionally left zero (no route
// reads them).
func resolveRateLimitConfig(getenv func(string) string) ratelimit.RateLimitConfig {
	if getenv == nil {
		getenv = os.Getenv
	}
	return ratelimit.RateLimitConfig{
		LoginLimit:         resolveRateLimit(getenv, "LOGIN", 5, time.Minute),
		RegisterLimit:      resolveRateLimit(getenv, "REGISTER", 10, time.Hour),
		TokenLimit:         resolveRateLimit(getenv, "TOKEN", 120, time.Minute),
		IntrospectionLimit: resolveRateLimit(getenv, "INTROSPECTION", 600, time.Minute),
		RevocationLimit:    resolveRateLimit(getenv, "REVOCATION", 120, time.Minute),
		PasswordResetLimit: resolveRateLimit(getenv, "PASSWORD_RESET", 10, 15*time.Minute),
	}
}

// resolveRateLimit resolves one class. An env override is honoured only when
// it parses to a positive value; a blank, malformed, or non-positive override
// keeps the safe default so misconfiguration can never silently disable a
// limit.
func resolveRateLimit(getenv func(string) string, class string, defRequests int, defWindow time.Duration) ratelimit.RateLimit {
	requests := defRequests
	if raw := strings.TrimSpace(getenv("IDENTUUM_IDP_RATE_LIMIT_" + class + "_REQUESTS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			requests = n
		}
	}
	window := defWindow
	if raw := strings.TrimSpace(getenv("IDENTUUM_IDP_RATE_LIMIT_" + class + "_WINDOW")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			window = d
		}
	}
	return ratelimit.RateLimit{RequestsPerWindow: requests, WindowDuration: window}
}
