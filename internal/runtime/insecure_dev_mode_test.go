package runtime

import (
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// IDENTUUM_IDP_INSECURE_DEV_MODE disables SERVER-SIDE RATE LIMITING ONLY, and
// is never default-on:
//
//   - flag unset (or any value but the literal "true") → every HTTP limiter
//     class keeps its safe non-zero default AND the login-risk lockout stays
//     wired — the fail-safe posture a production deployment gets by default;
//   - flag exactly "true" → every limiter class is zero-value (the documented
//     NewRateLimitMiddleware no-op) and the lockout gate is unwired (nil risk;
//     LocalLoginService is nil-risk-safe by design).
//
// Reverting either half — the resolveRateLimitConfig zero-value branch or the
// loginRiskForMode nil branch — fails this test; so does widening the accepted
// values (e.g. "1"), which would make the escape hatch easier to trip by
// accident.
// RULE: INSECURE-DEV-MODE-1
func TestInsecureDevMode_DisablesOnlyRateLimiting_NeverDefaultOn(t *testing.T) {
	envWith := func(v string) func(string) string {
		return func(key string) string {
			if key == "IDENTUUM_IDP_INSECURE_DEV_MODE" {
				return v
			}
			return ""
		}
	}

	// Never default-on: unset and every non-literal value leave the flag OFF.
	for _, v := range []string{"", "1", "TRUE", "yes", "on", "false"} {
		if insecureDevModeActive(envWith(v)) {
			t.Fatalf("flag value %q must NOT activate insecure dev mode (only the literal \"true\" may)", v)
		}
	}
	if !insecureDevModeActive(envWith("true")) {
		t.Fatal(`the literal "true" must activate insecure dev mode`)
	}
	if !insecureDevModeActive(envWith("  true  ")) {
		t.Fatal("surrounding whitespace must not defeat the documented literal")
	}

	// Fail-safe default: with the flag off, every mounted limiter class keeps a
	// positive request budget (the safe defaults resolveRateLimitConfig owns).
	def := resolveRateLimitConfig(envWith(""))
	for name, rl := range map[string]int{
		"login":          def.LoginLimit.RequestsPerWindow,
		"register":       def.RegisterLimit.RequestsPerWindow,
		"token":          def.TokenLimit.RequestsPerWindow,
		"introspection":  def.IntrospectionLimit.RequestsPerWindow,
		"revocation":     def.RevocationLimit.RequestsPerWindow,
		"password-reset": def.PasswordResetLimit.RequestsPerWindow,
	} {
		if rl < 1 {
			t.Fatalf("flag OFF: limiter class %q must keep a positive default, got %d", name, rl)
		}
	}

	// Escape hatch: with the flag on, every class is zero-value → the documented
	// NewRateLimitMiddleware no-op. This is the ONLY way to disable the
	// limiters; the per-class env overrides can only raise them.
	insecure := resolveRateLimitConfig(envWith("true"))
	for name, rl := range map[string]int{
		"login":          insecure.LoginLimit.RequestsPerWindow,
		"register":       insecure.RegisterLimit.RequestsPerWindow,
		"token":          insecure.TokenLimit.RequestsPerWindow,
		"introspection":  insecure.IntrospectionLimit.RequestsPerWindow,
		"revocation":     insecure.RevocationLimit.RequestsPerWindow,
		"password-reset": insecure.PasswordResetLimit.RequestsPerWindow,
	} {
		if rl != 0 {
			t.Fatalf("flag ON: limiter class %q must be zero-value (no-op middleware), got %d", name, rl)
		}
	}

	// The lockout half: loginRiskForMode passes the real service through
	// normally and returns nil under insecure dev mode — nil is exactly the
	// "no lockout gate" wiring LocalLoginService treats as absent by design.
	risk := &service.LoginRiskService{}
	if got := loginRiskForMode(risk, false); got != risk {
		t.Fatal("flag OFF: the real LoginRiskService must be wired (lockout stays on)")
	}
	if got := loginRiskForMode(risk, true); got != nil {
		t.Fatal("flag ON: the lockout gate must be unwired (nil risk service)")
	}
}
