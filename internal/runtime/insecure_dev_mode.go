package runtime

// insecure_dev_mode.go — the TEST-ONLY escape hatch for server-side rate
// limiting (THE-UI-PROVISIONER, 2026-08-29).
//
// WHY THIS EXISTS
// ---------------
// The OSS appliance ships two brute-force controls with NO off-switch:
//
//   - the six HTTP rate-limit classes (resolveRateLimitConfig): env overrides
//     can only RAISE a limit — a blank/invalid/non-positive override keeps the
//     safe default, so a misconfigured deployment can never silently disable
//     rate limiting;
//   - the LoginRiskService lockout on password login (5 failures per
//     (email, ip) in 15m), whose refusal is deliberately indistinguishable
//     from a wrong password (LOCKOUT-1, anti-enumeration).
//
// Correct in production, hostile to a test harness: the e2e suites drive
// hundreds of logins from ONE address, and a handful of TOTP-window replays or
// stale-credential attempts locks the account for 15 minutes — measured
// 2026-08-29 as a full-suite login stall (the login form never advances past
// the password step, because lockout answers invalid_credentials by design).
//
// THE BOUNDARY (do not widen)
// ---------------------------
// IDENTUUM_IDP_INSECURE_DEV_MODE=true disables SERVER-SIDE RATE LIMITING ONLY:
// the six HTTP limiter classes become no-ops and the login-risk lockout gate is
// left unwired. It MUST NOT disable authentication, authorization, MFA,
// WebAuthn validation, CORS, CSRF, audit logging, org scoping, or session
// validation — none of those read this flag, and additions here must keep it
// that way. The literal value "true" is required; anything else (including
// "1", "TRUE", "yes") leaves every control ON — fail-safe.
//
// It is NEVER default-on: the flag must be set explicitly in the environment
// (the e2e-full harness does; no shipped compose/config sets it), and an
// ACTIVE flag logs a loud ERROR banner at startup so it can never ride along
// silently into a production deployment.

import (
	"os"
	"strings"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// insecureDevModeActive reports whether the test-only rate-limit escape hatch
// is explicitly enabled. Exactly the literal "true" (after trimming) enables
// it; every other value — unset, empty, "1", "TRUE", "yes" — is OFF.
func insecureDevModeActive(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	return strings.TrimSpace(getenv("IDENTUUM_IDP_INSECURE_DEV_MODE")) == "true"
}

// loginRiskForMode resolves which LoginRiskService the local-login pipeline is
// wired with: the real one normally, nil under insecure dev mode.
// LocalLoginService is nil-risk-safe by design (its Login gate is
// `if s.risk != nil`), so a nil here cleanly disables ONLY the lockout gate —
// password verification, MFA, and session issuance are untouched. The service
// itself is still constructed and returned to the retention sweepers either
// way; only the login-gate wiring is dropped.
func loginRiskForMode(risk *service.LoginRiskService, insecure bool) *service.LoginRiskService {
	if insecure {
		return nil
	}
	return risk
}
