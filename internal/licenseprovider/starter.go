// Package licenseprovider hosts the OSS-safe license-provider
// implementation consumed by the IDP runtime through the three
// Phase 1 seam interfaces (features.FeatureGate,
// features.FeatureLimits, features.LicenseInfoProvider).
//
// This package depends only on internal/features (and standard
// library) — it has no internal/license import. It is the
// OSS-side companion to the commercial *internal/license.Service
// that will live in the future identuum-idp-ce module.
//
// Relocated into identuum-idp-oss in Phase 2 by slice
// identuum-idp-open-core-phase2-starter-provider-into-oss (copy
// from monolith; the monolith retains its own copy as the current
// source of truth until Phase 2 completes).
//
// SECURITY contract:
//
//   - StarterProvider has no secret material, no signing key, no
//     license envelope, no revocation bundle, no entitlement claim
//     parser. It is safe to embed in any artefact at any tier.
//   - GetLicenseInfo returns only runtime-safe scalar keys already
//     consumed by handler_component.go (status, tier, license_type,
//     deployment_mode). Customer-bearing fields (licensee, issued_at,
//     features list, expires) are returned as zero/nil values so the
//     existing projection logic in handler_component.go renders
//     them safely (expires_at = null, days_remaining = null) without
//     leaking anything that could only exist in a commercial license.
package licenseprovider

import (
	"github.com/identuum/identuum-idp-oss/internal/features"
)

// StarterProvider is the Starter-tier implementation of the Phase 1
// seam interfaces. It is stateless and safe to embed in any
// goroutine concurrently.
//
// Behaviour summary:
//   - IsFeatureEnabled delegates to features.StarterFeatureGate, so
//     it returns true for the documented Starter feature set
//     (Core, PublicRegistration, MFA, SSO, StaticVault, WebAuthn)
//     and false for every commercial feature. The site_admin MFA
//     invariant is honoured.
//   - GetLimit delegates to features.StarterFeatureLimits, so it
//     returns the documented Starter values (LimitTenants=1,
//     LimitM2MSessions=50, LimitUsers=-1 / unlimited) and 0 for
//     every other metric (matching the
//     `(*license.Service).GetLimit` "metric not in tier" fallback).
//   - GetLicenseInfo returns a stable map suitable for the existing
//     handler_component.go + handler_health.go projections. See the
//     starterLicenseInfo() helper for the exact key/value contract.
//
// Composition note: StarterProvider EMBEDS the two pure
// features.* primitives rather than reimplementing them so any
// future drift-mirror tests for StarterFeatureGate and
// StarterFeatureLimits transitively guard StarterProvider's
// behaviour against changes to the Starter tier definitions.
type StarterProvider struct {
	features.StarterFeatureGate
	features.StarterFeatureLimits
}

// New returns a ready-to-use Starter provider. Callers may also
// construct StarterProvider{} directly since it has no state; the
// constructor exists for symmetry with future commercial-provider
// factories.
//
// Phase 2 alias: NewStarterProvider returns the same value through
// the core-owned Provider interface so bootstrap can write a
// shape-symmetric pair `NewStarterProvider()` / `NewCommercialProvider(...)`
// without naming the concrete *StarterProvider type. Prefer
// NewStarterProvider in new code; New is retained for source
// compatibility with the prior Phase 2 boundary slice's tests and
// has identical behaviour.
func New() *StarterProvider {
	return &StarterProvider{}
}

// NewStarterProvider is the Phase 2 factory alias for New. It
// returns the Starter provider through the Provider interface so
// bootstrap can swap between NewStarterProvider and the
// CE-side commercial factory transparently when the OSS-vs-CE
// split lands.
func NewStarterProvider() Provider {
	return &StarterProvider{}
}

// GetLicenseInfo returns the runtime-safe license-info map
// consumed by handler_component.go::buildIDPComponentLicenseInfo
// and handler_health.go::HandleHealth.
//
// Returned keys + types:
//   - "status" (string)         — always "VALID" so the
//     component-discovery projection
//     reports license.status = "valid"
//     and the health-tier branch is
//     evaluated.
//   - "tier" (string)           — always "starter". The health
//     handler's tier-projection switch
//     falls through to the default
//     product string "identuum-idp".
//   - "license_type" (string)   — "starter". Renders verbatim in
//     the component-discovery DTO.
//   - "deployment_mode" (string)— "self-hosted". Renders verbatim
//     in the component-discovery DTO.
//   - "expires" (nil)           — perpetual Starter; the component
//     projection emits expires_at = null
//     and days_remaining = null when this
//     key is missing or nil.
//
// Customer-bearing keys (licensee, issued_at, features list) are
// intentionally NOT returned — they would either be empty
// placeholders that leak through to the wire or invent commercial-
// only data that does not apply to a Starter deployment. The
// component-discovery projection drops them anyway.
func (StarterProvider) GetLicenseInfo() map[string]any {
	return starterLicenseInfo()
}

// starterLicenseInfo is the canonical Starter license-info map.
// Extracted to a helper so tests can pin the exact contract
// without instantiating the provider.
func starterLicenseInfo() map[string]any {
	return map[string]any{
		"status":          "VALID",
		"tier":            "starter",
		"license_type":    "starter",
		"deployment_mode": "self-hosted",
	}
}

// Compile-time assertions that StarterProvider satisfies all three
// Phase 1 seam interfaces AND the Phase 2 Provider union.
// If any interface signature drifts, the build fails here at the
// authoritative location.
var (
	_ features.FeatureGate         = StarterProvider{}
	_ features.FeatureLimits       = StarterProvider{}
	_ features.LicenseInfoProvider = StarterProvider{}
	_ Provider                     = StarterProvider{}
	_ Provider                     = (*StarterProvider)(nil)
)
