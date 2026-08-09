package features

// FeatureLimits is the core-owned interface for runtime per-metric
// limit reads. Both the identuum-idp-oss Starter implementation
// (StarterFeatureLimits, below) and the identuum-idp-ce
// license-backed implementation (*internal/license.Service in the
// commercial module) satisfy this interface.
//
// Introduced in Phase 1 of the open-core split
// (identuum-idp-open-core-phase1-feature-limits-interface) as the
// counterpart to features.FeatureGate. Relocated into
// identuum-idp-oss in Phase 2 by slice
// identuum-idp-open-core-phase2-starter-provider-into-oss (copy;
// the monolith retains its own copy as the current source of truth
// until Phase 2 completes).
//
// The signature matches (*internal/license.Service).GetLimit
// exactly: `GetLimit(metric string) int64`. Returns -1 for
// "unlimited" (annual license model) and 0 for "metric not enabled
// at the current tier" — same convention as the license-backed
// implementation, so swapping a Starter limits provider in place of
// a license service is a fail-closed (and never-fail-open) change.
type FeatureLimits interface {
	GetLimit(metric string) int64
}

// StarterLimits is the canonical map of per-metric limit values
// enabled at the Starter tier per the current product definition.
// It mirrors internal/license.TierLimits[license.TierStarter] in
// the commercial module verbatim.
//
// StarterLimits intentionally lives in OSS (internal/features)
// because the StarterFeatureLimits implementation must not import
// internal/license.
var StarterLimits = map[string]int64{
	LimitTenants:     1,
	LimitM2MSessions: 50,
	LimitUsers:       -1, // Unlimited: annual license model.
}

// StarterFeatureLimits is the Starter-tier FeatureLimits
// implementation. It returns the Starter-tier limit for known
// metrics and 0 for everything else (matching
// (*license.Service).GetLimit's "metric not in tier" fallback).
//
// Behaviour (kept aligned with (*license.Service).GetLimit so a
// swap is risk-free):
//   - Known metrics return their Starter-tier value (see
//     StarterLimits).
//   - Unknown metrics return 0. This mirrors the license-backed
//     behaviour for a metric that is not in TierLimits[TierStarter]
//     (e.g. LimitSPIFFEPeers, which is Enterprise-only — Starter
//     gets 0, which fail-closes peer creation).
//
// StarterFeatureLimits has no state, no license parsing, no
// crypto, and no import of internal/license. It is safe to use in
// any code path that can reference internal/features.
type StarterFeatureLimits struct{}

// GetLimit answers Starter-tier per-metric limit reads. See
// StarterFeatureLimits for the contract.
func (StarterFeatureLimits) GetLimit(metric string) int64 {
	if val, ok := StarterLimits[metric]; ok {
		return val
	}
	return 0
}

// Compile-time assertion that StarterFeatureLimits satisfies the
// FeatureLimits interface. If the interface shape changes and the
// Starter implementation no longer conforms, the build fails
// here.
var _ FeatureLimits = StarterFeatureLimits{}
