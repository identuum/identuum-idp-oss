package licenseprovider

import (
	"github.com/identuum/identuum-idp-oss/internal/features"
)

// Provider is the core-owned union of the three Phase 1 runtime-
// decision seam interfaces (features.FeatureGate +
// features.FeatureLimits + features.LicenseInfoProvider). It is
// the single dependency type bootstrap / Application can store to
// represent "the license-driven runtime decisions" without naming
// the concrete commercial or starter implementation.
//
// Introduced in Phase 2 of the open-core split (slice
// identuum-idp-open-core-phase2-license-provider-factory). Relocated
// into identuum-idp-oss in Phase 2 by slice
// identuum-idp-open-core-phase2-starter-provider-into-oss (copy;
// the monolith retains its own copy as the current source of truth
// until Phase 2 completes).
//
// In OSS, the StarterProvider in this package satisfies Provider.
// In the future identuum-idp-ce commercial module, *license.Service
// will satisfy Provider (the compile-time pin lives in CE-side
// tests once that move happens).
//
// The interface deliberately exposes ONLY the three Phase 1
// seams. It MUST NOT grow to expose envelope verification,
// signing keys, revocation bundle parsing, machine-id binding,
// raw entitlement claims, or any other commercial-only internal.
// New commercial-only methods belong on the concrete commercial
// type, not on this interface.
type Provider interface {
	features.FeatureGate
	features.FeatureLimits
	features.LicenseInfoProvider
}
