// Package licenseprovider is the public OSS seam for the canonical
// license-provider model. It exposes the Provider interface (the
// runtime union of FeatureGate + FeatureLimits + LicenseInfoProvider)
// and the StarterProvider implementation that ships in OSS.
//
// This is the canonical import path for the identuum-idp-ce overlay:
// the CE-side CommercialProvider will satisfy the Provider interface
// declared here.
//
// Implementation note: this file is a thin shim over the existing
// internal/licenseprovider package using Go type aliases. The
// internal package remains the single source of truth for behavior;
// this public package is the stable import surface CE will pin
// against.
//
// SECURITY contract:
//   - This package depends only on the OSS internal/licenseprovider
//     package (which itself depends only on internal/features and
//     the standard library). It carries no license envelope, no
//     signing key, no revocation bundle, and no machine-id binding.
//   - The Provider interface exposes ONLY the three Phase 1 seams
//     (IsFeatureEnabled / GetLimit / GetLicenseInfo). It must not
//     grow to expose envelope verification, signing keys, or raw
//     entitlement claims; commercial-only methods belong on the
//     concrete commercial type in identuum-idp-ce.
//   - The OSS module must never import identuum-idp-ce.
package licenseprovider

import (
	internallp "github.com/identuum/identuum-idp-oss/internal/licenseprovider"
)

// Provider is the union of the three Phase 1 runtime-decision seam
// interfaces. The OSS StarterProvider in this package satisfies
// Provider; the CE-side CommercialProvider will also satisfy it.
type Provider = internallp.Provider

// StarterProvider is the OSS implementation of Provider. It
// is stateless and safe to embed in any goroutine concurrently.
type StarterProvider = internallp.StarterProvider

// New returns a ready-to-use Starter provider as a concrete
// *StarterProvider. Prefer NewStarterProvider when the call site
// only needs the Provider interface.
func New() *StarterProvider {
	return internallp.New()
}

// NewStarterProvider returns a ready-to-use Starter provider
// through the Provider interface. CE bootstrap may write a
// shape-symmetric pair `NewStarterProvider()` /
// `NewCommercialProvider(...)` without naming the concrete
// *StarterProvider type.
func NewStarterProvider() Provider {
	return internallp.NewStarterProvider()
}
